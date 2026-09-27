// Online self-upgrade API (admin): console endpoints over the
// internal/upgrade pipeline service. Four endpoints, all requireRole(Admin):
//
//	GET  /api/upgrade/status  - version + latest (60s TTL cache) + running
//	                            task + history (settings-page auto check;
//	                            ?refresh=1 bypasses the cache)
//	POST /api/upgrade/check   - forced version check (cache bypass, refreshes it)
//	POST /api/upgrade/start   - start an upgrade task ({"target_version": ""}
//	                            = latest); 409 + running task while one runs
//	GET  /api/upgrade/task?id=  - poll one task (404 when unknown)
//
// Degradation follows the console-port convention: when no upgrade service
// is wired (static mode, or a deployment built without the module) every
// endpoint answers 501 with a reason instead of a confusing 404/500.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/store"
	"github.com/kingmoat/kingmoat/internal/upgrade"
)

// upgradeCheckTTL bounds the cached version-check result served by the
// status endpoint. Opening the settings page must not hit the Gitee
// releases feed on every render (T-02 leftover: the cache is an API-layer
// concern; internal/upgrade.Check stays uncached), while the forced check
// endpoint and ?refresh=1 bypass it. One minute keeps the badge fresh
// enough for manual use without a request per poll.
const upgradeCheckTTL = 60 * time.Second

// upgradeCheckCache memoizes the last SUCCESSFUL version check. Failures
// are never cached: a transient Gitee outage must not blank the card for a
// full TTL - the next status call simply retries.
type upgradeCheckCache struct {
	mu      sync.Mutex
	latest  upgrade.CheckResult
	fetched time.Time
	valid   bool
}

func (c *upgradeCheckCache) get(now time.Time) (upgrade.CheckResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid || now.Sub(c.fetched) >= upgradeCheckTTL {
		return upgrade.CheckResult{}, false
	}
	return c.latest, true
}

func (c *upgradeCheckCache) put(res upgrade.CheckResult, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latest, c.fetched, c.valid = res, now, true
}

// upgradeLatestView is the version part of the status/check responses
// (contract: {version, update_available, notes[, assets_url]}). AssetsURL
// is the manual-download fallback surfaced by the pipeline service.
type upgradeLatestView struct {
	Version         string `json:"version"`
	UpdateAvailable bool   `json:"update_available"`
	Notes           string `json:"notes,omitempty"`
	AssetsURL       string `json:"assets_url,omitempty"`
}

func upgradeLatestOf(res upgrade.CheckResult) upgradeLatestView {
	return upgradeLatestView{
		Version:         res.LatestVersion,
		UpdateAvailable: res.UpdateAvailable,
		Notes:           res.Notes,
		AssetsURL:       res.AssetsURL,
	}
}

// upgradeUnavailable answers 501 when no upgrade service is wired. Returns
// true when the response was written (callers must stop).
func (s *Server) upgradeUnavailable(w http.ResponseWriter) bool {
	if s.opts.Upgrade != nil {
		return false
	}
	writeErr(w, http.StatusNotImplemented, simpleError("在线升级模块未启用（当前部署形态不支持）"))
	return true
}

// upgradeLatest serves the cached check result when fresh; refresh (or a
// cold cache) performs a live check and repopulates the cache. A failed
// live check answers nil (latest unknown) and leaves the cache untouched.
func (s *Server) upgradeLatest(ctx context.Context, svc *upgrade.Service, refresh bool) *upgradeLatestView {
	if !refresh {
		if res, ok := s.upgCache.get(time.Now()); ok {
			v := upgradeLatestOf(res)
			return &v
		}
	}
	res, err := svc.Check(ctx)
	if err != nil {
		return nil
	}
	s.upgCache.put(res, time.Now())
	v := upgradeLatestOf(res)
	return &v
}

// upgradeRunningTask snapshots the in-flight task (nil when idle).
func upgradeRunningTask(svc *upgrade.Service) *upgrade.Task {
	if t, ok := svc.Running(); ok {
		return &t
	}
	return nil
}

// handleUpgradeStatus composes the settings-page snapshot. version is the
// running build (Options.Version, always available even when the feed is
// unreachable); latest is null until a check succeeds; running_task and
// history mirror the pipeline service.
func (s *Server) handleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.upgradeUnavailable(w) {
		return
	}
	svc := s.opts.Upgrade
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      s.opts.Version,
		"latest":       s.upgradeLatest(r.Context(), svc, r.URL.Query().Get("refresh") == "1"),
		"running_task": upgradeRunningTask(svc),
		"history":      svc.History(),
	})
}

// handleUpgradeCheck performs a forced version check (cache bypass) and
// repopulates the cache with the fresh result.
func (s *Server) handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.upgradeUnavailable(w) {
		return
	}
	res, err := s.opts.Upgrade.Check(r.Context())
	if err != nil {
		s.writeUpgradeCheckErr(w, err)
		return
	}
	s.upgCache.put(res, time.Now())
	writeJSON(w, http.StatusOK, upgradeLatestOf(res))
}

// writeUpgradeCheckErr maps check failures: an unusable current version is
// the caller's deployment problem (400), anything else is an upstream feed
// failure (502).
func (s *Server) writeUpgradeCheckErr(w http.ResponseWriter, err error) {
	if errors.Is(err, upgrade.ErrInvalidCurrent) {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeErr(w, http.StatusBadGateway, fmt.Errorf("版本检测失败: %w", err))
}

// handleUpgradeStart launches an upgrade task ({"target_version": ""} =
// latest release). While a task runs the endpoint answers 409 with that
// running task so the UI can attach to it. The Running() probe is a fast
// path: if a concurrent start slips past it, the service's single-flight
// returns the SAME task with a nil error and this handler answers 200 with
// its id - the client still ends up polling the one real task, which is the
// guarantee that matters.
func (s *Server) handleUpgradeStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.upgradeUnavailable(w) {
		return
	}
	var req struct {
		TargetVersion string `json:"target_version"`
	}
	// An empty body is the common "upgrade to latest" call, so an absent
	// JSON document must not fail the decode.
	if err := decodeBody(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	svc := s.opts.Upgrade
	if t, ok := svc.Running(); ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "已有升级任务进行中", "task": t})
		return
	}
	t, err := svc.Start(req.TargetVersion)
	if err != nil {
		switch {
		case errors.Is(err, upgrade.ErrInvalidTarget), errors.Is(err, upgrade.ErrInvalidCurrent):
			writeErr(w, http.StatusBadRequest, err)
		case errors.Is(err, upgrade.ErrCooldown):
			writeErr(w, http.StatusTooManyRequests, err)
		default:
			writeErr(w, http.StatusInternalServerError, err)
		}
		return
	}
	target := t.TargetVersion
	if target == "" {
		target = "latest"
	}
	s.recordChange(r, "upgrade.start", target, "")
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID})
}

// handleUpgradeTask returns one task snapshot (404 when unknown, 400 when
// the id parameter is missing).
func (s *Server) handleUpgradeTask(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.upgradeUnavailable(w) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, simpleError("缺少 id 参数"))
		return
	}
	t, ok := s.opts.Upgrade.Task(id)
	if !ok {
		writeErr(w, http.StatusNotFound, simpleError("升级任务不存在"))
		return
	}
	writeJSON(w, http.StatusOK, t)
}
