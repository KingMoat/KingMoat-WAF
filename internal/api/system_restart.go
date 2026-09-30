// System restart API (admin): POST /api/system/restart asks systemd to
// restart the kingmoatwaf unit. The flow mirrors the console-port change
// (console_port.go): capability probe → audit → answer → submit the
// restart after a short delay, so the response connection is never torn
// down mid-write and the audit always precedes the process death.
//
// Deployment semantics: the restart submission lives on the upgrade
// service (nil = static mode / module not wired → 501); non-systemd and
// Windows deployments answer 501 with manual guidance, and the endpoint
// NEVER attempts a half-way "kill own process" fallback - on deployments
// without systemd the only correct action is to tell the operator how to
// restart the service themselves.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/kingmoat/kingmoat/internal/naming"
	"github.com/kingmoat/kingmoat/internal/store"
	"github.com/kingmoat/kingmoat/internal/upgrade"
)

// systemRestartDelay gives the HTTP response a head start before the
// restart submission fires: the submitter must not race the response write
// (same reasoning as console_port.go's defaultRestartDelay, and the task
// card's "avoid killing the response connection" requirement).
const systemRestartDelay = time.Second

// maxRestartDelaySeconds bounds the caller-supplied extra delay on top of
// systemRestartDelay (the card's contract: 0-60, out of range = 400).
const maxRestartDelaySeconds = 60

// handleSystemRestart submits a whole-service restart (admin only). Order
// of operations (task card T-RST-01): role gate → capability probe → body
// validation → change audit → response → delayed async submission. The
// audit MUST land before the systemctl submission: the restart tears this
// process down moments later, so anything written after the submission is
// lost with it - and unlike the best-effort recordChange precedent (which
// runs after the operation already succeeded), here the audit is the only
// durable trace of the action, so a failed write cancels the restart (an
// untraceable management action is worse than no action).
func (s *Server) handleSystemRestart(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.opts.Upgrade == nil {
		writeErr(w, http.StatusNotImplemented, simpleError("服务重启接口未启用（当前部署形态不支持在线重启）"))
		return
	}
	// An in-flight upgrade owns the process lifecycle (download → swap →
	// restart submission): an API-triggered restart tearing the unit down
	// mid-pipeline would orphan the swap and the self-heal handover. The
	// refusal is unconditional - it does not depend on the probe verdict -
	// and comes first to avoid a pointless probe.
	if _, busy := s.opts.Upgrade.Running(); busy {
		writeErr(w, http.StatusConflict, simpleError("升级任务进行中，禁止重启"))
		return
	}
	// Probe BEFORE the audit: a refused restart must not leave a
	// "restarting" audit entry behind.
	if err := s.opts.Upgrade.RestartProbe(); err != nil {
		guidance := fmt.Errorf("%w（可手动执行 systemctl restart %s 或 kmwafctl restart）", err, naming.ServiceName)
		if errors.Is(err, upgrade.ErrRestartUnavailable) {
			writeErr(w, http.StatusNotImplemented, guidance)
			return
		}
		writeErr(w, http.StatusInternalServerError, guidance)
		return
	}
	var req struct {
		DelaySeconds int `json:"delay_seconds"`
	}
	// An empty body is the common "restart now" call, so an absent JSON
	// document must not fail the decode.
	if err := decodeBody(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.DelaySeconds < 0 || req.DelaySeconds > maxRestartDelaySeconds {
		writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf("delay_seconds 需在 0-%d 之间", maxRestartDelaySeconds)))
		return
	}
	delay := systemRestartDelay + time.Duration(req.DelaySeconds)*time.Second
	if s.opts.SystemRestartDelay > 0 {
		delay = s.opts.SystemRestartDelay // test hook, mirrors Options.RestartDelay
	}
	actor, role := "local", ""
	if s.opts.Auth != nil && s.opts.Auth.hash != "" {
		actor, role = "unknown", ""
		if u := userFromContext(r); u != nil {
			actor, role = u.Username, u.Role
		}
	}
	detail := fmt.Sprintf("source_ip=%s delay_seconds=%d", remoteIP(r), req.DelaySeconds)
	if err := s.userStore().RecordChange(actor, role, "system.restart", naming.ServiceName, detail); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("变更审计写入失败，已取消重启（管理动作必须可追溯）: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "restarting"})
	// Submit the restart AFTER the response is written, so the submission
	// can never kill the response connection. The verdict cannot reach the
	// client anymore (the response is long gone) - failures are logged.
	svc := s.opts.Upgrade
	time.AfterFunc(delay, func() {
		// Deliberately NOT r.Context(): the request (and its context) is long
		// gone by the time the timer fires - a canceled context would fail
		// every submission. The submission bounds itself (5s systemctl
		// timeout inside defaultRestarter).
		//
		// TOCTOU re-check: the entry guard only saw the request-time state -
		// an upgrade task may have started during the delay window. The task
		// owns the process lifecycle (download -> swap -> restart handover),
		// so submitting now would orphan the swap mid-pipeline - the same
		// hazard the entry 409 guard protects against, re-checked at
		// timer-fire time when the answer can only reach the log.
		if task, busy := svc.Running(); busy {
			slog.Error("system restart cancelled: upgrade task started during the delay window",
				"task_id", task.ID, "delay", delay.String())
			return
		}
		if err := svc.Restart(context.Background()); err != nil {
			slog.Error("system restart submission failed", "err", err)
		}
	})
}

// remoteIP extracts the client IP from the request (used for the restart
// audit trail; the same shape as the login limiter's IP extraction).
func remoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
