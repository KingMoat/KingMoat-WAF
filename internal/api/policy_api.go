// Strategy-page APIs: false-positive whitelisting (log one-click whitelist →
// micro-engine allow rule), legacy false-positive exceptions (deprecated,
// kept only for migration), IP-group subscription management and
// interception-page copy. Changes publish a new config revision (hot reload,
// rollback-able).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/store"
)

// whitelistReq is the body of POST /api/policy/whitelist.
type whitelistReq struct {
	Site    string `json:"site"`             // domain; empty = all sites (legacy entries)
	Path    string `json:"path"`             // exact path or prefix
	Prefix  bool   `json:"prefix,omitempty"`  // true → prefix condition
	Comment string `json:"comment,omitempty"`
}

// cloneConfig deep-copies the shared active config via JSON round-trip (the
// same serialization the config center stores) so handlers never mutate the
// shared pointer in place: a failed Publish must leave the live config and
// concurrent Current() readers untouched.
func cloneConfig(cfg *config.Config) (*config.Config, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	out := &config.Config{}
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return out, nil
}

// isWhitelistDuplicate reports whether an existing allow rule already covers
// site+path+match-mode (idempotency check for POST /api/policy/whitelist).
func isWhitelistDuplicate(rules []config.MatcherRule, site, path string, prefix bool) bool {
	op := config.OpEq
	if prefix {
		op = config.OpPrefix
	}
	for _, m := range rules {
		if m.Action != config.ActionAllow {
			continue
		}
		if len(m.Sites) != 1 || !strings.EqualFold(m.Sites[0], site) {
			continue
		}
		if len(m.Conditions) != 1 {
			continue
		}
		c := m.Conditions[0]
		if c.Field == config.FieldPath && c.Op == op && c.Value == path {
			return true
		}
	}
	return false
}

// whitelistRuleName builds the rule display name, suffixing " #N" when the
// base name already exists (repeated whitelists on one site stay unique).
func whitelistRuleName(rules []config.MatcherRule, site, path string) string {
	base := "误报加白: " + site + path
	taken := map[string]bool{}
	for _, m := range rules {
		taken[m.Name] = true
	}
	if !taken[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s #%d", base, n)
		if !taken[candidate] {
			return candidate
		}
	}
}

// handlePolicyWhitelist serves POST /api/policy/whitelist {site, path,
// prefix, comment} (operator+): creates a micro-engine allow rule (site +
// path condition, action=allow → the whole detection chain is skipped for
// that path) and publishes. Idempotent: an existing allow rule with the same
// site+path+match-mode returns {ok, unchanged:true} without a new revision.
// The config is deep-copied before mutation; the shared active config is
// never modified in place.
func (s *Server) handlePolicyWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req whitelistReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	site := strings.ToLower(strings.TrimSpace(req.Site))
	path := strings.TrimSpace(req.Path)
	if path == "" || !strings.HasPrefix(path, "/") {
		writeErr(w, http.StatusBadRequest, simpleError("path is required and must start with /"))
		return
	}
	_, cfg := s.opts.Center.Current()
	clone, err := cloneConfig(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if clone.Policy == nil {
		clone.Policy = &config.Policy{}
	}
	if isWhitelistDuplicate(clone.Policy.Matchers, site, path, req.Prefix) {
		rev, _ := s.opts.Center.Current()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "revision": rev})
		return
	}
	rule := config.MatcherRule{
		Name:    whitelistRuleName(clone.Policy.Matchers, site, path),
		Enabled: true,
		Action:  config.ActionAllow,
		Logic:   "and",
		Conditions: []config.MatcherCondition{{
			Field: config.FieldPath,
			Op:    config.OpEq,
			Value: path,
		}},
		Comment: "误报加白",
	}
	if req.Prefix {
		rule.Conditions[0].Op = config.OpPrefix
	}
	if site != "" {
		rule.Sites = []string{site}
	} // else Sites stays nil = all sites (legacy exception entries)
	if comment := strings.TrimSpace(req.Comment); comment != "" {
		rule.Comment = "误报加白：" + comment
	}
	if err := rule.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	clone.Policy.Matchers = append(clone.Policy.Matchers, rule)
	newRev, err := s.opts.Center.Publish(clone, s.author(r), fmt.Sprintf("whitelist: %s %s", site, path))
	if err != nil {
		if errors.Is(err, configcenter.ErrNoChanges) {
			rev, _ := s.opts.Center.Current()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "revision": rev})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "policy.whitelist", site+path, "micro-engine allow rule created: "+rule.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": false, "revision": newRev, "name": rule.Name})
}

// handleExceptionList returns the configured false-positive exceptions.
//
// Deprecated: exceptions are superseded by micro-engine allow rules created
// via POST /api/policy/whitelist. Kept (read/write) only so the console can
// migrate legacy entries; new integrations must not use this endpoint.
func (s *Server) handleExceptionList(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	list := []config.Exception{}
	if cfg.Policy != nil {
		list = cfg.Policy.Exceptions
	}
	writeJSON(w, http.StatusOK, list)
}

// handleExceptionCreate appends an exception and publishes.
func (s *Server) handleExceptionCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var e config.Exception
	if err := decodeBody(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := e.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rev, cfg := s.opts.Center.Current()
	if cfg.Policy == nil {
		cfg.Policy = &config.Policy{}
	}
	cfg.Policy.Exceptions = append(cfg.Policy.Exceptions, e)
	newRev, err := s.opts.Center.Publish(cfg, s.author(r), fmt.Sprintf("exception: %s%s (%s)", e.Site, e.Path, e.RuleID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = rev
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": newRev})
}

// handleExceptionDelete removes an exception by index and publishes.
func (s *Server) handleExceptionDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("invalid index"))
		return
	}
	_, cfg := s.opts.Center.Current()
	if cfg.Policy == nil || idx < 0 || idx >= len(cfg.Policy.Exceptions) {
		writeErr(w, http.StatusNotFound, simpleError("exception not found"))
		return
	}
	removed := cfg.Policy.Exceptions[idx]
	cfg.Policy.Exceptions = append(cfg.Policy.Exceptions[:idx], cfg.Policy.Exceptions[idx+1:]...)
	newRev, err := s.opts.Center.Publish(cfg, s.author(r), fmt.Sprintf("exception removed: %s%s", removed.Site, removed.Path))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": newRev})
}

// handleIPGroupList returns subscription groups with entry previews.
func (s *Server) handleIPGroupList(w http.ResponseWriter, r *http.Request) {
	if s.groups() == nil {
		writeErr(w, http.StatusNotFound, simpleError("no ip groups configured"))
		return
	}
	writeJSON(w, http.StatusOK, s.groups().Describe())
}

// handleIPGroupRefresh forces a synchronous re-fetch of one group.
func (s *Server) handleIPGroupRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	if s.groups() == nil {
		writeErr(w, http.StatusNotFound, simpleError("no ip groups configured"))
		return
	}
	if !s.groups().RefreshNow(r.PathValue("name")) {
		writeErr(w, http.StatusNotFound, simpleError("group not found"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// author returns the acting console user for publish attribution.
func (s *Server) author(r *http.Request) string {
	if u := userFromContext(r); u != nil {
		return u.Username
	}
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return user
	}
	return "admin"
}

// groups returns the live IP-group subscription manager (nil when none
// configured). The data plane owns the manager instance.
func (s *Server) groups() *ipgroups.Manager {
	if s.groupsFn == nil {
		return nil
	}
	return s.groupsFn()
}

// author returns the acting console user for publish attribution.

