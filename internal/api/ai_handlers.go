package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/store"
)

// AI handlers: thin proxies over *ai.Service (nil = module disabled).

func (s *Server) aiDisabled(w http.ResponseWriter) {
	writeErr(w, http.StatusNotFound, fmt.Errorf("ai assistant is not enabled"))
}

// handleAIConfig serves GET /api/ai/config. "enabled" reports EFFECTIVE
// availability: the assistant is configured on AND an API key actually
// resolves (stored cipher / env var / inline literal). Without a usable key
// every chat would fail, so the console must show 未启用 instead of a
// half-working assistant; key_source keeps the resolved source for the
// settings-page badge (stored/env/inline/none).
func (s *Server) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "templates": ai.Templates()})
		return
	}
	cfg := s.ai().Config()
	if set, _ := cfg["api_key_set"].(bool); !set {
		cfg["enabled"] = false
	}
	cfg["templates"] = ai.Templates()
	writeJSON(w, http.StatusOK, cfg)
}

// handleAIChat serves POST /api/ai/chat (SSE).
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	owner := ""
	if u := userFromContext(r); u != nil {
		owner = u.Username
	}
	s.ai().HandleChat(w, r, owner)
}

// canAccessSession reports whether the requester may read/delete the
// session: authless deployments skip the check; admins see everything;
// everyone else only their own sessions (legacy owner='' rows are admin-only).
func (s *Server) canAccessSession(r *http.Request, id string) bool {
	u := userFromContext(r)
	if u == nil || u.Role == store.RoleAdmin {
		return true
	}
	own, err := s.ai().SessionOwner(id)
	return err == nil && own == u.Username
}

// handleAISessions serves GET /api/ai/sessions.
func (s *Server) handleAISessions(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	owner := ""
	if u := userFromContext(r); u != nil && u.Role != store.RoleAdmin {
		owner = u.Username
	}
	sessions, err := s.ai().ListSessions(100, owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// handleAISessionMessages serves GET /api/ai/sessions/{id}/messages.
func (s *Server) handleAISessionMessages(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	if !s.canAccessSession(r, r.PathValue("id")) {
		writeErr(w, http.StatusForbidden, fmt.Errorf("not your session"))
		return
	}
	msgs, err := s.ai().SessionMessages(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

// handleAISessionDelete serves DELETE /api/ai/sessions/{id}.
func (s *Server) handleAISessionDelete(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	if !s.canAccessSession(r, r.PathValue("id")) {
		writeErr(w, http.StatusForbidden, fmt.Errorf("not your session"))
		return
	}
	if err := s.ai().DeleteSession(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAIReports serves GET /api/ai/reports.
func (s *Server) handleAIReports(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	reports, err := s.ai().ListReports(100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

// handleAIReportGet serves GET /api/ai/reports/{id}.
func (s *Server) handleAIReportGet(w http.ResponseWriter, r *http.Request) {
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid report id"))
		return
	}
	rep, err := s.ai().GetReport(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleAIReportRun serves POST /api/ai/reports/run {"kind": "..."}.
func (s *Server) handleAIReportRun(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	if s.ai() == nil {
		s.aiDisabled(w)
		return
	}
	var req struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	window := 24 * time.Hour
	if req.Kind == "attack_summary_weekly" {
		window = 7 * 24 * time.Hour
	}
	id, err := s.ai().RunReport(req.Kind, "manual", window, ai.Delivery{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// ai returns the live assistant instance (nil = disabled); the entrypoint
// swaps the instance on hot reload when the ai config toggles.
func (s *Server) ai() *ai.Service {
	if s.aiFn == nil {
		return nil
	}
	return s.aiFn()
}

// handleMCPForward routes MCP requests to the live assistant instance.
func (s *Server) handleMCPForward(w http.ResponseWriter, r *http.Request) {
	svc := s.ai()
	if svc == nil || !svc.MCPEnabled() {
		writeErr(w, http.StatusNotFound, fmt.Errorf("ai assistant is not enabled"))
		return
	}
	svc.MCPHandler(s.opts.Version).ServeHTTP(w, r)
}
