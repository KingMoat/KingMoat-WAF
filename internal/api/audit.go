// Management change audit for the console: every user/credential mutation
// records who did what to whom. Entries are visible in the console (用户管理
// → 变更记录) via GET /api/audit/changes.
package api

import (
	"net/http"
	"strconv"

	"github.com/kingmoat/kingmoat/internal/store"
)

// recordChange writes one audit entry attributed to the acting console user
// (session, Basic or API-key identity). Dev mode (auth disabled) records
// actor "local".
func (s *Server) recordChange(r *http.Request, action, target, detail string) {
	if s.opts.Auth == nil || s.opts.Auth.hash == "" {
		if err := s.userStore().RecordChange("local", "", action, target, detail); err != nil {
			return // audit is best-effort; the operation itself already succeeded
		}
		return
	}
	actor, role := "unknown", ""
	if u := userFromContext(r); u != nil {
		actor, role = u.Username, u.Role
	}
	_ = s.userStore().RecordChange(actor, role, action, target, detail)
}

// handleAuditList returns recent management change entries. Readable by any
// authenticated console role (auditor included).
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAuditor) {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	logs, err := s.userStore().ListChangeLogs(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if logs == nil {
		logs = []store.ChangeLog{}
	}
	writeJSON(w, http.StatusOK, logs)
}
