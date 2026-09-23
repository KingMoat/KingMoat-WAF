package api

import (
	"net/http"

	"github.com/kingmoat/kingmoat/internal/store"
)

// handleDisableState exposes the data plane's CURRENT matcher disable state:
// site → disabled detection modules (plain stage names) and CRS category
// scopes ("coraza:<category>"). Read-only situational awareness for the
// console ("why is SQLi not blocking?") — admin/operator/auditor all read.
func (s *Server) handleDisableState(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAuditor) {
		return
	}
	out := map[string][]string{}
	if s.opts.DisableStateFn != nil {
		if reg := s.opts.DisableStateFn(); reg != nil {
			out = reg.Snapshot()
		}
	}
	writeJSON(w, http.StatusOK, out)
}
