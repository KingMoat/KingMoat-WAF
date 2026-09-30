package api

import (
	"net/http"

	"github.com/kingmoat/kingmoat/internal/store"
)

// handleDisableState exposes the data plane's CURRENT matcher disable state:
// site → disabled detection modules (plain stage names) and CRS category
// scopes ("coraza:<category>"). Read-only situational awareness for the
// console ("why is SQLi not blocking?") — admin/operator/auditor all read.
// Response is always an explicit envelope ({"stages":{},"total":0} when
// nothing is disabled) so consumers never see a bare {} or null body.
func (s *Server) handleDisableState(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAuditor) {
		return
	}
	stages := map[string][]string{}
	if s.opts.DisableStateFn != nil {
		if reg := s.opts.DisableStateFn(); reg != nil {
			stages = reg.Snapshot()
		}
	}
	if stages == nil {
		stages = map[string][]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"stages": stages, "total": len(stages)})
}
