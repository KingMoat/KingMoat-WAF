// Console TLS endpoints: the management plane's own certificate posture and
// hot-swappable binding to a certificate-library entry. The switch takes
// effect immediately (per-handshake GetCertificate) — no listener restart.
package api

import (
	"net/http"

	"github.com/kingmoat/kingmoat/internal/store"
)

// handleConsoleTLSGet returns the current console TLS posture
// (GET /api/console/tls; any authenticated role — it is read-only posture).
func (s *Server) handleConsoleTLSGet(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConsoleTLS == nil {
		writeErr(w, http.StatusNotFound, simpleError("console tls not configured"))
		return
	}
	writeJSON(w, http.StatusOK, s.opts.ConsoleTLS.Current())
}

// handleConsoleTLSApply switches the console certificate to a
// certificate-library entry (POST /api/console/tls {"cert_name": "..."}).
// Admin only: this is the management plane's own identity.
func (s *Server) handleConsoleTLSApply(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.opts.ConsoleTLS == nil {
		writeErr(w, http.StatusNotFound, simpleError("console tls not configured"))
		return
	}
	var req struct {
		CertName string `json:"cert_name"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.opts.ConsoleTLS.ApplyFromLibrary(req.CertName); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tls": s.opts.ConsoleTLS.Current()})
}
