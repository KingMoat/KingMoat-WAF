package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/store"
)

// cfgSecurity returns the active console security policy (nil-safe defaults).
func (s *Server) cfgSecurity() *config.ConsoleSecuritySettings {
	_, cfg := s.opts.Center.Current()
	return cfg.Security
}

// loginMax / loginWindow resolve the live brute-force protection settings
// (system settings → 安全设置 → 登录防爆破).
func (s *Server) loginMax() int {
	return s.cfgSecurity().LoginMaxFailuresOrDefault()
}

func (s *Server) loginWindow() time.Duration {
	return s.cfgSecurity().LoginLockoutOrDefault()
}

// handleMePassword serves POST /api/me/password: self-service password
// change. The current password is re-verified and the new one must satisfy
// the configured policy; the session cookie stays valid.
func (s *Server) handleMePassword(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r)
	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	st := s.userStore()
	if st == nil {
		writeErr(w, http.StatusNotImplemented, simpleError("user store unavailable"))
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	target, err := st.GetUser(u.Username)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if !passhash.VerifyArgon2id(target.PasswordHash, req.OldPassword) {
		writeErr(w, http.StatusBadRequest, simpleError("当前密码不正确"))
		return
	}
	if err := s.cfgSecurity().ValidatePassword(req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}
	if err := s.rejectPasswordReuse(st, u.Username, target.PasswordHash, req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}
	hash, err := passhash.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := st.UpdateUserPassword(u.Username, hash, s.cfgSecurity().PasswordHistoryCountOrDefault()); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "user.password_change", u.Username, "self-service")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// rejectPasswordReuse enforces the password-history policy: the new password
// must differ from the current one and from the last N recorded hashes
// (system settings → 安全设置 → 密码历史). The argon2 checks burn real
// verification cost per candidate; N is capped at 24 by the config layer.
func (s *Server) rejectPasswordReuse(st *store.Store, username, currentHash, newPassword string) error {
	n := s.cfgSecurity().PasswordHistoryCountOrDefault()
	if n <= 0 {
		return nil
	}
	candidates := append([]string{currentHash}, st.PasswordHistory(username)...)
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	for i, h := range candidates {
		if h == "" {
			continue
		}
		if passhash.VerifyArgon2id(h, newPassword) {
			return fmt.Errorf("新密码与最近 %d 次使用过的密码重复（第 %d 个），请更换", n, i+1)
		}
	}
	return nil
}

// handleAccessLogs serves GET /api/access_logs: the in-memory recent tail of
// the full access-log pipeline (available when access_log is enabled).
func (s *Server) handleAccessLogs(w http.ResponseWriter, r *http.Request) {
	ring := s.opts.AccessRing
	if ring == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"hint":    "访问日志管道未启用（系统设置 → 日志外发 → 全量访问日志）",
			"items":   []struct{}{},
		})
		return
	}
	qp := r.URL.Query()
	limit := 200
	if v := qp.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}
	items := ring.Recent(limit, qp.Get("site"), qp.Get("q"), qp.Get("outcome"))
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"count":   ring.Count(),
		"items":   items,
	})
}

// passwordExpired reports whether the account's password violates the
// configured max-age policy (policy off / no anchor → false).
func (s *Server) passwordExpired(username string, sec *config.ConsoleSecuritySettings) bool {
	maxAge := sec.MaxAgeOrDefault()
	if maxAge <= 0 {
		return false
	}
	st := s.userStore()
	if st == nil {
		return false
	}
	changed, err := st.PasswordChangedAt(username)
	if err != nil || changed.IsZero() {
		return false
	}
	return time.Since(changed) > time.Duration(maxAge)*24*time.Hour
}
