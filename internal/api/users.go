// Console user management and role-based access control (admin / operator /
// auditor). Users live in the console SQLite store; the ONLY built-in
// account is the first-boot kmadmin bootstrap account (forced password
// change at first login). No other account is ever created automatically.
package api

import (
	"crypto/rand"
	"log/slog"
	"math/big"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/store"
)

// Roles ordered by privilege level (higher wins).
var roleLevel = map[string]int{
	store.RoleAuditor:  1,
	store.RoleOperator: 2,
	store.RoleAdmin:    3,
}

// RoleAtLeast reports whether the session role satisfies the required level.
func RoleAtLeast(role, required string) bool {
	return roleLevel[role] >= roleLevel[required]
}

// currentUser is attached to the request context by the auth middleware.
type currentUser struct {
	Username string
	Role     string
}

// requireRole answers 403 unless the request carries a session/basic user
// with the required role (legacy single-admin sessions carry role admin).
// When console auth is disabled (dev mode) all operations are allowed.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, required string) bool {
	if s.opts.Auth == nil || s.opts.Auth.hash == "" {
		return true // auth disabled (dev mode)
	}
	u := userFromContext(r)
	if u == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	if !RoleAtLeast(u.Role, required) {
		writeErr(w, http.StatusForbidden, simpleError("insufficient role: "+required+" required"))
		return false
	}
	return true
}

// userStore returns the users store (nil when the console DB is unavailable,
// e.g. pure API tests).
func (s *Server) userStore() *store.Store { return s.opts.Center.Store() }

// Default bootstrap account: created on first boot with an empty users
// table when no legacy admin hash is configured. The initial password must
// be changed before the console can be used (forced first-login flow).
const (
	bootstrapUsername = "kmadmin"
	bootstrapPassword = "KingMoat@2026"
)

// ensureAdminSeed creates the first-boot bootstrap account the first time the
// console starts with an empty users table: the kmadmin account with the
// initial password, forced into a password change at first login. This is the
// ONLY account the product ever creates automatically.
func (s *Server) ensureAdminSeed() {
	st := s.userStore()
	if st == nil {
		return
	}
	n, err := st.CountUsers()
	if err != nil || n > 0 {
		return
	}
	hash, herr := passhash.HashPassword(bootstrapPassword)
	if herr != nil {
		return
	}
	if _, cerr := st.CreateUserInitial(bootstrapUsername, hash, store.RoleAdmin); cerr == nil {
		slog.Warn("default console account created", "username", bootstrapUsername,
			"action", "first login forces a password change")
	}
}

// handleUserList returns all console accounts (admin only).
func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	users, err := s.userStore().ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// handleUserResetPassword generates a one-time temporary password for the
// target account (admin only): the password is returned once, the account is
// forced into a password change at the next login, and the action is audited.
// Admins cannot reset their own account here (use self-service instead).
func (s *Server) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	if me := userFromContext(r); me != nil && me.Username == username {
		writeErr(w, http.StatusBadRequest, simpleError("use the self-service password change for your own account"))
		return
	}
	st := s.userStore()
	if _, err := st.GetUser(username); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	tempPassword, err := generateTempPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	hash, err := passhash.HashPassword(tempPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := st.ResetUserPassword(username, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "user.reset_password", username, "temporary password issued (must change at next login)")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "username": username,
		"temp_password": tempPassword, "must_change": true,
	})
}

// generateTempPassword returns a 20-char alphanumeric one-time password.
func generateTempPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 20)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}

// handleUserCreate adds a console account (admin only).
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, simpleError("username is required"))
		return
	}
	if err := s.cfgSecurity().ValidatePassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}
	if !store.ValidRole(req.Role) {
		writeErr(w, http.StatusBadRequest, simpleError("role must be admin, operator or auditor"))
		return
	}
	hash, err := passhash.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := s.userStore().CreateUser(req.Username, hash, req.Role); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "user.create", req.Username, "role="+req.Role)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username, "role": req.Role})
}

// handleUserUpdate changes role/password/disabled flags (admin only).
// Deleting or demoting the last enabled admin is refused to avoid lockout.
func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	target, err := st.GetUser(username)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	var req struct {
		Role     *string `json:"role,omitempty"`
		Password *string `json:"password,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
		Email    *string `json:"email,omitempty"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var changes []string

	if req.Email != nil && strings.TrimSpace(*req.Email) != target.Email {
		if err := st.SetUserEmail(username, strings.TrimSpace(*req.Email)); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		changes = append(changes, "email updated")
	}

	if req.Role != nil && *req.Role != target.Role {
		if err := s.guardLastAdmin(st, username, func() error { return st.UpdateUserRole(username, *req.Role) }); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		changes = append(changes, "role="+*req.Role)
	}
	if req.Disabled != nil && *req.Disabled != target.Disabled {
		if err := s.guardLastAdmin(st, username, func() error { return st.UpdateUserDisabled(username, *req.Disabled) }); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if *req.Disabled {
			changes = append(changes, "disabled")
		} else {
			changes = append(changes, "enabled")
		}
	}
	if req.Password != nil {
		if err := s.cfgSecurity().ValidatePassword(*req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
			return
		}
		if err := s.rejectPasswordReuse(st, username, target.PasswordHash, *req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
			return
		}
		hash, err := passhash.HashPassword(*req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := st.UpdateUserPassword(username, hash, s.cfgSecurity().PasswordHistoryCountOrDefault()); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		changes = append(changes, "password reset")
	}
	if len(changes) > 0 {
		s.recordChange(r, "user.update", username, strings.Join(changes, ", "))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserDelete removes an account (admin only; last enabled admin is
// protected).
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	if err := s.guardLastAdmin(st, username, func() error { return st.DeleteUser(username) }); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "user.delete", username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// guardLastAdmin refuses an operation when it would leave the console with
// no enabled admin account.
func (s *Server) guardLastAdmin(st *store.Store, username string, op func() error) error {
	target, err := st.GetUser(username)
	if err != nil {
		return err
	}
	if target.Role != store.RoleAdmin || target.Disabled {
		return op()
	}
	users, err := st.ListUsers()
	if err != nil {
		return err
	}
	enabledAdmins := 0
	for _, u := range users {
		if u.Role == store.RoleAdmin && !u.Disabled {
			enabledAdmins++
		}
	}
	if enabledAdmins <= 1 {
		return simpleError("refusing: this would remove the last enabled admin account")
	}
	return op()
}
