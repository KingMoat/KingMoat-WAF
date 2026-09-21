// Per-user console credentials: API keys (Bearer tokens for scripting and
// Prometheus scrapes) and TOTP MFA enrollment. Admins manage any account
// via /api/users/{username}/...; every signed-in account manages its own
// credentials via /api/me/.... Key plaintexts and TOTP secrets are never
// returned in clear twice, and all mutations land in the change audit.
package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"
	"net/http"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/kingmoat/kingmoat/internal/store"
)

// apiKeyPrefix namespaces console API keys; format is
// kma1_<8-hex-id>_<43-char base64url secret>.
const apiKeyPrefix = "kma1_"

// splitAPIKey parses a Bearer token in API-key form.
func splitAPIKey(token string) (id, secret string, ok bool) {
	if len(token) < len(apiKeyPrefix)+2 || token[:len(apiKeyPrefix)] != apiKeyPrefix {
		return "", "", false
	}
	rest := token[len(apiKeyPrefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '_' {
			return rest[:i], rest[i+1:], true
		}
	}
	return "", "", false
}

// hashAPISecret hashes the secret part for at-rest storage (the id half is
// public and used for lookup).
func hashAPISecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// mintAndStoreAPIKey generates a key and stores its hash on the account.
func mintAndStoreAPIKey(st *store.Store, username string) (plaintext, keyID string, err error) {
	plaintext, keyID, keyHash, err := generateAPIKey()
	if err != nil {
		return "", "", err
	}
	if err := st.SetUserAPIKey(username, keyID, keyHash); err != nil {
		return "", "", err
	}
	return plaintext, keyID, nil
}

// generateAPIKey returns (plaintext, keyID, secretHash).
func generateAPIKey() (string, string, string, error) {
	var idBytes [4]byte
	var secret [32]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", "", "", fmt.Errorf("api key: generate id: %w", err)
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", "", fmt.Errorf("api key: generate secret: %w", err)
	}
	id := hex.EncodeToString(idBytes[:])
	secretB64 := base64.RawURLEncoding.EncodeToString(secret[:])
	return apiKeyPrefix + id + "_" + secretB64, id, hashAPISecret(secretB64), nil
}

// startMFAEnrollment stores a pending TOTP secret and renders the QR image.
func startMFAEnrollment(st *store.Store, username string) (secretB32, url, qrB64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "KingMoat",
		AccountName: username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("mfa: generate secret: %w", err)
	}
	if err := st.SetUserTOTPPending(username, key.Secret()); err != nil {
		return "", "", "", err
	}
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", "", fmt.Errorf("mfa: render qr: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", "", fmt.Errorf("mfa: encode qr: %w", err)
	}
	return key.Secret(), key.URL(), base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// confirmUserMFA validates one code against the pending secret and
// activates per-user MFA.
func confirmUserMFA(st *store.Store, username, code string) error {
	u, err := st.GetUser(username)
	if err != nil {
		return err
	}
	if u.TOTPPending == "" {
		return simpleError("no pending MFA enrollment (call mfa/setup first)")
	}
	if !totp.Validate(code, u.TOTPPending) {
		return simpleError("invalid TOTP code")
	}
	return st.ConfirmUserTOTP(username)
}

// selfAccount resolves the signed-in account for /api/me endpoints; returns
// (nil, false) when there is no console identity (dev mode).
func (s *Server) selfAccount(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u := userFromContext(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, simpleError("no console identity (auth disabled)"))
		return nil, false
	}
	st := s.userStore()
	user, err := st.GetUser(u.Username)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return nil, false
	}
	return user, true
}

// handleMe returns the signed-in account's identity and credential state.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     user.Username,
		"role":         user.Role,
		"api_key_id":   user.APIKeyID,
		"totp_enabled": user.TOTPEnabled,
	})
}

// handleMeAPIKeyCreate generates (or replaces) the caller's own API key.
func (s *Server) handleMeAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	plaintext, keyID, err := mintAndStoreAPIKey(s.userStore(), user.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "apikey.create", user.Username, "self-service key "+keyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"api_key":    plaintext,
		"api_key_id": keyID,
		"notice":     "请立即保存，此密钥仅显示一次；重新生成会使旧密钥立即失效",
	})
}

// handleMeAPIKeyDelete revokes the caller's own API key.
func (s *Server) handleMeAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	if err := s.userStore().ClearUserAPIKey(user.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "apikey.revoke", user.Username, "self-service")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMeMFASetup starts self-service TOTP enrollment.
func (s *Server) handleMeMFASetup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	secret, url, qrB64, err := startMFAEnrollment(s.userStore(), user.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"secret":      secret,
		"otpauth_url": url,
		"qr_png":      qrB64,
		"notice":      "请用认证器 App 扫码后输入 6 位动态码确认；确认前 MFA 不会生效",
	})
}

// handleMeMFAConfirm confirms self-service enrollment.
func (s *Server) handleMeMFAConfirm(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := confirmUserMFA(s.userStore(), user.Username, req.Code); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "mfa.enable", user.Username, "self-service")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "totp_enabled": true})
}

// handleMeMFADisable turns off the caller's own MFA.
func (s *Server) handleMeMFADisable(w http.ResponseWriter, r *http.Request) {
	user, ok := s.selfAccount(w, r)
	if !ok {
		return
	}
	if err := s.userStore().DisableUserTOTP(user.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "mfa.disable", user.Username, "self-service")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "totp_enabled": false})
}

// ---- admin-managed endpoints (user management surface) ----

// handleUserAPIKeyCreate generates (or replaces) an account's API key. The
// plaintext is returned exactly once.
func (s *Server) handleUserAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	if _, err := st.GetUser(username); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	plaintext, keyID, err := mintAndStoreAPIKey(st, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "apikey.create", username, "key "+keyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"username":   username,
		"api_key":    plaintext,
		"api_key_id": keyID,
		"notice":     "请立即保存，此密钥仅显示一次；重新生成会使旧密钥立即失效",
	})
}

// handleUserAPIKeyDelete revokes an account's API key.
func (s *Server) handleUserAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	if err := s.userStore().ClearUserAPIKey(username); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "apikey.revoke", username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

// handleUserMFASetup starts TOTP enrollment: a pending secret is stored and
// returned with its otpauth URL and QR image (base64 PNG). It becomes
// active only after handleUserMFAConfirm validates one code.
func (s *Server) handleUserMFASetup(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	st := s.userStore()
	if _, err := st.GetUser(username); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	secret, url, qrB64, err := startMFAEnrollment(st, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"username":    username,
		"secret":      secret,
		"otpauth_url": url,
		"qr_png":      qrB64,
		"notice":      "请用认证器 App 扫码后输入 6 位动态码确认；确认前 MFA 不会生效",
	})
}

// handleUserMFAConfirm validates one TOTP code against the pending secret
// and activates per-user MFA.
func (s *Server) handleUserMFAConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	if err := confirmUserMFA(s.userStore(), username, decodeCode(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "mfa.enable", username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "totp_enabled": true})
}

// handleUserMFADisable turns off per-user MFA.
func (s *Server) handleUserMFADisable(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	username := r.PathValue("username")
	if err := s.userStore().DisableUserTOTP(username); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, "mfa.disable", username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "totp_enabled": false})
}

// decodeCode reads {"code": "..."} from the request body.
func decodeCode(r *http.Request) string {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &req); err != nil {
		return ""
	}
	return req.Code
}
