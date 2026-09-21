// Console users for role-based access control (admin / operator / auditor).
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Roles supported by the console RBAC model.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
)

// ValidRole reports whether role is one of the supported roles.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleAuditor
}

// ErrUserNotFound is returned when a username does not exist.
var ErrUserNotFound = errors.New("store: user not found")

// User is one console account (password_hash/api_key_hash/totp secrets are
// never serialized).
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
	// API key (plaintext is only shown once at generation time).
	APIKeyID        string     `json:"api_key_id,omitempty"`
	APIKeyCreatedAt *time.Time `json:"api_key_created_at,omitempty"`
	APIKeyLastUsed  *time.Time `json:"api_key_last_used,omitempty"`
	APIKeyHash      string     `json:"-"`
	// Per-user TOTP MFA.
	TOTPEnabled bool   `json:"totp_enabled"`
	TOTPSecret  string `json:"-"` // active base32 secret
	TOTPPending string `json:"-"` // secret awaiting confirmation
	// MustChange marks the initial-password state: while set, the console
	// only serves the self-service password change until it is cleared.
	MustChange bool `json:"must_change"`
	// Email is the optional contact address (password-reset mail target).
	Email string `json:"email,omitempty"`
}

// ResetUserPassword replaces a password hash and forces a change at the next
// login (admin-initiated reset and CLI rescue). Existing sessions remain
// valid but are gated by the must-change flow until the new password is set.
func (s *Store) ResetUserPassword(username, passwordHash string) error {
	res, err := s.db.Exec(
		`UPDATE users SET password_hash = ?, must_change = 1 WHERE username = ?`,
		passwordHash, username)
	if err != nil {
		return fmt.Errorf("store: reset password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetUserEmail stores the optional contact address ('' clears it).
func (s *Store) SetUserEmail(username, email string) error {
	res, err := s.db.Exec(`UPDATE users SET email = ? WHERE username = ?`, email, username)
	if err != nil {
		return fmt.Errorf("store: set email: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// CountUsers returns the number of console accounts.
func (s *Store) CountUsers() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// CreateUser inserts a console account.
func (s *Store) CreateUser(username, passwordHash, role string) (int64, error) {
	if !ValidRole(role) {
		return 0, fmt.Errorf("store: invalid role %q", role)
	}
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, disabled, created_at) VALUES(?,?,?,0,?)`,
		username, passwordHash, role, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("store: create user: %w", err)
	}
	return res.LastInsertId()
}

// CreateUserInitial inserts the first-boot default account with the
// must-change flag set so the first login is forced into a password change.
func (s *Store) CreateUserInitial(username, passwordHash, role string) (int64, error) {
	if !ValidRole(role) {
		return 0, fmt.Errorf("store: invalid role %q", role)
	}
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, disabled, must_change, created_at) VALUES(?,?,?,0,1,?)`,
		username, passwordHash, role, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("store: create initial user: %w", err)
	}
	return res.LastInsertId()
}

// GetUser returns one account by username.
func (s *Store) GetUser(username string) (*User, error) {
	row := s.db.QueryRow(userSelect+` WHERE username = ?`, username)
	return scanUser(row)
}

// GetUserByAPIKeyID returns the account owning an API key id.
func (s *Store) GetUserByAPIKeyID(keyID string) (*User, error) {
	row := s.db.QueryRow(userSelect+` WHERE api_key_id = ?`, keyID)
	return scanUser(row)
}

// userSelect lists the users columns in scanUser order.
const userSelect = `SELECT id, username, password_hash, role, disabled, created_at,
	api_key_id, api_key_hash, api_key_created_at, api_key_last_used,
	totp_secret, totp_pending, totp_enabled, must_change, email FROM users`

// ListUsers returns all console accounts ordered by creation.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(userSelect + ` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpdateUserPassword replaces an account's password hash and stamps the
// change time (anchor for the password max-age policy). The forced-change
// flag is cleared: any pending initial-password state ends here. When
// historyCount > 0 the replaced hash is prepended to the password history
// (JSON array, oldest evicted) so a future change can reject reuses.
func (s *Store) UpdateUserPassword(username, passwordHash string, historyCount int) error {
	var oldHash, histRaw string
	if err := s.db.QueryRow(`SELECT password_hash, password_history FROM users WHERE username = ?`, username).Scan(&oldHash, &histRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("store: read password history: %w", err)
	}
	hist := []string{}
	if histRaw != "" {
		_ = json.Unmarshal([]byte(histRaw), &hist)
	}
	var histOut string
	if historyCount > 0 {
		hist = append([]string{oldHash}, hist...)
		if len(hist) > historyCount {
			hist = hist[:historyCount]
		}
		if b, err := json.Marshal(hist); err == nil {
			histOut = string(b)
		}
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ?, password_changed_at = ?, must_change = 0, password_history = ? WHERE username = ?`,
		passwordHash, time.Now().UTC().Format(time.RFC3339), histOut, username)
	if err != nil {
		return fmt.Errorf("store: update password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// PasswordHistory returns the recorded previous password hashes (JSON list,
// newest first). Empty when the feature has never applied to the account.
func (s *Store) PasswordHistory(username string) []string {
	var raw string
	if err := s.db.QueryRow(`SELECT password_history FROM users WHERE username = ?`, username).Scan(&raw); err != nil || raw == "" {
		return nil
	}
	var hist []string
	if err := json.Unmarshal([]byte(raw), &hist); err != nil {
		return nil
	}
	return hist
}

// PasswordChangedAt returns the last password change time (zero value when
// the account predates the column — treated as "no anchor" by the policy).
func (s *Store) PasswordChangedAt(username string) (time.Time, error) {
	var raw string
	err := s.db.QueryRow(`SELECT password_changed_at FROM users WHERE username = ?`, username).Scan(&raw)
	if err != nil {
		return time.Time{}, err
	}
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// UpdateUserRole changes an account's role.
func (s *Store) UpdateUserRole(username, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("store: invalid role %q", role)
	}
	res, err := s.db.Exec(`UPDATE users SET role = ? WHERE username = ?`, role, username)
	if err != nil {
		return fmt.Errorf("store: update role: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpdateUserDisabled enables/disables an account.
func (s *Store) UpdateUserDisabled(username string, disabled bool) error {
	res, err := s.db.Exec(`UPDATE users SET disabled = ? WHERE username = ?`, boolInt(disabled), username)
	if err != nil {
		return fmt.Errorf("store: update disabled: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// DeleteUser removes an account (the last admin is protected by the caller).
func (s *Store) DeleteUser(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetUserAPIKey stores (or replaces) an account's API key.
func (s *Store) SetUserAPIKey(username, keyID, keyHash string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE users SET api_key_id = ?, api_key_hash = ?, api_key_created_at = ?, api_key_last_used = '' WHERE username = ?`,
		keyID, keyHash, now, username)
	if err != nil {
		return fmt.Errorf("store: set api key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ClearUserAPIKey revokes an account's API key.
func (s *Store) ClearUserAPIKey(username string) error {
	res, err := s.db.Exec(
		`UPDATE users SET api_key_id = '', api_key_hash = '', api_key_created_at = '', api_key_last_used = '' WHERE username = ?`,
		username)
	if err != nil {
		return fmt.Errorf("store: clear api key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// TouchAPIKeyUsed updates the last-used timestamp, throttled to once per
// minute to keep write volume negligible.
func (s *Store) TouchAPIKeyUsed(keyID string) error {
	if keyID == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	aMinuteAgo := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`UPDATE users SET api_key_last_used = ? WHERE api_key_id = ? AND (api_key_last_used = '' OR api_key_last_used < ?)`,
		now, keyID, aMinuteAgo)
	if err != nil {
		return fmt.Errorf("store: touch api key: %w", err)
	}
	return nil
}

// SetUserTOTPPending stores a secret awaiting confirmation (enrollment step
// 1; the authenticator is not active until ConfirmUserTOTP).
func (s *Store) SetUserTOTPPending(username, secretB32 string) error {
	res, err := s.db.Exec(`UPDATE users SET totp_pending = ? WHERE username = ?`, secretB32, username)
	if err != nil {
		return fmt.Errorf("store: set totp pending: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ConfirmUserTOTP activates enrollment: the pending secret becomes the
// active one and future logins require a valid code.
func (s *Store) ConfirmUserTOTP(username string) error {
	res, err := s.db.Exec(
		`UPDATE users SET totp_secret = totp_pending, totp_pending = '', totp_enabled = 1 WHERE username = ? AND totp_pending != ''`,
		username)
	if err != nil {
		return fmt.Errorf("store: confirm totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: no pending TOTP enrollment for %q", username)
	}
	return nil
}

// DisableUserTOTP turns off per-user MFA and clears all TOTP state.
func (s *Store) DisableUserTOTP(username string) error {
	res, err := s.db.Exec(
		`UPDATE users SET totp_secret = '', totp_pending = '', totp_enabled = 0 WHERE username = ?`,
		username)
	if err != nil {
		return fmt.Errorf("store: disable totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var disabled, totpEnabled, mustChange int
	var created, apiKeyID, apiKeyHash, apiKeyCreated, apiKeyUsed, totpSecret, totpPending string
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &disabled, &created,
		&apiKeyID, &apiKeyHash, &apiKeyCreated, &apiKeyUsed,
		&totpSecret, &totpPending, &totpEnabled, &mustChange, &u.Email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.TOTPEnabled = totpEnabled != 0
	u.MustChange = mustChange != 0
	u.APIKeyID, u.APIKeyHash, u.TOTPSecret, u.TOTPPending = apiKeyID, apiKeyHash, totpSecret, totpPending
	if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
		u.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, apiKeyCreated); err == nil && apiKeyCreated != "" {
		u.APIKeyCreatedAt = &t
	}
	if t, err := time.Parse(time.RFC3339Nano, apiKeyUsed); err == nil && apiKeyUsed != "" {
		u.APIKeyLastUsed = &t
	}
	return &u, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
