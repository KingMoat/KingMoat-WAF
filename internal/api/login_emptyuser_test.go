package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// emptyUserServer boots a fresh-install console (bootstrap kmadmin with the
// initial password, forced change pending) with an optional password max-age
// policy. Returns the server and the console SQLite path for direct checks.
func emptyUserServer(t *testing.T, maxAgeDays int) (*httptest.Server, string) {
	t.Helper()
	cfg := seedCfg()
	if maxAgeDays > 0 {
		cfg.Security = &config.ConsoleSecuritySettings{PasswordMaxAgeDays: maxAgeDays}
	}
	dbPath := filepath.Join(t.TempDir(), "emptyuser.db")
	center, err := configcenter.Open(dbPath, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = center.Close() })
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	srv := New(Options{Center: center, Logs: audit, Auth: NewAuth("")})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, dbPath
}

// TestBasicAuthEmptyUsernameMapsToBootstrap pins the identity fix: an empty
// Basic username with the correct password resolves to the bootstrap account
// (kmadmin), so the forced-change gate applies — previously it produced an
// untracked empty-name admin session that skipped the gate entirely.
func TestBasicAuthEmptyUsernameMapsToBootstrap(t *testing.T) {
	ts, _ := emptyUserServer(t, 0)

	// writes stay blocked by the forced-change gate
	req, _ := http.NewRequest("GET", ts.URL+"/api/config", nil)
	req.SetBasicAuth("", bootstrapPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || got.Error != "password_change_required" {
		t.Fatalf("empty-user basic /api/config = %d %q, want 403 password_change_required", resp.StatusCode, got.Error)
	}

	// self-service reads stay reachable and identify kmadmin
	req2, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	req2.SetBasicAuth("", bootstrapPassword)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	var me struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&me)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || me.Username != bootstrapUsername {
		t.Fatalf("empty-user basic /api/me = %d username=%q, want 200 %q", resp2.StatusCode, me.Username, bootstrapUsername)
	}
}

// TestLoginEmptyUsernameEnforcesPasswordMaxAge pins the policy-path fix: the
// password max-age gate runs against the NORMALIZED username, so an
// empty-username JSON login is rejected for an expired password exactly like
// the named one (previously the check looked up "" and never matched).
func TestLoginEmptyUsernameEnforcesPasswordMaxAge(t *testing.T) {
	ts, dbPath := emptyUserServer(t, 30)

	var lr struct {
		OK         bool   `json:"ok"`
		Username   string `json:"username"`
		MustChange bool   `json:"must_change"`
	}
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "", "password": bootstrapPassword})))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&lr)
	cookies := resp.Cookies()
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !lr.OK || lr.Username != bootstrapUsername || !lr.MustChange {
		t.Fatalf("empty-user login = %d ok=%v username=%q must_change=%v, want 200/true/%q/true",
			resp.StatusCode, lr.OK, lr.Username, lr.MustChange, bootstrapUsername)
	}
	if len(cookies) == 0 {
		t.Fatal("session cookie missing")
	}

	// clear the forced change (stamps password_changed_at = now)
	if code := postJSONWithCookie(t, ts, "/api/me/password",
		map[string]string{"old_password": bootstrapPassword, "new_password": "N3w-Passw0rd!"}, cookies[0]); code != http.StatusOK {
		t.Fatalf("password change = %d, want 200", code)
	}

	// age the password beyond the configured max age (30 days)
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stale := time.Now().AddDate(0, 0, -90).UTC().Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE users SET password_changed_at = ? WHERE username = ?`, stale, bootstrapUsername); err != nil {
		t.Fatal(err)
	}

	for _, user := range []string{"", bootstrapUsername} {
		resp, err := http.Post(ts.URL+"/api/login", "application/json",
			bytes.NewReader(mustJSON(t, map[string]string{"username": user, "password": "N3w-Passw0rd!"})))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expired-password login (username=%q) = %d, want 403", user, resp.StatusCode)
		}
	}
}

// TestBasicAuthEmptyUsernameAuditActor pins the attribution fix: management
// audit entries written through the empty-username Basic identity carry the
// bootstrap account name instead of an empty author.
func TestBasicAuthEmptyUsernameAuditActor(t *testing.T) {
	ts, _ := emptyUserServer(t, 0)

	// clear the forced change through the empty-username Basic identity
	req, _ := http.NewRequest("POST", ts.URL+"/api/me/password",
		bytes.NewReader(mustJSON(t, map[string]string{"old_password": bootstrapPassword, "new_password": "N3w-Passw0rd!"})))
	req.SetBasicAuth("", bootstrapPassword)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change = %d, want 200", resp.StatusCode)
	}

	// a self-service write is attributed to the bootstrap account, not ""
	req2, _ := http.NewRequest("POST", ts.URL+"/api/me/apikey", bytes.NewReader(mustJSON(t, map[string]string{})))
	req2.SetBasicAuth("", "N3w-Passw0rd!")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("self apikey mint = %d, want 200", resp2.StatusCode)
	}

	req3, _ := http.NewRequest("GET", ts.URL+"/api/audit/changes", nil)
	req3.SetBasicAuth("", "N3w-Passw0rd!")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	var logs []struct {
		Actor string `json:"actor"`
	}
	_ = json.NewDecoder(resp3.Body).Decode(&logs)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK || len(logs) == 0 {
		t.Fatalf("audit list = %d entries=%d, want 200 with entries", resp3.StatusCode, len(logs))
	}
	for _, l := range logs {
		if l.Actor != bootstrapUsername {
			t.Fatalf("audit actor = %q, want %q", l.Actor, bootstrapUsername)
		}
	}
}
