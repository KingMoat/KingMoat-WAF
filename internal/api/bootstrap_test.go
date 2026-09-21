package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kingmoat/kingmoat/internal/logstore"
)

func mustAudit(t *testing.T) *logstore.SQLiteStore {
	t.Helper()
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	return audit
}

// TestBootstrapDefaultAccountForcedChange covers the fresh-install flow:
// kmadmin is seeded with the initial password, the console is armed without
// any anchor hash, and every API surface but the self-service password
// change stays blocked until the initial password is replaced.
func TestBootstrapDefaultAccountForcedChange(t *testing.T) {
	center := mustCenter(t)
	audit := mustAudit(t)
	srv := New(Options{Center: center, Logs: audit, Auth: NewAuth("")})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// login with the initial password → 200 + must_change
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": bootstrapUsername, "password": bootstrapPassword})))
	if err != nil {
		t.Fatal(err)
	}
	var lr struct {
		OK         bool `json:"ok"`
		MustChange bool `json:"must_change"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !lr.OK || !lr.MustChange {
		t.Fatalf("initial login = %d ok=%v must_change=%v, want 200/true/true", resp.StatusCode, lr.OK, lr.MustChange)
	}
	sess := resp.Cookies()
	if len(sess) == 0 {
		t.Fatal("session cookie missing")
	}

	// while the initial password is in effect, other APIs are rejected
	req, _ := http.NewRequest("GET", ts.URL+"/api/config", nil)
	req.AddCookie(sess[0])
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		t.Fatalf("api/config under initial password = %d, want 403", r2.StatusCode)
	}

	// the self-service change is allowed and clears the flag
	if code := postJSONWithCookie(t, ts, "/api/me/password",
		map[string]string{"old_password": bootstrapPassword, "new_password": "N3w-Passw0rd!"}, sess[0]); code != http.StatusOK {
		t.Fatalf("password change = %d, want 200", code)
	}

	// re-login: must_change cleared, console opens up
	resp3, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": bootstrapUsername, "password": "N3w-Passw0rd!"})))
	if err != nil {
		t.Fatal(err)
	}
	var lr3 struct {
		MustChange bool `json:"must_change"`
	}
	_ = json.NewDecoder(resp3.Body).Decode(&lr3)
	sess3 := resp3.Cookies()
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK || lr3.MustChange {
		t.Fatalf("re-login = %d must_change=%v, want 200/false", resp3.StatusCode, lr3.MustChange)
	}
	req4, _ := http.NewRequest("GET", ts.URL+"/api/config", nil)
	req4.AddCookie(sess3[0])
	r4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("api/config after change = %d, want 200", r4.StatusCode)
	}
}

// TestOpenAPIRequiresAuth pins the auth posture of /openapi.json: anonymous
// clients get 401; a console session (or node token) may read it.
func TestOpenAPIRequiresAuth(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	ts, _ := loginServer(t, hash, "")

	resp, _ := http.Get(ts.URL + "/openapi.json")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous openapi.json = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp2.Cookies()
	resp2.Body.Close()
	req3, _ := http.NewRequest("GET", ts.URL+"/openapi.json", nil)
	req3.AddCookie(cookies[0])
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("openapi.json with session = %d, want 200", resp3.StatusCode)
	}
}

func postJSONWithCookie(t *testing.T, ts *httptest.Server, path string, body any, c *http.Cookie) int {
	t.Helper()
	req, err := http.NewRequest("POST", ts.URL+path, bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
