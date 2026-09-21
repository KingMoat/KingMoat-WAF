package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// rbacServer builds a console server with a store-seeded admin account and
// an authenticated client helper for the given username.
func rbacServer(t *testing.T) (*httptest.Server, func(user, pass string) *http.Client) {
	t.Helper()
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	center, err := configcenter.Open(t.TempDir()+"/rbac.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, Auth: NewAuth(hash)})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	login := func(user, pass string) *http.Client {
		body := mustJSON(t, map[string]string{"username": user, "password": pass})
		resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login %s = %d", user, resp.StatusCode)
		}
		return &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
	}
	return ts, login
}

type roundTripperWithCookie struct{ cookie *http.Cookie }

func (rt roundTripperWithCookie) RoundTrip(req *http.Request) (*http.Response, error) {
	req.AddCookie(rt.cookie)
	return http.DefaultTransport.RoundTrip(req)
}

func TestRBACUserLifecycle(t *testing.T) {
	ts, login := rbacServer(t)

	admin := login("admin", "hunter2")
	// legacy hash seeded an admin account
	if code := doJSON(t, admin, "GET", ts.URL+"/api/users", nil); code != http.StatusOK {
		t.Fatalf("user list = %d", code)
	}

	// admin creates operator + auditor
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "ops", "password": "operator-pw", "role": "operator",
	}); code != http.StatusOK {
		t.Fatalf("create operator = %d", code)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "aud", "password": "auditor-pw", "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create auditor = %d", code)
	}

	ops := login("ops", "operator-pw")
	aud := login("aud", "auditor-pw")

	// operator may publish; auditor may not
	cfg := `{"note":"rbac","config":{"listen_http":":8080","sites":[{"domains":["a.local"],"upstream":{"nodes":[{"address":"127.0.0.1:9000"}]}}]}}`
	if code := doRaw(t, ops, "POST", ts.URL+"/api/config/publish", cfg); code != http.StatusOK {
		t.Fatalf("operator publish = %d", code)
	}
	if code := doRaw(t, aud, "POST", ts.URL+"/api/config/publish", cfg); code != http.StatusForbidden {
		t.Fatalf("auditor publish = %d, want 403", code)
	}

	// auditor may read logs but not users
	if code := doJSON(t, aud, "GET", ts.URL+"/api/logs?limit=1", nil); code != http.StatusOK {
		t.Fatalf("auditor logs = %d", code)
	}
	if code := doJSON(t, aud, "GET", ts.URL+"/api/users", nil); code != http.StatusForbidden {
		t.Fatalf("auditor users = %d, want 403", code)
	}

	// operator may not manage users
	if code := doJSON(t, ops, "GET", ts.URL+"/api/users", nil); code != http.StatusForbidden {
		t.Fatalf("operator users = %d, want 403", code)
	}

	// last enabled admin is protected
	if code := doJSON(t, admin, "DELETE", ts.URL+"/api/users/admin", nil); code != http.StatusBadRequest {
		t.Fatalf("delete last admin = %d, want 400", code)
	}

	// auditor role can be revoked by admin
	if code := doJSON(t, admin, "PATCH", ts.URL+"/api/users/aud", map[string]any{"disabled": true}); code != http.StatusOK {
		t.Fatalf("disable auditor = %d", code)
	}
	// disabled account cannot log in
	if code := postLogin(t, ts, "aud", "auditor-pw"); code != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d, want 401", code)
	}
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any) int {
	t.Helper()
	return doRaw(t, client, method, url, string(mustJSON(t, body)))
}

func doRaw(t *testing.T, client *http.Client, method, url, body string) int {
	t.Helper()
	var rd *bytes.Reader
	if body == "" {
		rd = bytes.NewReader(nil)
	} else {
		rd = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func postLogin(t *testing.T, ts *httptest.Server, user, pass string) int {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": user, "password": pass})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

var _ = json.Valid
