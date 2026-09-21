package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
)

const testHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
	"MDAwMDAwMDAwMDAwMDAwMA$" +
	"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"

func loginServer(t *testing.T, hash, totpSecret string) (*httptest.Server, *Auth) {
	t.Helper()
	center, err := configcenter.Open(t.TempDir()+"/login.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })

	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })

	auth := NewAuth(hash)
	if totpSecret != "" {
		auth.SetTOTP(totpSecret)
	}
	seedStoreAdmin(t, center, hash)
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, Auth: auth})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, auth
}

func seedStoreAdmin(t *testing.T, center *configcenter.Center, hash string) {
	t.Helper()
	if _, err := center.Store().CreateUser("admin", hash, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleLoginSession(t *testing.T) {
	// hash of "hunter2" generated with kingmoat-cli-compatible parameters
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	ts, _ := loginServer(t, hash, "")

	// unauthenticated → 401
	resp, _ := http.Get(ts.URL + "/api/status")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status before login = %d, want 401", resp.StatusCode)
	}

	// wrong password → 401
	if code := postJSON(t, ts, "/api/login", map[string]string{"password": "nope"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password login = %d", code)
	}

	// correct password → 200 + session cookie
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cookies []*http.Cookie
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", resp2.StatusCode)
	}
	cookies = resp2.Cookies()
	resp2.Body.Close()
	if len(cookies) == 0 {
		t.Fatal("session cookie missing")
	}

	// session cookie grants access
	req2, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req2.AddCookie(cookies[0])
	resp3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("status with session = %d", resp3.StatusCode)
	}

	// logout clears the session
	req3, _ := http.NewRequest("POST", ts.URL+"/api/logout", nil)
	req3.AddCookie(cookies[0])
	resp4, _ := http.DefaultClient.Do(req3)
	resp4.Body.Close()
	req4, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req4.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: cookies[0].Value})
	resp5, _ := http.DefaultClient.Do(req4)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cleared session still accepted = %d", resp5.StatusCode)
	}
}

func TestConsoleTOTPLogin(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // base32 test secret
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	ts, _ := loginServer(t, hash, secret)

	// password only → rejected (TOTP enabled)
	if code := postJSON(t, ts, "/api/login", map[string]string{"username": "admin", "password": "hunter2"}); code != http.StatusUnauthorized {
		t.Fatalf("password-only login with 2FA = %d, want 401", code)
	}

	// wrong code → rejected
	if code := postJSON(t, ts, "/api/login", map[string]string{"username": "admin", "password": "hunter2", "totp": "000000"}); code != http.StatusUnauthorized {
		t.Fatalf("bad TOTP accepted = %d", code)
	}

	// valid code → accepted
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code2 := postJSON(t, ts, "/api/login", map[string]string{"username": "admin", "password": "hunter2", "totp": code}); code2 != http.StatusOK {
		t.Fatalf("valid TOTP rejected = %d", code2)
	}
}

func TestCertificatesEndpoint(t *testing.T) {
	ts, _ := loginServer(t, "", "") // auth disabled
	center := New(Options{SkipBootstrap: true, Center: mustCenter(t)})
	_ = center
	// simple shape check: no TLS sites → empty list
	resp, err := http.Get(ts.URL + "/api/certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty inventory, got %d", len(list))
	}
}

func mustCenter(t *testing.T) *configcenter.Center {
	center, err := configcenter.Open(t.TempDir()+"/cert.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	return center
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any) int {
	t.Helper()
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
