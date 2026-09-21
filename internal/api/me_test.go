package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// totpGenerate generates one valid code for a base32 secret.
func totpGenerate(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// loginRaw posts a login request and returns the status code.
func loginRaw(t *testing.T, ts *httptest.Server, body map[string]string) int {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func cookieClient(t *testing.T, ts *httptest.Server, user, pass string) *http.Client {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": user, "password": pass})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d", user, resp.StatusCode)
	}
	return &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
}

func TestSelfServiceAPIKey(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "ops", "password": "operator-pw", "role": "operator",
	}); code != http.StatusOK {
		t.Fatalf("create operator = %d", code)
	}

	// operator mints a key for themselves
	ops := cookieClient(t, ts, "ops", "operator-pw")
	code, out := doJSONBody(t, ops, "POST", ts.URL+"/api/me/apikey", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("self mint = %d", code)
	}
	key, _ := out["api_key"].(string)
	if !strings.HasPrefix(key, "kma1_") {
		t.Fatalf("self key format: %q", key)
	}

	// /api/me reflects the identity and key
	code, me := doJSONBody(t, ops, "GET", ts.URL+"/api/me", nil)
	if code != http.StatusOK || me["username"] != "ops" || me["role"] != "operator" {
		t.Fatalf("GET /api/me = %d %v", code, me)
	}
	if me["api_key_id"] == nil || me["api_key_id"] == "" {
		t.Fatal("/api/me missing api_key_id")
	}

	// key works with the operator role
	bc := bearerClient(key)
	if code := doJSON(t, bc, "GET", ts.URL+"/api/config", nil); code != http.StatusOK {
		t.Fatalf("self key config = %d", code)
	}
	if code := doJSON(t, bc, "GET", ts.URL+"/api/users", nil); code != http.StatusForbidden {
		t.Fatalf("self key users = %d, want 403", code)
	}

	// self revocation kills the key
	if code := doJSON(t, ops, "DELETE", ts.URL+"/api/me/apikey", nil); code != http.StatusOK {
		t.Fatalf("self revoke = %d", code)
	}
	if code := doJSON(t, bc, "GET", ts.URL+"/api/config", nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked self key = %d, want 401", code)
	}
}

func TestSelfServiceMFA(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "selfop", "password": "self-pass-wd", "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create user = %d", code)
	}

	self := cookieClient(t, ts, "selfop", "self-pass-wd")
	code, out := doJSONBody(t, self, "POST", ts.URL+"/api/me/mfa/setup", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("self mfa setup = %d", code)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("empty secret")
	}

	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, self, "POST", ts.URL+"/api/me/mfa/confirm", map[string]string{"code": valid}); code != http.StatusOK {
		t.Fatalf("self confirm = %d", code)
	}

	// re-login requires the code now
	if code := postLogin(t, ts, "selfop", "self-pass-wd"); code != http.StatusUnauthorized {
		t.Fatalf("password-only login = %d, want 401", code)
	}

	// self-disable restores password login
	if code := doJSON(t, self, "DELETE", ts.URL+"/api/me/mfa", nil); code != http.StatusOK {
		t.Fatalf("self mfa disable = %d", code)
	}
	if code := postLogin(t, ts, "selfop", "self-pass-wd"); code != http.StatusOK {
		t.Fatalf("post-disable login = %d, want 200", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, _ := rbacServer(t)

	// a burst of wrong passwords trips the per-source limiter
	for i := 0; i < maxLoginFailures; i++ {
		if code := loginRaw(t, ts, map[string]string{"username": "admin", "password": "wrong-" + string(rune('a'+i))}); code != http.StatusUnauthorized {
			t.Fatalf("bad login #%d = %d, want 401", i+1, code)
		}
	}
	// locked: even the correct password is refused with 429
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked login = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 missing Retry-After")
	}
	// bad attempts while locked also stay 429
	if code := loginRaw(t, ts, map[string]string{"username": "admin", "password": "more-wrong"}); code != http.StatusTooManyRequests {
		t.Fatalf("locked bad login = %d, want 429", code)
	}
}

func TestChangeAuditLog(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "audx", "password": "audit-pass-1", "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create user = %d", code)
	}
	if code := doJSON(t, admin, "PATCH", ts.URL+"/api/users/audx", map[string]any{"role": "operator"}); code != http.StatusOK {
		t.Fatalf("update user = %d", code)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users/audx/apikey", map[string]string{}); code != http.StatusOK {
		t.Fatalf("mint key = %d", code)
	}

	// audit lists the operations newest-first with actor attribution
	req, _ := http.NewRequest("GET", ts.URL+"/api/audit/changes", nil)
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var logs []map[string]any
	decodeInto(t, resp, &logs)
	if len(logs) < 3 {
		t.Fatalf("audit entries = %d, want >= 3", len(logs))
	}
	actions := map[string]bool{}
	for _, e := range logs {
		if e["actor"] != "admin" {
			t.Fatalf("audit actor = %v, want admin", e["actor"])
		}
		actions[e["action"].(string)] = true
	}
	for _, want := range []string{"user.create", "user.update", "apikey.create"} {
		if !actions[want] {
			t.Fatalf("audit missing %q (got %v)", want, actions)
		}
	}
	// detail must not contain secrets
	for _, e := range logs {
		if strings.Contains(e["detail"].(string), "audit-pass-1") {
			t.Fatal("audit detail leaked a password")
		}
	}
	if !actions["user.update"] || !strings.Contains(logs[0]["detail"].(string)+logs[1]["detail"].(string)+logs[2]["detail"].(string), "role=operator") {
		// role change detail is recorded on the user.update entry (order-insensitive)
		found := false
		for _, e := range logs {
			if e["action"] == "user.update" && strings.Contains(e["detail"].(string), "role=operator") {
				found = true
			}
		}
		if !found {
			t.Fatal("user.update detail missing role change")
		}
	}

	// auditor can read the audit trail
	aud := cookieClient(t, ts, "audx", "audit-pass-1")
	if code := doJSON(t, aud, "GET", ts.URL+"/api/audit/changes", nil); code != http.StatusOK {
		t.Fatalf("auditor audit read = %d", code)
	}
}
