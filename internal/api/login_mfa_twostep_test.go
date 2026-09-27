package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// enableUserMFA enrolls and confirms per-user TOTP for username through the
// admin API, returning the base32 secret.
func enableUserMFA(t *testing.T, ts *httptest.Server, admin *http.Client, username string) string {
	t.Helper()
	code, out := doJSONBody(t, admin, "POST", ts.URL+"/api/users/"+username+"/mfa/setup", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("mfa setup %s = %d", username, code)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("mfa setup: empty secret")
	}
	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users/"+username+"/mfa/confirm", map[string]string{"code": valid}); code != http.StatusOK {
		t.Fatalf("mfa confirm %s = %d", username, code)
	}
	return secret
}

// mfaLoginServer builds a console server with a store-seeded admin plus a
// per-user MFA account (mfauser / mfa-user-pw). Returns the server, an
// authenticated admin client and the MFA secret.
func mfaLoginServer(t *testing.T) (*httptest.Server, *http.Client, string) {
	t.Helper()
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "mfauser", "password": "mfa-user-pw", "role": "operator",
	}); code != http.StatusOK {
		t.Fatalf("create mfauser = %d", code)
	}
	secret := enableUserMFA(t, ts, admin, "mfauser")
	return ts, admin, secret
}

// postLoginBody posts a JSON login and returns the status code plus the
// parsed response body.
func postLoginBody(t *testing.T, ts *httptest.Server, body map[string]string) (int, map[string]any) {
	t.Helper()
	return doJSONBody(t, &http.Client{}, "POST", ts.URL+"/api/login", body)
}

// B1: a wrong password for an MFA-enabled account must answer the generic
// denial — never totp_required, which would leak that the account has MFA.
func TestLoginMFA_B1_WrongPasswordNeverHintsTOTP(t *testing.T) {
	ts, _, _ := mfaLoginServer(t)

	code, body := postLoginBody(t, ts, map[string]string{"username": "mfauser", "password": "totally-wrong"})
	if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
		t.Fatalf("wrong password on MFA account = %d %v, want 401 invalid credentials", code, body)
	}
}

// B2: correct password without a TOTP code asks for the dynamic code.
func TestLoginMFA_B2_PasswordOnlyReturnsTOTPRequired(t *testing.T) {
	ts, _, _ := mfaLoginServer(t)

	code, body := postLoginBody(t, ts, map[string]string{"username": "mfauser", "password": "mfa-user-pw"})
	if code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("password-only login with MFA = %d %v, want 401 totp_required", code, body)
	}
}

// B3: correct password with a wrong TOTP code still asks for the dynamic code.
func TestLoginMFA_B3_WrongCodeReturnsTOTPRequired(t *testing.T) {
	ts, _, _ := mfaLoginServer(t)

	code, body := postLoginBody(t, ts, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": "000000"})
	if code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("wrong TOTP login = %d %v, want 401 totp_required", code, body)
	}
}

// B4: correct password with a valid TOTP code issues a working session.
func TestLoginMFA_B4_ValidCodeIssuesSession(t *testing.T) {
	ts, _, secret := mfaLoginServer(t)
	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/login",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": valid})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	var body struct {
		OK       bool   `json:"ok"`
		Role     string `json:"role"`
		Username string `json:"username"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !body.OK || body.Username != "mfauser" || len(cookies) == 0 {
		t.Fatalf("valid-code login = %d ok=%v username=%q cookies=%d, want 200 ok=true with session cookie",
			resp.StatusCode, body.OK, body.Username, len(cookies))
	}

	req2, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	req2.AddCookie(cookies[0])
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("/api/me with session = %d, want 200", resp2.StatusCode)
	}
}

// B5: a disabled MFA-enabled account answers invalid credentials, never
// totp_required — the disabled check must precede the TOTP decision.
func TestLoginMFA_B5_DisabledAccountStaysInvalidCredentials(t *testing.T) {
	ts, admin, _ := mfaLoginServer(t)

	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "disuser", "password": "dis-user-pw", "role": "operator",
	}); code != http.StatusOK {
		t.Fatalf("create disuser = %d", code)
	}
	enableUserMFA(t, ts, admin, "disuser")
	if code := doJSON(t, admin, "PATCH", ts.URL+"/api/users/disuser", map[string]any{"disabled": true}); code != http.StatusOK {
		t.Fatalf("disable disuser = %d", code)
	}

	code, body := postLoginBody(t, ts, map[string]string{"username": "disuser", "password": "dis-user-pw"})
	if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
		t.Fatalf("disabled MFA account login = %d %v, want 401 invalid credentials", code, body)
	}
}

// B6: unknown usernames keep the existing invalid-credentials semantics.
func TestLoginMFA_B6_UnknownUserStaysInvalidCredentials(t *testing.T) {
	ts, _, _ := mfaLoginServer(t)

	code, body := postLoginBody(t, ts, map[string]string{"username": "no-such-user", "password": "whatever"})
	if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
		t.Fatalf("unknown user login = %d %v, want 401 invalid credentials", code, body)
	}
}

// B7: with the global env TOTP secret the same three states hold.
func TestLoginMFA_B7_GlobalTOTPThreeStates(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	ts, _ := loginServer(t, hash, secret)

	code, body := postLoginBody(t, ts, map[string]string{"username": "admin", "password": "hunter2"})
	if code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("global TOTP password-only login = %d %v, want 401 totp_required", code, body)
	}

	code, body = postLoginBody(t, ts, map[string]string{"username": "admin", "password": "hunter2", "totp": "000000"})
	if code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("global TOTP wrong-code login = %d %v, want 401 totp_required", code, body)
	}

	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	code, body = postLoginBody(t, ts, map[string]string{"username": "admin", "password": "hunter2", "totp": valid})
	if code != http.StatusOK || body["ok"] != true {
		t.Fatalf("global TOTP valid-code login = %d %v, want 200 ok=true", code, body)
	}
}

// B8: TOTP wrong-code failures fill the shared brute-force window and a
// successful login clears the counter.
func TestLoginMFA_B8_TOTPFailuresFillLockoutAndSuccessResets(t *testing.T) {
	ts, _, secret := mfaLoginServer(t)

	for i := 1; i <= 4; i++ {
		code, body := postLoginBody(t, ts, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": "000000"})
		if code != http.StatusUnauthorized || body["error"] != "totp_required" {
			t.Fatalf("wrong-code failure %d = %d %v, want 401 totp_required", i, code, body)
		}
	}
	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code := postJSON(t, ts, "/api/login", map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": valid}); code != http.StatusOK {
		t.Fatalf("successful login after failures = %d, want 200", code)
	}
	// the counter was reset, so ten fresh failures stay below the lockout
	for i := 1; i <= 10; i++ {
		code, body := postLoginBody(t, ts, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": "000000"})
		if code != http.StatusUnauthorized || body["error"] != "totp_required" {
			t.Fatalf("post-reset wrong-code failure %d = %d %v, want 401 totp_required", i, code, body)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": "000000"})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th consecutive failure = %d, want 429", resp.StatusCode)
	}
	ra := resp.Header.Get("Retry-After")
	if n, err := strconv.Atoi(ra); err != nil || n <= 0 {
		t.Fatalf("429 Retry-After = %q, want positive seconds", ra)
	}
}

// B9: Basic auth against an MFA account is denied even with the correct
// password, and the failure counts into the same brute-force counter.
func TestLoginMFA_B9_BasicAuthMFAFailureCountsIntoLockout(t *testing.T) {
	ts, _, secret := mfaLoginServer(t)

	for i := 1; i <= 10; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
		req.SetBasicAuth("mfauser", "mfa-user-pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("basic auth without TOTP attempt %d = %d, want 401", i, resp.StatusCode)
		}
	}

	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": valid})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("JSON login with valid code after 10 basic failures = %d, want 429 (shared counter)", resp.StatusCode)
	}
}

// B10: the empty username still normalizes to kmadmin in MFA scenarios.
func TestLoginMFA_B10_EmptyUsernameNormalizesWithMFA(t *testing.T) {
	ts, _ := emptyUserServer(t, 0)

	// clear the forced first-password change through the empty-username
	// Basic identity (existing empty-user flow)
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
		t.Fatalf("initial password change = %d, want 200", resp.StatusCode)
	}

	login := func(password, totpCode string) (int, map[string]any, []*http.Cookie) {
		payload := map[string]string{"username": "", "password": password}
		if totpCode != "" {
			payload["totp"] = totpCode
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(mustJSON(t, payload)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		cookies := resp.Cookies()
		resp.Body.Close()
		return resp.StatusCode, body, cookies
	}

	code, body, cookies := login("N3w-Passw0rd!", "")
	if code != http.StatusOK || body["ok"] != true || len(cookies) == 0 {
		t.Fatalf("empty-username login before MFA = %d %v, want 200 ok=true with cookie", code, body)
	}

	self := &http.Client{Transport: roundTripperWithCookie{cookie: cookies[0]}}
	code, out := doJSONBody(t, self, "POST", ts.URL+"/api/me/mfa/setup", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("self mfa setup = %d", code)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("self mfa setup: empty secret")
	}
	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, self, "POST", ts.URL+"/api/me/mfa/confirm", map[string]string{"code": valid}); code != http.StatusOK {
		t.Fatalf("self mfa confirm = %d", code)
	}

	code, body, _ = login("N3w-Passw0rd!", "")
	if code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("empty-username login after MFA = %d %v, want 401 totp_required", code, body)
	}
	code, body, _ = login("wrong-password", "")
	if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
		t.Fatalf("empty-username wrong-password login = %d %v, want 401 invalid credentials", code, body)
	}
	valid2, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	code, body, cookies = login("N3w-Passw0rd!", valid2)
	if code != http.StatusOK || body["ok"] != true || len(cookies) == 0 {
		t.Fatalf("empty-username login with valid code = %d %v, want 200 ok=true with cookie", code, body)
	}
}
