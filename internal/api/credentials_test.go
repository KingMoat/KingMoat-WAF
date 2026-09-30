package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// decodeInto reads a JSON response body into v.
func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func doJSONBody(t *testing.T, client *http.Client, method, url string, body any) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	return resp.StatusCode, out
}

func bearerClient(token string) *http.Client {
	return &http.Client{Transport: bearerTransport{token: token}}
}

type bearerTransport struct{ token string }

func (bt bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+bt.token)
	return http.DefaultTransport.RoundTrip(req)
}

func TestAPIKeyLifecycle(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	// create an operator account
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "ops", "password": "operator-pw", "role": "operator",
	}); code != http.StatusOK {
		t.Fatalf("create operator = %d", code)
	}

	// non-admin cannot mint keys
	ops := login("ops", "operator-pw")
	if code := doJSON(t, ops, "POST", ts.URL+"/api/users/ops/apikey", map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("operator mint key = %d, want 403", code)
	}

	// admin mints a key for the operator
	code, out := doJSONBody(t, admin, "POST", ts.URL+"/api/users/ops/apikey", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("mint key = %d", code)
	}
	key, _ := out["api_key"].(string)
	if !strings.HasPrefix(key, "kma1_") {
		t.Fatalf("api key format: %q", key)
	}

	// key authenticates with the owner's role: config readable, users not
	bc := bearerClient(key)
	if code := doJSON(t, bc, "GET", ts.URL+"/api/config", nil); code != http.StatusOK {
		t.Fatalf("bearer config = %d", code)
	}
	if code := doJSON(t, bc, "GET", ts.URL+"/api/users", nil); code != http.StatusForbidden {
		t.Fatalf("bearer users = %d, want 403", code)
	}

	// a tampered secret is rejected
	tampered := key[:len(key)-2] + "xx"
	if code := doJSON(t, bearerClient(tampered), "GET", ts.URL+"/api/config", nil); code != http.StatusUnauthorized {
		t.Fatalf("tampered bearer = %d, want 401", code)
	}

	// user list shows the key id
	reqList, _ := http.NewRequest("GET", ts.URL+"/api/users", nil)
	listResp, err := admin.Do(reqList)
	if err != nil {
		t.Fatal(err)
	}
	var users []map[string]any
	decodeInto(t, listResp, &users)
	found := false
	for _, u := range users {
		if u["username"] == "ops" && u["api_key_id"] != nil && u["api_key_id"] != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("api_key_id missing from user list")
	}

	// revocation kills the key immediately
	if code := doJSON(t, admin, "DELETE", ts.URL+"/api/users/ops/apikey", nil); code != http.StatusOK {
		t.Fatalf("revoke key = %d", code)
	}
	if code := doJSON(t, bc, "GET", ts.URL+"/api/config", nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer = %d, want 401", code)
	}
}

func TestPerUserMFAFlow(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "mfauser", "password": "mfa-user-pw", "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create user = %d", code)
	}

	// password-only login works before MFA is confirmed
	if code := postLogin(t, ts, "mfauser", "mfa-user-pw"); code != http.StatusOK {
		t.Fatalf("pre-MFA login = %d, want 200", code)
	}

	// setup returns a secret + QR
	code, out := doJSONBody(t, admin, "POST", ts.URL+"/api/users/mfauser/mfa/setup", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("mfa setup = %d", code)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("mfa setup: empty secret")
	}
	if qr, _ := out["qr_png"].(string); !strings.HasPrefix(qr, "iVBOR") {
		t.Fatal("mfa setup: missing QR PNG")
	}
	// confirming without a pending enrollment fails
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users/admin/mfa/confirm", map[string]string{"code": "000000"}); code != http.StatusBadRequest {
		t.Fatalf("confirm without pending = %d, want 400", code)
	}

	// wrong code does not activate
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users/mfauser/mfa/confirm", map[string]string{"code": "000000"}); code != http.StatusBadRequest {
		t.Fatalf("confirm bad code = %d, want 400", code)
	}

	// valid code activates per-user MFA
	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users/mfauser/mfa/confirm", map[string]string{"code": valid}); code != http.StatusOK {
		t.Fatalf("confirm = %d", code)
	}

	// login now requires the TOTP code
	if code := postLogin(t, ts, "mfauser", "mfa-user-pw"); code != http.StatusUnauthorized {
		t.Fatalf("password-only login with MFA = %d, want 401", code)
	}
	loginBody := map[string]string{"username": "mfauser", "password": "mfa-user-pw", "totp": valid}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(mustJSON(t, loginBody)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with TOTP = %d, want 200", resp.StatusCode)
	}

	// disabling MFA restores password-only login
	if code := doJSON(t, admin, "DELETE", ts.URL+"/api/users/mfauser/mfa", nil); code != http.StatusOK {
		t.Fatalf("disable mfa = %d", code)
	}
	if code := postLogin(t, ts, "mfauser", "mfa-user-pw"); code != http.StatusOK {
		t.Fatalf("post-disable login = %d, want 200", code)
	}
}

func TestHostStatsBehindAuth(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	center := mustCenter(t)
	seedStoreAdmin(t, center, hash)
	srv := New(Options{SkipBootstrap: true, Center: center, Auth: NewAuth(hash)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if code := doJSON(t, &http.Client{}, "GET", ts.URL+"/api/host/stats", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauth /api/host/stats = %d, want 401", code)
	}

	// login to get a cookie on THIS server
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})))
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	if len(cookies) == 0 {
		t.Fatal("login cookie missing")
	}
	client := &http.Client{Transport: roundTripperWithCookie{cookie: cookies[0]}}
	code, body := doJSONBody(t, client, "GET", ts.URL+"/api/host/stats", nil)
	if code != http.StatusOK {
		t.Fatalf("authed /api/host/stats = %d, want 200", code)
	}
	if _, ok := body["cpu_used_pct"]; !ok {
		t.Fatalf("host stats payload missing cpu_used_pct: %v", body)
	}
	if _, ok := body["mem_used_pct"]; !ok {
		t.Fatalf("host stats payload missing mem_used_pct: %v", body)
	}
}

func TestSessionCookieSecureFlag(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	center := mustCenter(t)
	seedStoreAdmin(t, center, hash)
	srv := New(Options{SkipBootstrap: true, Center: center, Auth: NewAuth(hash)})
	body := mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})

	// over TLS the cookie carries Secure
	tlsSrv := httptest.NewTLSServer(srv.Handler())
	defer tlsSrv.Close()
	resp, err := tlsSrv.Client().Post(tlsSrv.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 || !cookies[0].Secure {
		t.Fatalf("TLS login cookie Secure = false (cookies=%v)", cookies)
	}

	// plain HTTP stays usable (no Secure attribute)
	plain := httptest.NewServer(srv.Handler())
	defer plain.Close()
	resp2, err := http.Post(plain.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	cookies2 := resp2.Cookies()
	if len(cookies2) == 0 || cookies2[0].Secure {
		t.Fatalf("plain login cookie unexpectedly Secure (cookies=%v)", cookies2)
	}
}

// TestMeUsersTOTPEnabledConsistency pins review N-1: the TOTP state must
// come from one source of truth across /api/me, /api/users and the mutation
// responses. The reported reproduction sequence (disable MFA, then compare
// both read endpoints) stays in lockstep at every step, and each mutation
// response carries the value actually persisted in the store.
func TestMeUsersTOTPEnabledConsistency(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "consist", "password": "consist-pw", "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create user = %d", code)
	}
	secret := enableUserMFA(t, ts, admin, "consist")

	// self login now requires the dynamic code (per-user MFA is active)
	valid, err := totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/login",
		bytes.NewReader(mustJSON(t, map[string]string{"username": "consist", "password": "consist-pw", "totp": valid})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(cookies) == 0 {
		t.Fatalf("self login with TOTP = %d cookies=%d, want 200 with cookie", resp.StatusCode, len(cookies))
	}
	self := &http.Client{Transport: roundTripperWithCookie{cookie: cookies[0]}}

	usersState := func() bool {
		listResp, err := admin.Get(ts.URL + "/api/users")
		if err != nil {
			t.Fatal(err)
		}
		var users []map[string]any
		decodeInto(t, listResp, &users)
		for _, u := range users {
			if u["username"] == "consist" {
				enabled, _ := u["totp_enabled"].(bool)
				return enabled
			}
		}
		t.Fatal("consist missing from /api/users")
		return false
	}
	meState := func() bool {
		code, body := doJSONBody(t, self, "GET", ts.URL+"/api/me", nil)
		if code != http.StatusOK {
			t.Fatalf("/api/me = %d", code)
		}
		enabled, _ := body["totp_enabled"].(bool)
		return enabled
	}

	// MFA active: both read endpoints report true, in lockstep
	if meState() != true || usersState() != true {
		t.Fatalf("MFA on: me=%v users=%v, want both true", meState(), usersState())
	}

	// self disables MFA; the mutation response reports the stored state
	code, body := doJSONBody(t, self, "DELETE", ts.URL+"/api/me/mfa", nil)
	if code != http.StatusOK {
		t.Fatalf("self mfa disable = %d", code)
	}
	if body["totp_enabled"] != false {
		t.Fatalf("self disable response totp_enabled = %v, want false", body["totp_enabled"])
	}

	// reproduction sequence: after the disable, /api/me and /api/users
	// must agree (both false)
	if meState() {
		t.Fatal("/api/me totp_enabled = true after disable, want false")
	}
	if usersState() {
		t.Fatal("/api/users totp_enabled = true after disable, want false")
	}

	// admin re-enrolls and disables again through the user-management
	// surface: both mutation responses carry the real stored values
	code, out := doJSONBody(t, admin, "POST", ts.URL+"/api/users/consist/mfa/setup", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("admin mfa setup = %d", code)
	}
	secret, _ = out["secret"].(string)
	valid, err = totpGenerate(secret)
	if err != nil {
		t.Fatal(err)
	}
	code, body = doJSONBody(t, admin, "POST", ts.URL+"/api/users/consist/mfa/confirm", map[string]string{"code": valid})
	if code != http.StatusOK {
		t.Fatalf("admin mfa confirm = %d", code)
	}
	if body["totp_enabled"] != true {
		t.Fatalf("confirm response totp_enabled = %v, want true", body["totp_enabled"])
	}
	code, body = doJSONBody(t, admin, "DELETE", ts.URL+"/api/users/consist/mfa", nil)
	if code != http.StatusOK {
		t.Fatalf("admin mfa disable = %d", code)
	}
	if body["totp_enabled"] != false {
		t.Fatalf("admin disable response totp_enabled = %v, want false", body["totp_enabled"])
	}
	if meState() || usersState() {
		t.Fatalf("after admin disable: me=%v users=%v, want both false", meState(), usersState())
	}
}
