package proxy

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// v3up starts a tiny upstream returning a fixed body.
func v3up(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, body)
	}))
}

func mustReloadable(t *testing.T, cfg *config.Config) *Handler {
	t.Helper()
	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	return h
}

func do(t *testing.T, h *Handler, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, url, nil))
	return rec
}

func TestV3SiteAuthEnforced(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{
				Auth: &config.AuthSettings{Users: []config.AuthUser{{Username: "ops", Password: "pw123"}}},
			},
		}},
	}
	h := mustReloadable(t, cfg)

	if rec := do(t, h, "GET", "http://t.local/"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: status = %d, want 401", rec.Code)
	}
	// wrong password
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://t.local/", nil)
	req.SetBasicAuth("ops", "wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: status = %d", rec.Code)
	}
	// correct password → forwarded
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "http://t.local/", nil)
	req2.SetBasicAuth("ops", "pw123")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("valid credentials: status = %d", rec2.Code)
	}
}

func TestV3CaptchaFlow(t *testing.T) {
	up := v3up(t, "secret-area")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{
				Captcha: &config.CaptchaSettings{Enabled: true, Secret: "v3-secret", Tolerance: 8},
			},
		}},
	}
	h := mustReloadable(t, cfg)

	// 1. challenge page
	rec := do(t, h, "GET", "http://t.local/private?id=1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "km-captcha/verify") {
		t.Fatalf("expected slider challenge, got %d", rec.Code)
	}

	// 2. verify at the correct gap → pass cookie
	html := rec.Body.String()
	ti := strings.Index(html, "token=")
	rest := html[ti+len("token="):]
	token := rest[:strings.IndexAny(rest, "&\"'")]
	gapBytes, err := hex.DecodeString(strings.Split(token, ".")[0])
	if err != nil || len(gapBytes) == 0 {
		t.Fatalf("bad token %q", token)
	}
	// the gap is a big-endian number (60..259, may span two bytes)
	var gap int64
	for _, b := range gapBytes {
		gap = gap<<8 | int64(b)
	}
	gapX := int(gap)

	recV := do(t, h, "GET", "http://t.local"+CaptchaVerifyPath()+"?token="+token+"&x="+itoa(gapX))
	if recV.Code != http.StatusOK {
		t.Fatalf("verify failed: %d %s", recV.Code, recV.Body.String())
	}
	var passCookie *http.Cookie
	for _, c := range recV.Result().Cookies() {
		if strings.HasPrefix(c.Name, "km_captcha") {
			passCookie = c
		}
	}
	if passCookie == nil {
		t.Fatal("pass cookie missing")
	}

	// 3. pass cookie holder reaches the origin
	rec3 := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://t.local/private?id=1", nil)
	req.AddCookie(passCookie)
	h.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "secret-area" {
		t.Fatalf("pass cookie not honored: %d %q", rec3.Code, rec3.Body.String())
	}
}

// CaptchaVerifyPath is re-declared here to avoid importing stages twice in
// different spellings.
func CaptchaVerifyPath() string { return "/.well-known/km-captcha/verify" }

func itoa(n int) string {
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestV3DynamicProtectionTransformsHTML(t *testing.T) {
	orig := "<html><body>" + strings.Repeat("payload ", 80) + "</body></html>"
	up := v3up(t, orig)
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{Dynamic: &config.DynamicSettings{Enabled: true}},
		}},
	}
	h := mustReloadable(t, cfg)

	// Plain-HTTP inbound (secure context off) → response forwarded untouched;
	// the encryption path itself is covered by the dynamics unit tests.
	rec := do(t, h, "GET", "http://t.local/")
	if rec.Body.String() != orig {
		t.Fatalf("plain http must not be transformed; got %.80s", rec.Body.String())
	}
}

func TestV3GroupACLSubscription(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	listSrc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "# subscribed blocklist\n10.0.0.0/8\n\n192.168.0.0/16\n")
	}))
	defer listSrc.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		IPGroups: []config.IPGroupSettings{
			{Name: "blocked-nets", URL: listSrc.URL},
		},
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{
				ACL: &config.ACLSettings{Blacklist: []string{"group:blocked-nets"}},
			},
		}},
	}
	h := mustReloadable(t, cfg)

	if rec := do(t, h, "GET", "http://t.local/"); rec.Code == http.StatusForbidden {
		// caller IP is 127.0.0.1 — not in the group; must forward
		t.Fatal("loopback should not be blocked")
	}

	// Rewrite the subscription to include the request source, then verify the
	// refreshed group takes effect via a fresh reload (hot path).
	cfg.IPGroups[0].URL = listSrc.URL // same
	list2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "192.0.2.0/24\n") // httptest.NewRequest default source
	}))
	defer list2.Close()
	cfg2 := *cfg
	cfg2.IPGroups = []config.IPGroupSettings{{Name: "blocked-nets", URL: list2.URL}}
	if err := h.Reload(&cfg2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if rec := do(t, h, "GET", "http://t.local/"); rec.Code != http.StatusForbidden {
		t.Fatalf("subscribed group entry not enforced: %d", rec.Code)
	}
}

func TestV3HealthCheckDrainsUnhealthyNode(t *testing.T) {
	up := v3up(t, "primary")
	defer up.Close()
	// dead node: closed listener port
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains: []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{
				{Address: trimScheme(up.URL), Weight: 1},
				{Address: trimScheme(deadURL), Weight: 1},
			}},
			Health: &config.HealthSettings{
				Enabled: true, IntervalSec: 1, TimeoutSec: 1,
				Passive: true, FailThreshold: 2, CooldownSec: 5,
			},
		}},
	}
	h := mustReloadable(t, cfg)

	// Wait for the first active probe cycle to mark the dead node down.
	time.Sleep(1600 * time.Millisecond)
	for i := 0; i < 6; i++ {
		if rec := do(t, h, "GET", "http://t.local/"); rec.Code != http.StatusOK {
			t.Fatalf("request %d failed with an unhealthy node present: %d", i, rec.Code)
		}
	}
}

func TestV3SemanticStageInPipeline(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      wafOff(),
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}
	h := mustReloadable(t, cfg)
	if rec := do(t, h, "GET", `http://t.local/?id=1%27%20or%20%271%27=%271`); rec.Code != http.StatusForbidden {
		t.Fatalf("semantic layer did not block SQLi: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "http://t.local/?id=42&page=3"); rec.Code != http.StatusOK {
		t.Fatalf("benign request blocked: %d", rec.Code)
	}
}

func wafOff() *config.WAFSettings {
	off := false
	return &config.WAFSettings{Enabled: &off}
}

func TestV3RequestCaptureInLogs(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	store, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{
		ListenHTTP:      ":0",
		CaptureRequests: true,
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}
	h := mustReloadable(t, cfg)
	_ = h // handler rebuilt below with the audit store

	h2, err := NewReloadable(cfg, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", `http://t.local/p?id=1%27%20or%20%271%27=%271`, nil)
	req.Header.Set("Authorization", "Bearer sk-supersecret")
	req.Header.Set("X-Custom-Trace", "visible-value")
	h2.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected semantic block, got %d", rec.Code)
	}

	if err := store.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	devs := store.Recent(10)
	if len(devs) == 0 {
		t.Fatal("no audit event captured")
	}
	ev := devs[0]
	if ev.Headers == nil {
		t.Fatal("capture_requests did not store headers")
	}
	if ev.Headers["Authorization"] != "***" {
		t.Fatalf("authorization header not redacted: %q", ev.Headers["Authorization"])
	}
	if ev.Headers["X-Custom-Trace"] != "visible-value" {
		t.Fatalf("custom header lost: %q", ev.Headers["X-Custom-Trace"])
	}
}
