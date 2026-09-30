package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func reloadTestCfg(upstreamAddr string, withRateLimit bool) *config.Config {
	site := config.Site{
		Domains:  []string{"example.com"},
		Mode:     "intercept",
		WAF:      &config.WAFSettings{Enabled: boolPtr(false)}, // no CRS for speed
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: upstreamAddr}}},
	}
	if withRateLimit {
		site.Security = &config.SecuritySettings{
			RateLimit: &config.RateLimitSettings{Requests: 1, WindowSec: 60, Action: "throttle"},
		}
	}
	return &config.Config{ListenHTTP: ":0", Sites: []config.Site{site}}
}

func TestReloadHotSwap(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	addr := strings.TrimPrefix(up.URL, "http://")

	h, err := NewReloadable(reloadTestCfg(addr, false), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-reload status = %d", rec.Code)
	}

	// Hot-swap to a rate-limited config: second request must be throttled.
	if err := h.Reload(reloadTestCfg(addr, true), 2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("post-reload first request = %d, want 200", rec2.Code)
	}
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("post-reload second request = %d, want 429 (hot reload not effective)", rec3.Code)
	}

	// Failed reload must keep the current state intact.
	bad := reloadTestCfg(addr, true)
	bad.Sites[0].Security.ACL = &config.ACLSettings{Blacklist: []string{"not-a-cidr"}}
	if err := h.Reload(bad, 3); err == nil {
		t.Fatal("invalid config must fail the reload")
	}
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("failed reload changed behavior: status = %d", rec4.Code)
	}
}

// TestReloadWithEmptyPrevState is the N-4 defensive regression: a handler
// whose state pointer was never stored (Swap returns nil on an empty
// atomic.Pointer) must reload cleanly — the prev-sites log line used to
// dereference the nil old state unconditionally and panicked.
func TestReloadWithEmptyPrevState(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	h := &Handler{logger: testLogger(), logSampler: newLogSampler(0)}
	if err := h.Reload(reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), false), 3); err != nil {
		t.Fatalf("Reload on a stateless handler: %v", err)
	}
	if got := h.RunningRevision(); got != 3 {
		t.Fatalf("revision after reload = %d, want 3", got)
	}
}

func BenchmarkProxyForward(b *testing.B) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	h, err := NewReloadable(reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), false), nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
}

// TestRunningRevisionTracking: the running revision follows successful
// reloads (Reload-carried and boot-stamped) and stays pinned to the live
// state when a reload fails (fail-static).
func TestRunningRevisionTracking(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	h, err := NewReloadable(reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), false), nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := h.RunningRevision(); got != 0 {
		t.Fatalf("boot revision = %d, want 0 (unknown until stamped)", got)
	}
	h.SetRunningRevision(1)
	if got := h.RunningRevision(); got != 1 {
		t.Fatalf("stamped revision = %d, want 1", got)
	}
	if err := h.Reload(reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), true), 7); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := h.RunningRevision(); got != 7 {
		t.Fatalf("revision after reload = %d, want 7", got)
	}
	// Failed reload: state (and its revision) stay untouched.
	bad := reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), true)
	bad.Sites[0].Security.ACL = &config.ACLSettings{Blacklist: []string{"not-a-cidr"}}
	if err := h.Reload(bad, 8); err == nil {
		t.Fatal("invalid config must fail the reload")
	}
	if got := h.RunningRevision(); got != 7 {
		t.Fatalf("revision after failed reload = %d, want 7 (fail-static)", got)
	}
}

func BenchmarkProxyWithCRS(b *testing.B) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	cfg := reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), false)
	cfg.Sites[0].WAF = &config.WAFSettings{Enabled: boolPtr(true)} // full CRS per request
	h, err := NewReloadable(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/products?id=1&page=2", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
}
