package stages

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func secCfg(security *config.SecuritySettings) *config.Config {
	return &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9"}}},
			Security: security,
		}},
	}
}

func run(t *testing.T, st pipeline.Stage, remote, target string, cookies map[string]string) (*pipeline.RequestContext, pipeline.Verdict) {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	if remote != "" {
		r.RemoteAddr = remote
	}
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: "t.local"},
		Values:  map[string]any{"trace_id": "test"},
	}
	return rc, st.Inspect(context.Background(), rc)
}

func TestACLDenyBlacklisted(t *testing.T) {
	acl, err := NewACL(secCfg(&config.SecuritySettings{
		ACL: &config.ACLSettings{Blacklist: []string{"10.0.0.0/8"}},
	}), nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	_, v := run(t, acl, "10.1.2.3:5555", "http://t.local/", nil)
	if v.Action != pipeline.ActionDeny || v.Rule != "acl/blacklist" {
		t.Fatalf("blacklist not denied: %+v", v)
	}
}

func TestACLWhitelistMarksTrusted(t *testing.T) {
	acl, err := NewACL(secCfg(&config.SecuritySettings{
		ACL: &config.ACLSettings{
			Blacklist: []string{"0.0.0.0/0"},
			Whitelist: []string{"192.168.1.1"},
		},
	}), nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	rc, v := run(t, acl, "192.168.1.1:1000", "http://t.local/", nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("whitelisted client denied: %+v", v)
	}
	if rc.Values["trusted"] != true {
		t.Fatal("whitelist hit must mark request trusted")
	}
}

// TestACLWhitelistTrustedFlagType pins the flag's type contract: the data
// plane's trustedFlow helper decides on a strict bool type assertion, so the
// whitelist must store a real bool true in rc.Values (not a string or other
// truthy value that would silently stop being recognized).
func TestACLWhitelistTrustedFlagType(t *testing.T) {
	acl, err := NewACL(secCfg(&config.SecuritySettings{
		ACL: &config.ACLSettings{Whitelist: []string{"192.168.1.1"}},
	}), nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := run(t, acl, "192.168.1.1:1000", "http://t.local/", nil)
	trusted, ok := rc.Values["trusted"].(bool)
	if !ok || !trusted {
		t.Fatalf("trusted flag must be a strict bool true, got %T=%v", rc.Values["trusted"], rc.Values["trusted"])
	}
}

// TestGlobalACLAppliesToSitesWithoutPerSiteACL pins the strategy-page global
// whitelist/blacklist behavior for sites that carry no security.acl section:
// those sites are absent from the stage's byDomain map, but global lists must
// still be consulted — a global whitelist hit marks the request trusted and a
// global blacklist hit denies, regardless of per-site ACL configuration.
func TestGlobalACLAppliesToSitesWithoutPerSiteACL(t *testing.T) {
	cfg := secCfg(nil)
	cfg.Policy = &config.Policy{GlobalACL: &config.ACLSettings{Whitelist: []string{"192.168.1.1"}}}
	acl, err := NewACL(cfg, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	rc, v := run(t, acl, "192.168.1.1:1000", "http://t.local/", nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("global-whitelisted client denied: %+v", v)
	}
	if rc.Values["trusted"] != true {
		t.Fatal("global whitelist hit must mark request trusted")
	}

	cfg.Policy = &config.Policy{GlobalACL: &config.ACLSettings{Blacklist: []string{"192.168.1.1"}}}
	acl, err = NewACL(cfg, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	_, v = run(t, acl, "192.168.1.1:1000", "http://t.local/", nil)
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("global-blacklisted client allowed: %+v", v)
	}
}

func TestRateLimitThrottleAfterBurst(t *testing.T) {
	rl, err := NewRateLimit(secCfg(&config.SecuritySettings{
		RateLimit: &config.RateLimitSettings{Requests: 2, WindowSec: 60, Action: "throttle"},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	for i := 0; i < 2; i++ {
		if _, v := run(t, rl, "9.9.9.9:1111", "http://t.local/", nil); v.Action != pipeline.ActionAllow {
			t.Fatalf("request %d within budget denied: %+v", i+1, v)
		}
	}
	_, v := run(t, rl, "9.9.9.9:1111", "http://t.local/", nil)
	if v.Action != pipeline.ActionDeny || v.Status != http.StatusTooManyRequests {
		t.Fatalf("third request not throttled: %+v", v)
	}
	// Different IP is unaffected.
	if _, v := run(t, rl, "8.8.4.4:2222", "http://t.local/", nil); v.Action != pipeline.ActionAllow {
		t.Fatalf("other ip throttled: %+v", v)
	}
}

func TestRateLimitDenyMode(t *testing.T) {
	rl, err := NewRateLimit(secCfg(&config.SecuritySettings{
		RateLimit: &config.RateLimitSettings{Requests: 1, WindowSec: 60, Action: "deny"},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	_, _ = run(t, rl, "7.7.7.7:1", "http://t.local/", nil)
	_, v := run(t, rl, "7.7.7.7:2", "http://t.local/", nil)
	if v.Status != http.StatusForbidden {
		t.Fatalf("deny mode status = %d, want 403", v.Status)
	}
}

func TestBotChallengeFlow(t *testing.T) {
	bot, err := NewBotChallenge(secCfg(&config.SecuritySettings{
		BotCheck: &config.BotSettings{Secret: "test-secret-123"},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	// First request: no cookie 鈫?challenge.
	rc, v := run(t, bot, "5.5.5.5:3", "http://t.local/", nil)
	if v.Action != pipeline.ActionChallenge {
		t.Fatalf("first request not challenged: %+v", v)
	}
	token, _ := rc.Values["challenge_token"].(string)
	if token == "" {
		t.Fatal("challenge token missing")
	}
	// Valid cookie 鈫?allow.
	if _, v := run(t, bot, "5.5.5.5:4", "http://t.local/", map[string]string{"km_challenge": token}); v.Action != pipeline.ActionAllow {
		t.Fatalf("valid challenge cookie denied: %+v", v)
	}
	// Tampered cookie 鈫?challenge again.
	if _, v := run(t, bot, "5.5.5.5:5", "http://t.local/", map[string]string{"km_challenge": token + "x"}); v.Action != pipeline.ActionChallenge {
		t.Fatal("tampered cookie must be challenged")
	}
}

func TestRespFilterMaskAndBlock(t *testing.T) {
	// Mask mode.
	rf, err := NewRespFilter(secCfg(&config.SecuritySettings{
		RespFilter: &config.RespFilterSettings{Enabled: true, Action: "mask", Presets: []string{"phone"}},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader("contact 13812345678 now")),
		ContentLength: -1,
	}
	if !rf.Apply("t.local", resp) {
		t.Fatal("mask: response not rewritten")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "[REDACTED:cn_mobile_phone]") {
		t.Fatalf("mask failed: %s", body)
	}
	if string(body) != "contact [REDACTED:cn_mobile_phone] now" {
		t.Fatalf("mask altered surrounding text: %s", body)
	}

	// Block mode.
	rfb, err := NewRespFilter(secCfg(&config.SecuritySettings{
		RespFilter: &config.RespFilterSettings{Enabled: true, Action: "block", Presets: []string{"idcard"}},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	resp2 := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(`{"id":"11010119900307867X"}`)),
		ContentLength: -1,
	}
	if !rfb.Apply("t.local", resp2) {
		t.Fatal("block: response not rewritten")
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("block status = %d", resp2.StatusCode)
	}

	// Clean body passes through untouched.
	rfc, _ := NewRespFilter(secCfg(&config.SecuritySettings{
		RespFilter: &config.RespFilterSettings{Enabled: true, Presets: []string{"phone", "idcard", "secret"}},
	}), quiet())
	resp3 := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader("<p>hello world</p>")),
		ContentLength: -1,
	}
	if rfc.Apply("t.local", resp3) {
		t.Fatal("clean body must not be rewritten")
	}
}
