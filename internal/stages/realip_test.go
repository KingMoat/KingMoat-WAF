package stages

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func realIPSite(trusted []string, header string) *config.Site {
	s := &config.Site{
		Domains: []string{"a.local"},
		RealIP:  &config.RealIPSettings{Enabled: true, TrustedProxies: trusted},
	}
	if header != "" {
		s.RealIP.Header = header
	}
	return s
}

func reqWithPeer(peer string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://a.local/", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveRealIPDisabled(t *testing.T) {
	s := &config.Site{Domains: []string{"a.local"}}
	r := reqWithPeer("10.0.0.9:1111", map[string]string{"X-Forwarded-For": "203.0.113.5"})
	if ip := ResolveRealIP(s, r); ip != nil {
		t.Fatalf("disabled site must not resolve, got %v", ip)
	}
}

func TestResolveRealIPUntrustedPeerIgnored(t *testing.T) {
	// Peer is not a trusted proxy: a spoofed XFF must be ignored entirely.
	s := realIPSite([]string{"10.0.0.0/8"}, "")
	r := reqWithPeer("203.0.113.99:2222", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if ip := ResolveRealIP(s, r); ip != nil {
		t.Fatalf("untrusted peer must fail closed, got %v", ip)
	}
}

func TestResolveRealIPAppendChain(t *testing.T) {
	// LB (trusted) forwarding a real client chain: rightmost non-trusted wins.
	s := realIPSite([]string{"10.0.0.0/8"}, "")
	r := reqWithPeer("10.0.0.9:3333", map[string]string{
		"X-Forwarded-For": "198.51.100.7, 10.0.0.1, 10.0.0.9",
	})
	got := ResolveRealIP(s, r)
	if got == nil || got.String() != "198.51.100.7" {
		t.Fatalf("want 198.51.100.7, got %v", got)
	}
}

func TestResolveRealIPNoHeaderFallsBack(t *testing.T) {
	s := realIPSite([]string{"10.0.0.0/8"}, "")
	r := reqWithPeer("10.0.0.9:4444", nil)
	if ip := ResolveRealIP(s, r); ip != nil {
		t.Fatalf("missing header must return nil (caller falls back to peer), got %v", ip)
	}
}

func TestResolveRealIPAllTrustedLeftmost(t *testing.T) {
	// Nested trusted proxies: every entry trusted → leftmost is closest
	// to the real client.
	s := realIPSite([]string{"10.0.0.0/8", "172.16.0.0/12"}, "")
	r := reqWithPeer("10.0.0.9:5555", map[string]string{
		"X-Forwarded-For": "172.16.0.5, 10.0.0.1",
	})
	got := ResolveRealIP(s, r)
	if got == nil || got.String() != "172.16.0.5" {
		t.Fatalf("want 172.16.0.5, got %v", got)
	}
}

func TestResolveRealIPMultiHeaderAndPorts(t *testing.T) {
	s := realIPSite([]string{"10.0.0.0/8"}, "")
	r := reqWithPeer("10.0.0.9:6666", map[string]string{
		"X-Forwarded-For": "10.0.0.1:8888",
	})
	r.Header.Add("X-Forwarded-For", "198.51.100.9:1234")
	r.Header.Add("X-Forwarded-For", "garbage")
	got := ResolveRealIP(s, r)
	if got == nil || got.String() != "198.51.100.9" {
		t.Fatalf("want 198.51.100.9, got %v", got)
	}
}

func TestResolveRealIPCustomHeader(t *testing.T) {
	s := realIPSite([]string{"10.0.0.0/8"}, "X-Real-IP")
	r := reqWithPeer("10.0.0.9:7777", map[string]string{
		"X-Forwarded-For": "198.51.100.1", // ignored: custom header configured
		"X-Real-IP":       "198.51.100.2",
	})
	got := ResolveRealIP(s, r)
	if got == nil || got.String() != "198.51.100.2" {
		t.Fatalf("want 198.51.100.2, got %v", got)
	}
}

func TestResolveRealIPCaseInsensitiveHeader(t *testing.T) {
	s := realIPSite([]string{"10.0.0.0/8"}, "x-forwarded-for")
	r := reqWithPeer("10.0.0.9:8888", map[string]string{"X-FORWARDED-FOR": "198.51.100.3"})
	got := ResolveRealIP(s, r)
	if got == nil || got.String() != "198.51.100.3" {
		t.Fatalf("want 198.51.100.3, got %v", got)
	}
}

// ClientIPFromContext must win over RemoteAddr for every stage consumer.
func TestClientIPPrefersContext(t *testing.T) {
	r := reqWithPeer("10.0.0.9:9999", nil)
	ctx := pipeline.WithClientIP(r.Context(), net.ParseIP("198.51.100.42"))
	r = r.WithContext(ctx)
	got := clientIP(r)
	if got == nil || got.String() != "198.51.100.42" {
		t.Fatalf("clientIP must prefer context, got %v", got)
	}
}

// ACL must evaluate entries against the resolved real IP.
func TestACLUsesRealIP(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{*realIPSite([]string{"10.0.0.0/8"}, "")}}
	cfg.Sites[0].Security = &config.SecuritySettings{
		ACL: &config.ACLSettings{Blacklist: []string{"198.51.100.7"}},
	}
	acl, err := NewACL(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := reqWithPeer("10.0.0.9:1010", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	ctx := pipeline.WithClientIP(context.Background(), net.ParseIP("198.51.100.7"))
	r = r.WithContext(ctx)
	rc := &pipeline.RequestContext{Request: r, Site: pipeline.SiteView{Domain: "a.local"}, Values: map[string]any{}}
	if v := acl.Inspect(context.Background(), rc); v.Action != pipeline.ActionDeny {
		t.Fatalf("real IP must be blacklisted, verdict %v", v)
	}
}

// Matcher client_ip conditions must see the resolved real IP.
func TestMatcherUsesRealIP(t *testing.T) {
	cfg := &config.Config{
		Policy: &config.Policy{
			Matchers: []config.MatcherRule{{
				Name: "block-spoofed", Enabled: true, Action: config.ActionDeny,
				Conditions: []config.MatcherCondition{{Field: config.FieldClientIP, Op: config.OpCIDR, Value: "198.51.100.0/24"}},
			}},
		},
	}
	m, err := NewMatcher(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := reqWithPeer("10.0.0.9:1111", nil) // peer is NOT in the rule CIDR
	ctx := pipeline.WithClientIP(r.Context(), net.ParseIP("198.51.100.7"))
	r = r.WithContext(ctx)
	rc := &pipeline.RequestContext{Request: r, Site: pipeline.SiteView{Domain: "a.local"}, Values: map[string]any{}}
	if v := m.Inspect(context.Background(), rc); v.Action != pipeline.ActionDeny {
		t.Fatalf("matcher must match real IP, verdict %v", v)
	}
}

func TestParseForwardedChainIPv6(t *testing.T) {
	ips := parseForwardedChain([]string{"[2001:db8::1]:443, 2001:db8::2"})
	if len(ips) != 2 || ips[0].String() != "2001:db8::1" || ips[1].String() != "2001:db8::2" {
		t.Fatalf("unexpected chain: %v", ips)
	}
}
