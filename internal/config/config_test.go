package config

import (
	"strings"
	"testing"
)

func baseRedirSite() Site {
	return Site{
		Domains:         []string{"a.local"},
		Upstream:        Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}},
		TLSCert:         "/tmp/a.crt",
		TLSKey:          "/tmp/a.key",
		RedirectToHTTPS: true,
	}
}

func TestValidateRedirectOK(t *testing.T) {
	c := &Config{ListenHTTP: ":80", ListenHTTPS: ":443", Sites: []Site{baseRedirSite()}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid redirect config rejected: %v", err)
	}
}

func TestValidateRedirectRequiresTLS(t *testing.T) {
	s := baseRedirSite()
	s.TLSCert = ""
	s.TLSKey = ""
	c := &Config{ListenHTTP: ":80", ListenHTTPS: ":443", Sites: []Site{s}}
	if err := c.Validate(); err == nil {
		t.Fatal("redirect without tls_cert/tls_key must be rejected")
	}
}

func TestValidateRedirectRequiresHTTPSListener(t *testing.T) {
	c := &Config{ListenHTTP: ":80", Sites: []Site{baseRedirSite()}}
	if err := c.Validate(); err == nil {
		t.Fatal("redirect without global listen_https must be rejected")
	}
}

func TestValidateRedirectOffNeedsNoTLS(t *testing.T) {
	s := baseRedirSite()
	s.RedirectToHTTPS = false
	s.TLSCert = ""
	s.TLSKey = ""
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err != nil {
		t.Fatalf("plain site must not require TLS: %v", err)
	}
}

func baseRealIPSite() Site {
	return Site{
		Domains: []string{"a.local"},
		Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}},
	}
}


func TestValidateRejectsDuplicateDomainAcrossSites(t *testing.T) {
	c := &Config{
		ListenHTTP: ":80",
		Sites: []Site{
			{Name: "portal", Domains: []string{"Portal.Local"},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}}},
			// Same domain, different case: normalization must flag it
			// (whitespace variants are already rejected per-site).
			{Domains: []string{"portal.LOCAL"},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9001"}}}},
		},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("duplicate domain across sites must be rejected")
	}
	// The error must carry the conflicting domain and BOTH site names.
	if !strings.Contains(err.Error(), `"portal.local"`) ||
		!strings.Contains(err.Error(), `"portal"`) {
		t.Fatalf("error must name domain and both sites: %v", err)
	}
}

func TestValidateWildcardDomainSkipsDuplicateCheck(t *testing.T) {
	// Wildcard entries are exempt (apex/subdomain combos are legitimate),
	// and an exact domain may coexist with a covering wildcard.
	c := &Config{
		ListenHTTP: ":80",
		Sites: []Site{
			{Domains: []string{"*.local"},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}}},
			{Domains: []string{"*.local"},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9001"}}}},
			{Domains: []string{"a.local"},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9002"}}}},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("wildcard/parent domains must not be flagged: %v", err)
	}
	// The wildcard may not be abused to sneak an exact duplicate past the
	// check: normalization still applies to exact entries.
	c.Sites[1].Domains = []string{"*.local", "a.local"}
	if err := c.Validate(); err == nil {
		t.Fatal("exact duplicate hidden behind a wildcard sibling must be rejected")
	}
}

func TestValidateRealIPOK(t *testing.T) {
	s := baseRealIPSite()
	s.RealIP = &RealIPSettings{Enabled: true, TrustedProxies: []string{"10.0.0.0/8", "192.0.2.1"}}
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid real_ip config rejected: %v", err)
	}
}

func TestValidateRealIPRequiresTrustedProxies(t *testing.T) {
	s := baseRealIPSite()
	s.RealIP = &RealIPSettings{Enabled: true}
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err == nil {
		t.Fatal("real_ip without trusted_proxies must be rejected")
	}
}

func TestValidateRealIPRejectsBadCIDR(t *testing.T) {
	s := baseRealIPSite()
	s.RealIP = &RealIPSettings{Enabled: true, TrustedProxies: []string{"not-an-ip"}}
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err == nil {
		t.Fatal("real_ip with invalid trusted proxy must be rejected")
	}
}

func TestValidateHeadersOK(t *testing.T) {
	s := baseRealIPSite()
	s.Headers = &HeaderRewrite{
		Set: map[string]string{"X-Real-IP": "$client_ip", "X-Fwd-User": "$hdr.X-Auth-User"},
		Del: []string{"X-Internal-Trace"},
	}
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid headers config rejected: %v", err)
	}
}

func TestValidateHeadersRejectsProtected(t *testing.T) {
	s := baseRealIPSite()
	s.Headers = &HeaderRewrite{Set: map[string]string{"Host": "evil.local"}}
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err == nil {
		t.Fatal("headers rewriting Host must be rejected")
	}
}
