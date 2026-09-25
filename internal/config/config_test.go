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
	err := c.Validate()
	if err == nil {
		t.Fatal("redirect without tls_cert/tls_key must be rejected")
	}
	if !strings.Contains(err.Error(), `site "a.local" enables "redirect HTTP to HTTPS"`) ||
		!strings.Contains(err.Error(), "serve HTTPS first") {
		t.Fatalf("unfriendly redirect TLS message: %v", err)
	}
}

func TestValidateRedirectRequiresHTTPSListener(t *testing.T) {
	c := &Config{ListenHTTP: ":80", Sites: []Site{baseRedirSite()}}
	err := c.Validate()
	if err == nil {
		t.Fatal("redirect without global listen_https must be rejected")
	}
	if !strings.Contains(err.Error(), `site "a.local" enables "redirect HTTP to HTTPS"`) ||
		!strings.Contains(err.Error(), "global HTTPS listen address") ||
		!strings.Contains(err.Error(), "Sites page") {
		t.Fatalf("unfriendly redirect listen message: %v", err)
	}
}

func baseACMESite() Site {
	return Site{
		Domains:  []string{"acme.local"},
		Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:9000"}}},
		ACME:     &ACMESettings{},
	}
}

func TestValidateACMEEmailRequired(t *testing.T) {
	c := &Config{ListenHTTP: ":80", ListenHTTPS: ":443", Sites: []Site{baseACMESite()}}
	err := c.Validate()
	if err == nil {
		t.Fatal("ACME site without any contact email must be rejected")
	}
	if !strings.Contains(err.Error(), `site "acme.local" enables ACME`) ||
		!strings.Contains(err.Error(), "contact email") {
		t.Fatalf("unfriendly ACME email message: %v", err)
	}
}

func TestValidateACMERequiresHTTPSListener(t *testing.T) {
	s := baseACMESite()
	s.ACME.Email = "ops@example.com"
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	err := c.Validate()
	if err == nil {
		t.Fatal("ACME site without global listen_https must be rejected")
	}
	if !strings.Contains(err.Error(), `site "acme.local" enables ACME`) ||
		!strings.Contains(err.Error(), "global HTTPS listen address") ||
		!strings.Contains(err.Error(), "Sites page") {
		t.Fatalf("unfriendly ACME listen message: %v", err)
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

func baseSNIHostSite() Site {
	return Site{
		Domains:  []string{"a.local"},
		Upstream: Upstream{Nodes: []UpstreamNode{{Address: "https://127.0.0.1:9000"}}},
	}
}

func TestValidateUpstreamSNIHostOK(t *testing.T) {
	s := baseSNIHostSite()
	s.Upstream.SNIHost = "backend.example.com"
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	if err := c.Validate(); err != nil {
		t.Fatalf("sni_host-only config rejected: %v", err)
	}
}

func TestValidateUpstreamSNIForwardSNIHostExclusive(t *testing.T) {
	s := baseSNIHostSite()
	s.Upstream.SNIForward = true
	s.Upstream.SNIHost = "backend.example.com"
	c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
	err := c.Validate()
	if err == nil {
		t.Fatal("sni_forward + sni_host must be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error must name the exclusivity rule: %v", err)
	}
}

func TestValidateUpstreamSNIHostRejectsInvalidHostname(t *testing.T) {
	for _, bad := range []string{
		"https://backend.example.com", // scheme
		"backend.example.com:443",     // port
		"backend.example.com/path",    // path
		"backend example.com",         // whitespace
		"backend.example.com：8443",    // full-width colon
	} {
		s := baseSNIHostSite()
		s.Upstream.SNIHost = bad
		c := &Config{ListenHTTP: ":80", Sites: []Site{s}}
		err := c.Validate()
		if err == nil {
			t.Fatalf("sni_host %q must be rejected", bad)
		}
		if !strings.Contains(err.Error(), "not a valid hostname") {
			t.Fatalf("sni_host %q: unexpected error: %v", bad, err)
		}
	}
}
