package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func hdrTestReq(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://a.local/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	r.Header.Set("X-Authenticated-User", "ops@example.com")
	r.Header.Set("X-Internal-Trace", "secret-1")
	return r
}

func TestApplyHeaderOpsSetAddDel(t *testing.T) {
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{"X-Real-IP": "$client_ip"},
		Add: map[string]string{"X-Multi": "a"},
		Del: []string{"x-internal-trace"},
	})
	in := hdrTestReq("10.0.0.9:1000", "")
	in = in.WithContext(pipeline.WithClientIP(in.Context(), net.ParseIP("198.51.100.7")))
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)

	if got := out.Get("X-Real-IP"); got != "198.51.100.7" {
		t.Fatalf("set $client_ip: got %q", got)
	}
	if got := out["X-Multi"]; len(got) != 1 || got[0] != "a" {
		t.Fatalf("add: got %v", got)
	}
	if out.Get("X-Internal-Trace") != "" {
		t.Fatal("del must remove the header")
	}
}

func TestApplyHeaderOpsDelBeforeSet(t *testing.T) {
	// del runs first so a deleted header cannot survive via set ordering.
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Del: []string{"X-Internal-Trace"},
	})
	in := hdrTestReq("10.0.0.9:1000", "")
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)
	if out.Get("X-Internal-Trace") != "" {
		t.Fatal("del must remove the header")
	}
}

func TestApplyHeaderOpsHdrCopyAndSkip(t *testing.T) {
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{
			"X-Forwarded-User": "$hdr.X-Authenticated-User",
			"X-Empty":          "$hdr.X-Missing-Header",
		},
	})
	in := hdrTestReq("10.0.0.9:1000", "")
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)

	if got := out.Get("X-Forwarded-User"); got != "ops@example.com" {
		t.Fatalf("hdr copy: got %q", got)
	}
	if _, ok := out["X-Empty"]; ok {
		t.Fatal("missing $hdr source must skip the op entirely")
	}
}

func TestApplyHeaderOpsScalarVars(t *testing.T) {
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{"X-Env": "$scheme|$host|$remote_addr"},
	})
	in := hdrTestReq("10.0.0.9:1000", "")
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)
	if got := out.Get("X-Env"); got != "http|a.local|10.0.0.9" {
		t.Fatalf("scalar vars: got %q", got)
	}
}

func TestApplyHeaderOpsOverrideXFF(t *testing.T) {
	// Explicit site config wins over the built-in X-Forwarded-* handling.
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{"X-Forwarded-For": "$client_ip"},
	})
	in := hdrTestReq("10.0.0.9:1000", "1.2.3.4")
	in = in.WithContext(pipeline.WithClientIP(in.Context(), net.ParseIP("198.51.100.7")))
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)
	if got := out.Get("X-Forwarded-For"); got != "198.51.100.7" {
		t.Fatalf("config must override XFF, got %q", got)
	}
}

func TestApplyHeaderOpsNil(t *testing.T) {
	in := hdrTestReq("10.0.0.9:1000", "")
	out := in.Header.Clone()
	applyHeaderOps(out, in, nil)
	if len(out) != len(in.Header) {
		t.Fatal("nil plan must be a no-op")
	}
}

func TestApplyHeaderOpsClientIPFallsBackToPeer(t *testing.T) {
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{"X-Real-IP": "$client_ip"},
	})
	in := hdrTestReq("10.0.0.9:1000", "") // no context IP
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)
	if got := out.Get("X-Real-IP"); got != "10.0.0.9" {
		t.Fatalf("peer fallback: got %q", got)
	}
}

// config-level validation rejects protected headers and unknown placeholders.
func TestHeaderRewriteValidate(t *testing.T) {
	ok := &config.HeaderRewrite{Set: map[string]string{"X-A": "$client_ip $host $scheme $trace_id $remote_addr $hdr.X-B"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, cfg := range map[string]*config.HeaderRewrite{
		"protected-set":  {Set: map[string]string{"Content-Length": "1"}},
		"protected-del":  {Del: []string{"transfer-encoding"}},
		"protected-host": {Set: map[string]string{"Host": "evil.local"}},
		"bad-name":       {Set: map[string]string{"X A": "1"}},
		"empty-name":     {Del: []string{""}},
		"crlf":           {Set: map[string]string{"X-A": "v\r\nX-Evil: 1"}},
		"unknown-var":    {Set: map[string]string{"X-A": "$request_uri"}},
		"bad-hdr":        {Set: map[string]string{"X-A": "$hdr."}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}

func TestCompileCanonicalizesNames(t *testing.T) {
	c := compileHeaderRewrite(&config.HeaderRewrite{
		Set: map[string]string{"x-real-ip": "1"},
		Del: []string{"x-internal-trace"},
	})
	in := hdrTestReq("10.0.0.9:1000", "")
	out := in.Header.Clone()
	applyHeaderOps(out, in, c)
	if got := out.Get("X-Real-Ip"); got != "1" {
		t.Fatalf("canonical set: got %q", got)
	}
	if out.Get("X-Internal-Trace") != "" {
		t.Fatal("canonical del failed")
	}
}
