package proxy

import (
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestBuildRouterLegacyCertPathErrorHints pins the post-migration failure
// message: a tls_cert still spelled with the pre-rename data directory (and
// missing from every candidate location) must fail the site build with an
// error that names the upgrade migration as the likely cause — the operator
// sees why, instead of a bare "file not found".
func TestBuildRouterLegacyCertPathErrorHints(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"legacy-cert.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:1"}}},
			TLSCert:  "/var/lib/kingmoat/uploads/certs/site-a/cert.pem",
			TLSKey:   "/var/lib/kingmoat/uploads/certs/site-a/key.pem",
		}},
	}
	_, err := buildRouter(cfg, nil, testLogger(), nil, nil, 0)
	if err == nil {
		t.Fatal("buildRouter must fail for a missing legacy-path certificate")
	}
	msg := err.Error()
	for _, want := range []string{"read tls_cert", "疑似升级迁移", "/var/lib/kingmoat", "/var/lib/kingmoatwaf", "请更新配置或重新在控制台选择证书"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

// TestBuildRouterCurrentLayoutCertPathUnchanged is the no-regression half:
// current-layout paths without migration residue build (or fail) exactly as
// before, with no migration hint appended.
func TestBuildRouterCurrentLayoutCertPathUnchanged(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"plain-cert.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:1"}}},
			TLSCert:  "/var/lib/kingmoatwaf/uploads/certs/site-a/cert.pem",
			TLSKey:   "/var/lib/kingmoatwaf/uploads/certs/site-a/key.pem",
		}},
	}
	_, err := buildRouter(cfg, nil, testLogger(), nil, nil, 0)
	if err == nil {
		t.Fatal("buildRouter must fail for a missing certificate")
	}
	if strings.Contains(err.Error(), "疑似升级迁移") {
		t.Fatalf("current-layout failure must not carry the migration hint: %v", err)
	}
	if !strings.Contains(err.Error(), "read tls_cert") {
		t.Fatalf("error must keep the original shape: %v", err)
	}
}
