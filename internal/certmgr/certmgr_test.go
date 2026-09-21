package certmgr

import (
	"reflect"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestInspectSitesSharedCertificates covers the sites-reference grouping:
// two sites pointing at the same tls_cert file list both primary domains,
// a site with its own file lists only itself, and an ACME site lists itself.
func TestInspectSitesSharedCertificates(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.Site{
			{Domains: []string{"a.local"}, TLSCert: "/certs/shared.pem", TLSKey: "/certs/shared.key"},
			{Domains: []string{"b.local"}, TLSCert: "/certs/shared.pem", TLSKey: "/certs/shared.key"},
			{Domains: []string{"c.local"}, TLSCert: "/certs/c.pem", TLSKey: "/certs/c.key"},
			{Domains: []string{"d.local"}, ACME: &config.ACMESettings{}},
		},
	}
	out := InspectSites(cfg)
	bySite := map[string]Info{}
	for _, info := range out {
		bySite[info.Site] = info
	}
	if got := bySite["a.local"].Sites; !reflect.DeepEqual(got, []string{"a.local", "b.local"}) {
		t.Fatalf("a.local sites = %v, want [a.local b.local]", got)
	}
	if got := bySite["b.local"].Sites; !reflect.DeepEqual(got, []string{"a.local", "b.local"}) {
		t.Fatalf("b.local sites = %v, want [a.local b.local]", got)
	}
	if got := bySite["c.local"].Sites; !reflect.DeepEqual(got, []string{"c.local"}) {
		t.Fatalf("c.local sites = %v, want [c.local]", got)
	}
	if got := bySite["d.local"].Sites; !reflect.DeepEqual(got, []string{"d.local"}) {
		t.Fatalf("d.local (acme) sites = %v, want [d.local]", got)
	}
}
