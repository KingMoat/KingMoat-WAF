package certmgr

import (
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestInspectSitesGroupsLegacyAndCurrentPaths pins the post-migration
// reference grouping: a site still configured with the pre-rename data
// directory and a site using the current spelling of the same certificate
// material must surface as one shared group — the strict-equality grouping
// made the migration silently hide live references.
func TestInspectSitesGroupsLegacyAndCurrentPaths(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{
			{Domains: []string{"a.local"}, TLSCert: "/var/lib/kingmoat/uploads/certs/shop/cert.pem", TLSKey: "/var/lib/kingmoat/uploads/certs/shop/key.pem"},
			{Domains: []string{"b.local"}, TLSCert: "/var/lib/kingmoatwaf/uploads/certs/shop/cert.pem", TLSKey: "/var/lib/kingmoatwaf/uploads/certs/shop/key.pem"},
			{Domains: []string{"c.local"}, TLSCert: "/var/lib/kingmoatwaf/uploads/certs/solo/cert.pem", TLSKey: "/var/lib/kingmoatwaf/uploads/certs/solo/key.pem"},
		},
	}
	out := InspectSites(cfg)
	sitesOf := map[string][]string{}
	for _, info := range out {
		sitesOf[info.Site] = info.Sites
	}
	if got := sitesOf["a.local"]; len(got) != 2 || got[0] != "a.local" || got[1] != "b.local" {
		t.Fatalf("a.local sites = %v, want [a.local b.local]", got)
	}
	if got := sitesOf["b.local"]; len(got) != 2 || got[0] != "a.local" || got[1] != "b.local" {
		t.Fatalf("b.local sites = %v, want [a.local b.local]", got)
	}
	if got := sitesOf["c.local"]; len(got) != 1 || got[0] != "c.local" {
		t.Fatalf("c.local sites = %v, want [c.local]", got)
	}
}
