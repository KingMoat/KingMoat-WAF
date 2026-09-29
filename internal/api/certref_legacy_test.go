package api

import (
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestCertRefSitesSurvivesLegacyPaths pins the certificate-library reference
// lookup across the v0.7.10 data-directory rename: a site still spelled with
// the pre-rename directory counts as referencing the entry under the current
// uploads root, so the console keeps showing live references after a
// migration (the strict-prefix predicate showed an empty list and invited
// deleting certificates that were still in use).
func TestCertRefSitesSurvivesLegacyPaths(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{
		{Domains: []string{"legacy.local"}, TLSCert: "/var/lib/kingmoat/uploads/certs/shop/cert.pem", TLSKey: "/var/lib/kingmoat/uploads/certs/shop/key.pem"},
		{Domains: []string{"current.local"}, TLSCert: "/var/lib/kingmoatwaf/uploads/certs/shop/cert.pem"},
		{Domains: []string{"other.local"}, TLSCert: "/var/lib/kingmoatwaf/uploads/certs/solo/cert.pem"},
	}}
	s := &Server{}

	got := s.certRefSites(cfg, "/var/lib/kingmoatwaf/uploads/certs/shop")
	want := []string{"legacy.local", "current.local"}
	if len(got) != len(want) {
		t.Fatalf("shop refs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("shop refs = %v, want %v", got, want)
		}
	}

	if got := s.certRefSites(cfg, "/var/lib/kingmoatwaf/uploads/certs/solo"); len(got) != 1 || got[0] != "other.local" {
		t.Fatalf("solo refs = %v, want [other.local]", got)
	}
	if got := s.certRefSites(cfg, "/var/lib/kingmoatwaf/uploads/certs/none"); len(got) != 0 {
		t.Fatalf("unreferenced entry refs = %v, want empty", got)
	}
}

// TestPathWithinNormalizesPaths pins the shared predicate: whitespace and
// separator spelling must not change the answer, and a legacy-prefixed path
// matches under the current root.
func TestPathWithinNormalizesPaths(t *testing.T) {
	const dir = "/var/lib/kingmoatwaf/uploads/certs/shop"
	cases := []struct {
		name string
		p    string
		want bool
	}{
		{"direct cert", dir + "/cert.pem", true},
		{"legacy spelling", "/var/lib/kingmoat/uploads/certs/shop/cert.pem", true},
		{"other entry", "/var/lib/kingmoatwaf/uploads/certs/solo/cert.pem", false},
		{"legacy other entry", "/var/lib/kingmoat/uploads/certs/solo/cert.pem", false},
		{"dir itself", dir, true},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathWithin(dir, tc.p); got != tc.want {
				t.Fatalf("pathWithin(dir, %q) = %v, want %v", tc.p, got, tc.want)
			}
		})
	}
}
