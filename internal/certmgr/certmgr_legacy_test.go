package certmgr

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// TestInspectSitesReadsRemappedLegacyCert pins review item C5: the
// inspection read follows the runtime path contract, so a site still
// configured with the pre-rename data directory reports certificate
// metadata once the file exists under the current layout. The resolver
// indirection keeps the test portable: the remap target is hardcoded under
// /var/lib, which a unit test cannot (and must not) populate for real.
func TestInspectSitesReadsRemappedLegacyCert(t *testing.T) {
	dir := t.TempDir()
	genCert, genKey, err := EnsureSelfSigned(dir, "remap.local")
	if err != nil {
		t.Fatal(err)
	}
	shop := filepath.Join(dir, "uploads", "certs", "shop")
	if err := os.MkdirAll(shop, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, m := range [][2]string{{genCert, "cert.pem"}, {genKey, "key.pem"}} {
		b, err := os.ReadFile(m[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shop, m[1]), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orig := resolveDataPath
	resolveDataPath = func(p string, _ *slog.Logger) string {
		const legacy = "/var/lib/kingmoat/"
		if strings.HasPrefix(p, legacy) {
			return filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(p, legacy)))
		}
		return p
	}
	t.Cleanup(func() { resolveDataPath = orig })

	cfg := &config.Config{
		Sites: []config.Site{
			{Domains: []string{"a.local"}, TLSCert: "/var/lib/kingmoat/uploads/certs/shop/cert.pem", TLSKey: "/var/lib/kingmoat/uploads/certs/shop/key.pem"},
			{Domains: []string{"c.local"}, TLSCert: genCert, TLSKey: genKey},
			{Domains: []string{"d.local"}, TLSCert: "/var/lib/kingmoat/uploads/certs/none/cert.pem", TLSKey: "/var/lib/kingmoat/uploads/certs/none/key.pem"},
		},
	}
	out := InspectSites(cfg)
	bySite := map[string]Info{}
	for _, info := range out {
		bySite[info.Site] = info
	}
	// Remapped legacy paths must read the certificate metadata.
	a := bySite["a.local"]
	if a.Error != "" || a.Subject == "" || a.NotAfter == "" {
		t.Fatalf("a.local info = %+v, want metadata read via the remap (no error)", a)
	}
	// Current-layout paths behave exactly as before (no remap involved).
	c := bySite["c.local"]
	if c.Error != "" || c.Subject == "" {
		t.Fatalf("c.local info = %+v, want a plain read without remapping", c)
	}
	// A legacy path whose remapped target is missing keeps the read error
	// (same contract as the data plane: no silent remap on a probe miss).
	d := bySite["d.local"]
	if d.Error == "" {
		t.Fatalf("d.local info = %+v, want the read error preserved", d)
	}
}
