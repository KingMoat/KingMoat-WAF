package certmgr

import (
	"context"
	"reflect"
	"testing"

	"golang.org/x/crypto/acme/autocert"

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

// TestACMEHosts covers the domain set feeding the HostWhitelist: only ACME
// sites contribute, order follows first appearance, duplicates collapse.
func TestACMEHosts(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.Site{
			{Domains: []string{"plain.local"}},
			{Domains: []string{"a.local", "x.local"}, ACME: &config.ACMESettings{}},
			{Domains: []string{"b.local"}, ACME: &config.ACMESettings{}},
			{Domains: []string{"a.local"}, ACME: &config.ACMESettings{}},
			{Domains: []string{"other.local"}},
		},
	}
	got := ACMEHosts(cfg)
	want := []string{"a.local", "x.local", "b.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ACMEHosts = %v, want %v", got, want)
	}
	if got := ACMEHosts(&config.Config{}); got != nil {
		t.Fatalf("ACMEHosts(empty) = %v, want nil", got)
	}
}

// TestACMEHolderSlotManagers covers the slot construction contract: nil
// slots without ACME sites, per-slot HostWhitelist membership, the
// site-to-global email fallback chain and the staging directory URL (each
// mode's manager owns its own CA endpoint and cache directory).
func TestACMEHolderSlotManagers(t *testing.T) {
	t.Run("nil without acme sites", func(t *testing.T) {
		h := NewACMEHolder(t.TempDir())
		cfg := &config.Config{Sites: []config.Site{{Domains: []string{"plain.local"}}}}
		if prod, staging := h.Rebuild(cfg, "ops@x.io"); prod != nil || staging != nil {
			t.Fatalf("Rebuild = (%v, %v), want nil managers", prod, staging)
		}
	})

	t.Run("host whitelist", func(t *testing.T) {
		h := NewACMEHolder(t.TempDir())
		cfg := &config.Config{Sites: []config.Site{
			{Domains: []string{"a.local"}, ACME: &config.ACMESettings{}},
			{Domains: []string{"b.local"}, ACME: &config.ACMESettings{}},
		}}
		prod, staging := h.Rebuild(cfg, "")
		if prod == nil || staging != nil {
			t.Fatalf("Rebuild = (%v, %v), want prod manager only", prod, staging)
		}
		for _, host := range []string{"a.local", "b.local"} {
			if err := prod.HostPolicy(context.Background(), host); err != nil {
				t.Fatalf("HostPolicy(%q) = %v, want allowed", host, err)
			}
		}
		if err := prod.HostPolicy(context.Background(), "other.local"); err == nil {
			t.Fatal("HostPolicy(other.local) = nil, want rejected")
		}
	})

	t.Run("email fallback chain", func(t *testing.T) {
		// Site contact wins over the global settings email.
		h := NewACMEHolder(t.TempDir())
		cfg := &config.Config{Sites: []config.Site{
			{Domains: []string{"a.local"}, ACME: &config.ACMESettings{Email: "site@x.io"}},
		}}
		prod, _ := h.Rebuild(cfg, "global@x.io")
		if prod == nil || prod.Email != "site@x.io" {
			t.Fatalf("Email = %q, want site contact", prod.Email)
		}
		// Without a site contact the global settings email applies.
		h = NewACMEHolder(t.TempDir())
		cfg = &config.Config{Sites: []config.Site{
			{Domains: []string{"a.local"}, ACME: &config.ACMESettings{}},
		}}
		prod, _ = h.Rebuild(cfg, "global@x.io")
		if prod == nil || prod.Email != "global@x.io" {
			t.Fatalf("Email = %q, want global contact", prod.Email)
		}
	})

	t.Run("staging directory url", func(t *testing.T) {
		h := NewACMEHolder(t.TempDir())
		cfg := &config.Config{Sites: []config.Site{
			{Domains: []string{"a.local"}, ACME: &config.ACMESettings{Staging: true}},
		}}
		prod, staging := h.Rebuild(cfg, "")
		if staging == nil || staging.Client == nil || staging.Client.DirectoryURL != "https://acme-staging-v02.api.letsencrypt.org/directory" {
			t.Fatalf("staging client = %+v, want staging directory URL", staging)
		}
		if prod != nil {
			t.Fatalf("prod manager = %v, want nil (no prod sites)", prod)
		}
		cfg.Sites[0].ACME.Staging = false
		prod, staging = h.Rebuild(cfg, "")
		if prod == nil || prod.Client != nil {
			t.Fatalf("non-staging client = %+v, want nil", prod)
		}
		if staging != nil {
			t.Fatalf("staging manager = %v, want nil after flag flip", staging)
		}
	})
}

// TestACMEHolderRebuildFollowsConfig covers the dynamic rebuild contract:
// adding an ACME site publishes a manager that allows the new domain,
// removing the last ACME site stores nil (ACME disabled), and re-adding
// swaps to a manager scoped to the new domain set only.
func TestACMEHolderRebuildFollowsConfig(t *testing.T) {
	h := NewACMEHolder(t.TempDir())
	if m := h.Prod(); m != nil {
		t.Fatalf("fresh holder Prod = %v, want nil", m)
	}

	withACME := func(domains ...string) *config.Config {
		cfg := &config.Config{}
		for _, d := range domains {
			cfg.Sites = append(cfg.Sites, config.Site{Domains: []string{d}, ACME: &config.ACMESettings{}})
		}
		return cfg
	}
	allows := func(m *autocert.Manager, host string) bool {
		return m != nil && m.HostPolicy(context.Background(), host) == nil
	}

	// Publish an ACME site: the new domain becomes issuable.
	if prod, staging := h.Rebuild(withACME("a.local"), ""); prod == nil || staging != nil {
		t.Fatalf("Rebuild(a.local) = (%v, %v), want prod manager only", prod, staging)
	}
	if m := h.Prod(); !allows(m, "a.local") {
		t.Fatalf("Prod after rebuild: HostPolicy(a.local) rejected (m=%v)", m)
	}

	// Publish the removal of the last ACME site: ACME disables cleanly.
	if prod, staging := h.Rebuild(&config.Config{}, ""); prod != nil || staging != nil {
		t.Fatalf("Rebuild(empty) = (%v, %v), want nil", prod, staging)
	}
	if m := h.Prod(); m != nil {
		t.Fatalf("Prod after removal = %v, want nil", m)
	}

	// Re-add with a different domain: the old domain stops being answered.
	if prod, _ := h.Rebuild(withACME("c.local"), ""); prod == nil {
		t.Fatal("Rebuild(c.local) = nil, want manager")
	}
	m := h.Prod()
	if !allows(m, "c.local") || allows(m, "a.local") {
		t.Fatalf("Prod after re-add: c.local allowed=%v, a.local allowed=%v", allows(m, "c.local"), allows(m, "a.local"))
	}
}
