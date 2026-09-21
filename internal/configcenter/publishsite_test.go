package configcenter

import (
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func siteByDomain(cfg *config.Config, domain string) (config.Site, bool) {
	for _, s := range cfg.Sites {
		for _, d := range s.Domains {
			if strings.EqualFold(d, domain) {
				return s, true
			}
		}
	}
	return config.Site{}, false
}

func TestPublishSiteReplacesExisting(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", twoSiteCfg(), quiet())
	defer c.Close()

	updated := config.Site{
		Domains:  []string{"b.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9099"}}},
	}
	rev, err := c.PublishSite("B.LOCAL", updated, "tester", "retarget b")
	if err != nil {
		t.Fatalf("PublishSite: %v", err)
	}
	if rev != 2 {
		t.Fatalf("revision = %d", rev)
	}
	_, cfg := c.Current()
	if len(cfg.Sites) != 2 {
		t.Fatalf("site count changed: %d", len(cfg.Sites))
	}
	got, ok := siteByDomain(cfg, "b.local")
	if !ok || got.Upstream.Nodes[0].Address != "127.0.0.1:9099" {
		t.Fatalf("site b.local not replaced: %+v", got)
	}
	if a, _ := siteByDomain(cfg, "a.local"); a.Upstream.Nodes[0].Address != "127.0.0.1:9001" {
		t.Fatalf("site a.local must be untouched: %+v", a)
	}
}

func TestPublishSiteAppendsNew(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	fresh := config.Site{
		Domains:  []string{"c.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9098"}}},
	}
	if _, err := c.PublishSite("c.local", fresh, "tester", "add c"); err != nil {
		t.Fatalf("PublishSite: %v", err)
	}
	_, cfg := c.Current()
	if len(cfg.Sites) != 2 {
		t.Fatalf("new site not appended: sites=%d", len(cfg.Sites))
	}
}

func TestPublishSiteErrorIsolated(t *testing.T) {
	// Live config holds a valid site; publishing a broken site must fail
	// while the live config (and a concurrent valid site publish) is not
	// blocked by it.
	c, _ := Open(t.TempDir()+"/cc.db", twoSiteCfg(), quiet())
	defer c.Close()

	broken := config.Site{
		Domains:  []string{"bad.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: ""}}},
	}
	_, err := c.PublishSite("bad.local", broken, "tester", "")
	if err == nil {
		t.Fatal("broken site accepted")
	}
	if !strings.Contains(err.Error(), "sites[2]") && !strings.Contains(err.Error(), "bad.local") {
		t.Fatalf("error should point at the submitted site: %v", err)
	}
	if _, cfg := c.Current(); len(cfg.Sites) != 2 {
		t.Fatalf("live config mutated by failed publish: sites=%d", len(cfg.Sites))
	}

	// A valid publish right after still works (no cross-site blocking).
	good := config.Site{
		Domains:  []string{"c.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9097"}}},
	}
	if _, err := c.PublishSite("c.local", good, "tester", "add c after failure"); err != nil {
		t.Fatalf("valid publish blocked after a failed one: %v", err)
	}
}

func TestPublishAggregateReportsAllBrokenSites(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	bad := twoSiteCfg()
	bad.Sites[0].Upstream.Nodes[0].Address = ""
	bad.Sites[1].Upstream.Nodes[0].Address = ""
	err := bad.Validate()
	if err == nil {
		t.Fatal("expected aggregated validation error")
	}
	if !strings.Contains(err.Error(), "sites[0]") || !strings.Contains(err.Error(), "sites[1]") {
		t.Fatalf("aggregate error must list every broken site:\n%v", err)
	}
	if _, perr := c.Publish(bad, "t", ""); perr == nil {
		t.Fatal("invalid config accepted")
	}
}
