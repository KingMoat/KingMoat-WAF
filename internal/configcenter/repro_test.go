package configcenter

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func bptr(b bool) *bool { return &b }

func TestReproSmokeIsolationSequence(t *testing.T) {
	db := filepath.Join(t.TempDir(), "repro.db")
	seed := &config.Config{
		ListenHTTP: ":19081",
		Sites: []config.Site{{
			Domains:  []string{"a.local"},
			WAF:      &config.WAFSettings{Enabled: bptr(true)},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:19090"}}},
		}},
	}
	c, err := Open(db, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	strong := config.Site{
		Domains:    []string{"a.local"},
		WAF:        &config.WAFSettings{Enabled: bptr(true)},
		TLSProfile: "strong",
		Upstream:   config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:19090"}}},
	}
	rev2, err := c.PublishSite("a.local", strong, "t", "smoke site publish")
	t.Logf("rev2: %d err: %v", rev2, err)

	broken := config.Site{
		Domains:  []string{"bad.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: ""}}},
	}
	_, err = c.PublishSite("bad.local", broken, "t", "")
	t.Logf("bad publish err: %v", err)

	good := config.Site{
		Domains:  []string{"c.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:19090"}}},
	}
	rev4, err := c.PublishSite("c.local", good, "t", "")
	t.Logf("good publish: rev=%d err=%v", rev4, err)

	_, cfg := c.Current()
	for i, s := range cfg.Sites {
		t.Logf("sites[%d] = %v upstream=%v", i, s.Domains, s.Upstream.Nodes)
	}
	if len(cfg.Sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(cfg.Sites))
	}
	fmt.Println("repro done")
}
