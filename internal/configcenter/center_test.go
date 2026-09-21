package configcenter

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func seedCfg() *config.Config {
	return &config.Config{
		ListenHTTP: ":8080",
		Sites: []config.Site{{
			Domains:  []string{"a.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9001"}}},
		}},
	}
}

func twoSiteCfg() *config.Config {
	c := seedCfg()
	c.Sites = append(c.Sites, config.Site{
		Domains:  []string{"b.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9002"}}},
	})
	return c
}

func TestOpenSeedPublishSubscribe(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rev, cfg := c.Current()
	if rev != 1 || len(cfg.Sites) != 1 {
		t.Fatalf("seed state: rev=%d sites=%d", rev, len(cfg.Sites))
	}

	ch, cancel := c.Subscribe()
	defer cancel()

	rev2, err := c.Publish(twoSiteCfg(), "tester", "add site b")
	if err != nil {
		t.Fatal(err)
	}
	if rev2 != 2 {
		t.Fatalf("publish rev = %d", rev2)
	}
	cur, curCfg := c.Current()
	if cur != 2 || len(curCfg.Sites) != 2 {
		t.Fatalf("after publish: rev=%d sites=%d", cur, len(curCfg.Sites))
	}
	select {
	case got := <-ch:
		if got != 2 {
			t.Fatalf("subscriber got rev %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber not notified")
	}
}

func TestPublishInvalidRejected(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	bad := &config.Config{ListenHTTP: ":8080", Sites: []config.Site{{Domains: []string{}}}}
	if _, err := c.Publish(bad, "t", ""); err == nil {
		t.Fatal("invalid config accepted")
	}
	rev, cfg := c.Current()
	if rev != 1 || len(cfg.Sites) != 1 {
		t.Fatalf("current must be untouched after failed publish: rev=%d", rev)
	}
}

func TestRollbackAppendsNewRevision(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	if _, err := c.Publish(twoSiteCfg(), "t", "v2"); err != nil {
		t.Fatal(err)
	}
	rev3, err := c.Publish(seedCfg(), "t", "v3 back to one site")
	if err != nil {
		t.Fatal(err)
	}
	_ = rev3

	newRev, err := c.Rollback(1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if newRev != 4 {
		t.Fatalf("rollback revision = %d, want 4", newRev)
	}
	_, cfg := c.Current()
	if len(cfg.Sites) != 1 {
		t.Fatalf("rollback content wrong: sites=%d", len(cfg.Sites))
	}
}
