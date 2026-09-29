package stages

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func geoCapture(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func geoCfg(dbPath string, blacklist, whitelist []string) *config.Config {
	return &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9"}}},
			Security: &config.SecuritySettings{
				Geo: &config.GeoSettings{
					Enabled:   true,
					DBPath:    dbPath,
					Blacklist: blacklist,
					Whitelist: whitelist,
				},
			},
		}},
	}
}

func geoRun(t *testing.T, g *Geo, domain string) pipeline.Verdict {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+domain+"/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: domain},
		Values:  map[string]any{},
	}
	return g.Inspect(context.Background(), rc)
}

func geoWarnCount(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "geo: configured but engine missing")
}

// TestGeoEngineMissingWarnRateLimited pins the fail-open guard: a domain the
// config declared geo-enabled but the running engine lost (stale engine kept
// alive by a failed hot-reload) must never pass silently. Requests stay
// allowed (alerting only, no false positives) and the warning is capped at
// one per domain per interval.
func TestGeoEngineMissingWarnRateLimited(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.warnEvery = 50 * time.Millisecond
	delete(g.byDomain, "t.local") // simulate engine/config desync

	for i := 0; i < 5; i++ {
		if v := geoRun(t, g, "t.local"); v.Action != pipeline.ActionAllow {
			t.Fatalf("engine-missing request must not be blocked: %+v", v)
		}
	}
	if n := geoWarnCount(&buf); n != 1 {
		t.Fatalf("warnings within window = %d, want 1\nlog:\n%s", n, buf.String())
	}

	time.Sleep(60 * time.Millisecond)
	geoRun(t, g, "t.local")
	if n := geoWarnCount(&buf); n != 2 {
		t.Fatalf("warnings after window = %d, want 2 (rate limit must be per-window, not once-ever)\nlog:\n%s", n, buf.String())
	}
}

// TestGeoEngineMissingNotWarnedForPlainSites pins the negative half of the
// guard: domains without geo in the config must stay silent (no warning
// noise for the majority of sites).
func TestGeoEngineMissingNotWarnedForPlainSites(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	delete(g.byDomain, "t.local")

	if v := geoRun(t, g, "other.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("non-geo site request must pass: %+v", v)
	}
	if n := geoWarnCount(&buf); n != 0 {
		t.Fatalf("warnings for non-geo site = %d, want 0\nlog:\n%s", n, buf.String())
	}
}

// TestGeoNormalMappingUnaffected is the regression for correctly mapped
// sites: lookups still run, verdicts are unchanged by the guard, domain
// matching stays case-insensitive, and no engine-missing warning fires.
// "ZZ" is not a valid ISO code, so it never matches a lookup result: the
// blacklist case deterministically allows and the whitelist case
// deterministically denies.
func TestGeoNormalMappingUnaffected(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", []string{"ZZ"}, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if !g.configured["t.local"] || g.byDomain["t.local"] == nil {
		t.Fatal("configured/byDomain must both contain the geo site after build")
	}
	if v := geoRun(t, g, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("blacklist miss must allow: %+v", v)
	}
	// Case-insensitive domain matching (pre-existing behavior).
	if v := geoRun(t, g, "T.Local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("case-insensitive domain must still map: %+v", v)
	}
	if n := geoWarnCount(&buf); n != 0 {
		t.Fatalf("engine-missing warnings for mapped site = %d, want 0\nlog:\n%s", n, buf.String())
	}

	// Whitelist mode regression: unknown countries denied with the
	// pre-existing rule identifier.
	gw, err := NewGeo(geoCfg("", nil, []string{"ZZ"}), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	v := geoRun(t, gw, "t.local")
	if v.Action != pipeline.ActionDeny || v.Rule != "geo/not_whitelisted" {
		t.Fatalf("whitelist miss must deny with geo/not_whitelisted: %+v", v)
	}
}

// TestGeoEmptyDBPathUsesEmbeddedAndSurvivesClose pins the embedded-database
// contract: an empty db_path builds against the geoip.Reader() singleton and
// keeps working after the engine is closed — a successful hot-reload closes
// the previous engine, and the singleton must survive it (closing it silently
// broke every lookup in the new engine; production-verified).
func TestGeoEmptyDBPathUsesEmbeddedAndSurvivesClose(t *testing.T) {
	g, err := NewGeo(geoCfg("", nil, nil), quiet())
	if err != nil {
		t.Fatalf("empty db_path must build against the embedded database: %v", err)
	}
	if g.byDomain["t.local"].db != geoip.Reader() {
		t.Fatal("empty db_path must use the geoip.Reader() singleton")
	}

	// Simulate the hot-reload swap: previous engine closed, lookup must
	// still work for the next engine built from the same singleton.
	if err := g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	g2, err := NewGeo(geoCfg("", []string{"ZZ"}, nil), quiet())
	if err != nil {
		t.Fatalf("rebuild after close: %v", err)
	}
	defer g2.Close()
	if v := geoRun(t, g2, "t.local"); v.Action != pipeline.ActionAllow {
		t.Fatalf("lookup after engine close must still work (embedded db closed?): %+v", v)
	}
}

// TestGeoBuildWarnsWhenNoUsableDomains pins the defensive build-time warning:
// a geo-enabled site whose domain list is empty (or blank) can never be
// evaluated and must not stay silent.
func TestGeoBuildWarnsWhenNoUsableDomains(t *testing.T) {
	var buf bytes.Buffer
	cfg := geoCfg("", nil, nil)
	cfg.Sites[0].Domains = []string{"", "   "}
	g, err := NewGeo(cfg, geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if len(g.byDomain) != 0 {
		t.Fatalf("blank domains must not enter byDomain, got %d", len(g.byDomain))
	}
	if !strings.Contains(buf.String(), "no usable domains") {
		t.Fatalf("build must warn about unusable domains\nlog:\n%s", buf.String())
	}
}

// TestGeoCustomPathMissingFailsStatic is the regression for the pre-existing
// fail-static contract: a configured db_path that cannot be opened fails the
// build instead of degrading silently.
func TestGeoCustomPathMissingFailsStatic(t *testing.T) {
	if _, err := NewGeo(geoCfg(t.TempDir()+`\missing.mmdb`, nil, nil), quiet()); err == nil {
		t.Fatal("missing custom mmdb must fail the build (fail-static)")
	}
}
