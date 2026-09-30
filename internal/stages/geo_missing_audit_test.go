package stages

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestGeoEngineMissingFlagFollowsWarnRateLimit pins the side channel the
// proxy audit consumer reads (rc.Values["geo_engine_missing"]): it is set
// exactly when a warning fires and obeys the same rate limit, so the audit
// trail stays visible without flooding the audit store on a hot path.
func TestGeoEngineMissingFlagFollowsWarnRateLimit(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.warnEvery = 50 * time.Millisecond
	delete(g.byDomain, "t.local") // defensive-path simulation: unreachable in production builds, deleted here to exercise the sentinel logic

	run := func() *pipeline.RequestContext {
		t.Helper()
		r := httptest.NewRequest("GET", "http://t.local/", nil)
		r.RemoteAddr = "9.9.9.9:1234"
		rc := &pipeline.RequestContext{
			Request: r,
			Site:    pipeline.SiteView{Domain: "t.local"},
			Values:  map[string]any{},
		}
		if v := g.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
			t.Fatalf("engine-missing request must not be blocked: %+v", v)
		}
		return rc
	}

	rc := run()
	if rc.Values["geo_engine_missing"] != true {
		t.Fatalf("first flagged request must carry geo_engine_missing, got %v", rc.Values["geo_engine_missing"])
	}

	rc = run() // inside the warn window: rate-limited, no flag
	if _, ok := rc.Values["geo_engine_missing"]; ok {
		t.Fatal("rate-limited request must NOT carry the flag (the audit trail would flood)")
	}

	time.Sleep(60 * time.Millisecond)
	rc = run()
	if rc.Values["geo_engine_missing"] != true {
		t.Fatal("flag must return after the warn window")
	}
}

// TestGeoEngineMissingFlagNotSetForPlainSites pins the negative half: a
// site without geo in the config never gets the flag (and never warns).
func TestGeoEngineMissingFlagNotSetForPlainSites(t *testing.T) {
	var buf bytes.Buffer
	g, err := NewGeo(geoCfg("", nil, nil), geoCapture(&buf))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	delete(g.byDomain, "t.local") // defensive-path simulation (same as above); requests below target a plain non-geo domain and must stay unflagged

	r := httptest.NewRequest("GET", "http://other.local/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: "other.local"},
		Values:  map[string]any{},
	}
	if v := g.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
		t.Fatalf("non-geo site request must pass: %+v", v)
	}
	if _, ok := rc.Values["geo_engine_missing"]; ok {
		t.Fatal("non-geo site must not carry the engine-missing flag")
	}
}
