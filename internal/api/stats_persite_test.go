package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/metrics"
)

type perSiteRow struct {
	Site     string `json:"site"`
	Requests int64  `json:"requests"`
	Attacks  int    `json:"attacks"`
}

type perSitePayload struct {
	WindowStart string       `json:"window_start"`
	WindowEnd   string       `json:"window_end"`
	Sites       []perSiteRow `json:"sites"`
}

// newPerSiteServer builds a control-plane API server over a fresh SQLite
// audit store, with an extra zero-traffic configured site (quiet.local) so
// the zero-fill merge path is observable.
func newPerSiteServer(t *testing.T) (*Server, *logstore.SQLiteStore) {
	t.Helper()
	st, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := seedCfg()
	cfg.Sites = append(cfg.Sites, config.Site{
		Domains:  []string{"quiet.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9002"}}},
	})
	center, err := configcenter.Open(t.TempDir()+"/cert.db", cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	s := New(Options{SkipBootstrap: true, Center: center, Logs: st, Auth: NewAuth("")})
	return s, st
}

// TestStatsPerSiteMergesAuditAndMetrics verifies the merge contract: audit
// attack counts (attack criteria, window-bounded) and daily metrics request
// counts both land in the payload, configured sites are zero-filled, no_site
// rows are skipped and rows sort by requests desc then site asc.
func TestStatsPerSiteMergesAuditAndMetrics(t *testing.T) {
	s, st := newPerSiteServer(t)
	now := time.Now()
	// Events must land inside the handler's "today" window (local midnight to
	// now): use the midpoint of the elapsed day — now-1h belongs to yesterday
	// right after local midnight, which made this test fail between 00:00 and
	// 01:00 (midnight-flaky).
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	ts := dayStart.Add(now.Sub(dayStart) / 2).Format(time.RFC3339Nano)
	events := []logstore.Event{
		{TS: ts, Site: "a.local", Action: "blocked", Rule: "crs/942100"},
		{TS: ts, Site: "a.local", Action: "challenged", Rule: "bot/bad"},
		{TS: ts, Site: "a.local", Action: "blocked"},                                                                      // no rule: not an attack
		{TS: ts, Action: "blocked", Rule: "crs/942100"},                                                                   // no_site: skipped
		{TS: now.Add(-72 * time.Hour).Format(time.RFC3339Nano), Site: "old.local", Action: "blocked", Rule: "crs/942100"}, // out of window
	}
	for i := range events {
		st.Write(&events[i])
	}
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	// Daily metrics: two requests for c.local (unconfigured site), one for
	// a.local; an empty site label (no_site) must be skipped.
	metrics.DailyReqInc("c.local", "forwarded")
	metrics.DailyReqInc("c.local", "blocked")
	metrics.DailyReqInc("a.local", "forwarded")
	metrics.DailyReqInc("", "forwarded")

	rec := httptest.NewRecorder()
	s.handleStatsPerSite(rec, httptest.NewRequest("GET", "/api/stats/per-site", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out perSitePayload
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sites) != 3 {
		t.Fatalf("len(sites) = %d, want 3 (a.local, c.local, quiet.local): %+v", len(out.Sites), out.Sites)
	}
	bySite := map[string]perSiteRow{}
	for _, it := range out.Sites {
		bySite[it.Site] = it
	}
	if a := bySite["a.local"]; a.Site == "" || a.Requests != 1 || a.Attacks != 2 {
		t.Fatalf("a.local wrong: %+v (want requests=1, attacks=2)", a)
	}
	if c := bySite["c.local"]; c.Site == "" || c.Requests != 2 || c.Attacks != 0 {
		t.Fatalf("c.local wrong: %+v (want requests=2, attacks=0)", c)
	}
	// Zero-fill: quiet.local is configured but has no traffic or attacks.
	if q := bySite["quiet.local"]; q.Site == "" || q.Requests != 0 || q.Attacks != 0 {
		t.Fatalf("quiet.local wrong: %+v (want zero-filled)", q)
	}
	// old.local (out-of-window) and the no_site row must not appear.
	for _, it := range out.Sites {
		if it.Site == "old.local" || it.Site == "" {
			t.Fatalf("unexpected site row %q: %+v", it.Site, out.Sites)
		}
	}
	// Ordering: requests desc, then site asc → c.local (2), a.local (1),
	// quiet.local (0).
	if out.Sites[0].Site != "c.local" || out.Sites[1].Site != "a.local" {
		t.Fatalf("ordering wrong: %+v", out.Sites)
	}
	// Window: local midnight to now.
	if ws, err := time.Parse(time.RFC3339, out.WindowStart); err != nil || !ws.Equal(dayStart) {
		t.Fatalf("window_start = %q, want local midnight %s", out.WindowStart, dayStart.Format(time.RFC3339))
	}
}

// TestStatsPerSiteDegradedGate verifies the auditQueryGate degraded path:
// with the emergency switch on, the endpoint answers 503 + degraded=true.
func TestStatsPerSiteDegradedGate(t *testing.T) {
	st, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	center, err := configcenter.Open(t.TempDir()+"/cert.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	degraded := true
	next := seedCfg()
	next.AuditQuery = &config.AuditQuerySettings{Degraded: &degraded}
	if _, err := center.Publish(next, "test", "degrade queries"); err != nil {
		t.Fatal(err)
	}
	s := New(Options{SkipBootstrap: true, Center: center, Logs: st, Auth: NewAuth("")})

	rec := httptest.NewRecorder()
	s.handleStatsPerSite(rec, httptest.NewRequest("GET", "/api/stats/per-site", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (degraded)", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["degraded"] != true {
		t.Fatalf("degraded flag missing: %+v", out)
	}
}

// TestStatsPerSiteNoStore verifies the empty payload shape when no log
// store is wired (static assemblies).
func TestStatsPerSiteNoStore(t *testing.T) {
	s := New(Options{SkipBootstrap: true, Center: mustCenter(t), Auth: NewAuth("")})
	rec := httptest.NewRecorder()
	s.handleStatsPerSite(rec, httptest.NewRequest("GET", "/api/stats/per-site", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out perSitePayload
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sites) != 0 {
		t.Fatalf("no-store payload = %+v, want empty sites", out)
	}
}
