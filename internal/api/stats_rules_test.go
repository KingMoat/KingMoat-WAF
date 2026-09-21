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
)

// newStatsRulesServer builds a control-plane API server over a fresh SQLite
// audit store (test helper for the /api/stats/rules handler tests).
func newStatsRulesServer(t *testing.T) (*Server, *logstore.SQLiteStore) {
	t.Helper()
	st, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(Options{SkipBootstrap: true, Center: mustCenter(t), Logs: st, Auth: NewAuth("")})
	return s, st
}

// TestStatsRulesClamp verifies hours/limit clamping (1..720 / 1..50) and the
// attack-event criteria through the handler: out-of-window, empty-rule and
// action-less events never count, and the top list is capped by the clamped
// limit while total stays unbounded.
func TestStatsRulesClamp(t *testing.T) {
	s, st := newStatsRulesServer(t)
	inWindow := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	beyondHours := time.Now().UTC().Add(-1000 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 55; i++ {
		st.Write(&logstore.Event{TS: inWindow, Action: "blocked", Rule: "crs/rule-" + string(rune('A'+i/26)) + string(rune('A'+i%26))})
	}
	st.Write(&logstore.Event{TS: beyondHours, Action: "blocked", Rule: "old/beyond-window"})
	st.Write(&logstore.Event{TS: inWindow, Action: "blocked"})
	st.Write(&logstore.Event{TS: inWindow, Rule: "crs/no-action"})
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	// hours=9999 clamps to 720 (out-of-window event excluded); limit=1000
	// clamps to 50 items; total remains unbounded by the item limit.
	rec := httptest.NewRecorder()
	s.handleStatsRules(rec, httptest.NewRequest("GET", "/api/stats/rules?hours=9999&limit=1000", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out struct {
		Total int64 `json:"total"`
		Items []struct {
			Rule  string `json:"rule"`
			Count int    `json:"count"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 55 {
		t.Fatalf("total = %d, want 55 (clamped 720h window, attack criteria)", out.Total)
	}
	if len(out.Items) != 50 {
		t.Fatalf("len(items) = %d, want 50 (limit clamp)", len(out.Items))
	}
	for _, it := range out.Items {
		if it.Rule == "old/beyond-window" {
			t.Fatalf("out-of-window rule must not appear: %+v", out.Items)
		}
	}

	// Defaults (no params): 24h window, limit 10.
	rec2 := httptest.NewRecorder()
	s.handleStatsRules(rec2, httptest.NewRequest("GET", "/api/stats/rules", nil))
	if rec2.Code != 200 {
		t.Fatalf("default status = %d", rec2.Code)
	}
	var def struct {
		Total int64 `json:"total"`
		Items []struct {
			Rule string `json:"rule"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &def); err != nil {
		t.Fatal(err)
	}
	if def.Total != 55 {
		t.Fatalf("default total = %d, want 55", def.Total)
	}
	if len(def.Items) != 10 {
		t.Fatalf("default len(items) = %d, want 10", len(def.Items))
	}
	// Ordering: top item carries the highest count (each rule has 1 hit, so
	// the tie-break is lexicographic: crs/rule-AA first).
	if def.Items[0].Rule != "crs/rule-AA" {
		t.Fatalf("items[0] = %q, want crs/rule-AA (count tie-break)", def.Items[0].Rule)
	}

	// Garbage params fall back to defaults instead of failing.
	rec3 := httptest.NewRecorder()
	s.handleStatsRules(rec3, httptest.NewRequest("GET", "/api/stats/rules?hours=abc&limit=-3", nil))
	if rec3.Code != 200 {
		t.Fatalf("garbage params status = %d", rec3.Code)
	}
}

// TestStatsRulesDegradedGate verifies the auditQueryGate degraded path: with
// the emergency switch on, the endpoint answers 503 + degraded=true instead
// of querying the store.
func TestStatsRulesDegradedGate(t *testing.T) {
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
	s.handleStatsRules(rec, httptest.NewRequest("GET", "/api/stats/rules", nil))
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

// TestStatsRulesNoStore verifies the empty payload shape when no log store is
// wired (static assemblies).
func TestStatsRulesNoStore(t *testing.T) {
	s := New(Options{SkipBootstrap: true, Center: mustCenter(t), Auth: NewAuth("")})
	rec := httptest.NewRecorder()
	s.handleStatsRules(rec, httptest.NewRequest("GET", "/api/stats/rules", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out struct {
		Total int64 `json:"total"`
		Items []struct {
			Rule string `json:"rule"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 0 || out.Items == nil {
		t.Fatalf("no-store payload = %+v, want total 0 and empty items", out)
	}
}
