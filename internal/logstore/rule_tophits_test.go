package logstore

import (
	"testing"
	"time"
)

// TestRuleTopHitsCriteria covers the attack-event criteria (action and rule
// must both be non-empty), the time window bounds, ordering and the TopN cap.
func TestRuleTopHitsCriteria(t *testing.T) {
	st, err := NewSQLiteStore(t.TempDir()+"/audit.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339Nano)
	events := []Event{
		{TS: ts, Action: "blocked", Rule: "crs/942100"},
		{TS: ts, Action: "blocked", Rule: "crs/942100"},
		{TS: ts, Action: "blocked", Rule: "crs/942100"},
		{TS: ts, Action: "challenged", Rule: "captcha/slider"},
		{TS: ts, Action: "challenged", Rule: "captcha/slider"},
		{TS: ts, Action: "monitor", Rule: "matcher/watch-only"},
		{TS: old, Action: "blocked", Rule: "geo/CN"},   // outside a 24h window
		{TS: ts, Action: "blocked"},                    // empty rule excluded
		{TS: ts, Rule: "crs/930100"},                   // empty action excluded
		{TS: ts, Action: "", Rule: ""},                 // fully empty excluded
	}
	for i := range events {
		st.Write(&events[i])
	}
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	until := time.Now()
	since := until.Add(-24 * time.Hour)

	hits, total, err := st.RuleTopHits(since, until, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 {
		t.Fatalf("total = %d, want 6 (in-window events with action+rule)", total)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits) = %d, want 2 (TopN cap)", len(hits))
	}
	if hits[0].Key != "crs/942100" || hits[0].Count != 3 {
		t.Fatalf("hits[0] = %+v, want crs/942100 x3", hits[0])
	}
	if hits[1].Key != "captcha/slider" || hits[1].Count != 2 {
		t.Fatalf("hits[1] = %+v, want captcha/slider x2", hits[1])
	}

	// A limit above the distinct-rule count returns every rule, ordered.
	all, totalAll, err := st.RuleTopHits(since, until, 50)
	if err != nil {
		t.Fatal(err)
	}
	if totalAll != 6 {
		t.Fatalf("totalAll = %d, want 6", totalAll)
	}
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3 distinct in-window rules", len(all))
	}
	if all[2].Key != "matcher/watch-only" || all[2].Count != 1 {
		t.Fatalf("all[2] = %+v, want matcher/watch-only x1", all[2])
	}
}

// TestRuleTopHitsEmptyStore ensures the zero-value shape: empty item list and
// zero total, never nil.
func TestRuleTopHitsEmptyStore(t *testing.T) {
	st, err := NewSQLiteStore(t.TempDir()+"/audit.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	until := time.Now()
	hits, total, err := st.RuleTopHits(until.Add(-time.Hour), until, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(hits) != 0 {
		t.Fatalf("empty store: total = %d, hits = %+v, want 0/empty", total, hits)
	}
}
