package logstore

import (
	"testing"
	"time"
)

// TestTopSourceIPsAttackCriteria verifies that the attack-origin aggregation
// matches the TypeDistribution criteria (action != '' AND rule != '') and
// excludes empty client_ip / out-of-window events, ordering by count desc.
func TestTopSourceIPsAttackCriteria(t *testing.T) {
	st, err := NewSQLiteStore(t.TempDir()+"/audit.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().Format(time.RFC3339Nano)
	old := time.Now().Add(-72 * time.Hour).Format(time.RFC3339Nano)
	evs := []*Event{
		{TS: now, Action: "blocked", Rule: "crs/942100", ClientIP: "1.1.1.1"},
		{TS: now, Action: "blocked", Rule: "crs/942100", ClientIP: "1.1.1.1"},
		{TS: now, Action: "blocked", Rule: "crs/942100", ClientIP: "1.1.1.1"},
		{TS: now, Action: "challenged", Rule: "crs/920100", ClientIP: "2.2.2.2"},
		{TS: now, Action: "challenged", Rule: "crs/920100", ClientIP: "2.2.2.2"},
		{TS: now, Action: "monitor", Rule: "crs/920280", ClientIP: "3.3.3.3"},
		// Excluded: missing rule (noise rows)
		{TS: now, Action: "blocked", Rule: "", ClientIP: "4.4.4.4"},
		{TS: now, Action: "blocked", Rule: "", ClientIP: "4.4.4.4"},
		// Excluded: empty action
		{TS: now, Action: "", Rule: "crs/930100", ClientIP: "5.5.5.5"},
		// Excluded: empty client_ip
		{TS: now, Action: "blocked", Rule: "crs/931100", ClientIP: ""},
		// Excluded: outside the 24h window
		{TS: old, Action: "blocked", Rule: "crs/942100", ClientIP: "6.6.6.6"},
	}
	for _, ev := range evs {
		st.Write(ev)
	}
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	since := time.Now().Add(-24 * time.Hour)
	until := time.Now().Add(time.Minute)
	hits, err := st.TopSourceIPs(since, until, 200)
	if err != nil {
		t.Fatal(err)
	}
	want := []TopHit{{Key: "1.1.1.1", Count: 3}, {Key: "2.2.2.2", Count: 2}, {Key: "3.3.3.3", Count: 1}}
	if len(hits) != len(want) {
		t.Fatalf("hits = %+v, want %+v", hits, want)
	}
	for i, w := range want {
		if hits[i] != w {
			t.Fatalf("hits[%d] = %+v, want %+v", i, hits[i], w)
		}
	}

	total, err := st.AttackTotal(since, until)
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 {
		t.Fatalf("total = %d, want 6 (3+2+1, noise/empty/out-of-window excluded)", total)
	}
}
