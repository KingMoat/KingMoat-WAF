package logstore

import (
	"path/filepath"
	"testing"
	"time"
)

// Regression for the disk-guard Phase-2 fix: OldestEventTime must read the
// ts_ms column (the schema has no ts column) and return the oldest live
// event regardless of write order; ok=false on an empty store.
func TestOldestEventTimeReturnsOldestLiveEvent(t *testing.T) {
	st, err := NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	if _, ok := st.OldestEventTime(); ok {
		t.Fatal("empty store: ok=true, want false")
	}

	base := time.Now().UTC().Add(-48 * time.Hour)
	for _, offset := range []time.Duration{24 * time.Hour, 0, 48 * time.Hour} {
		ev := &Event{
			TS:     base.Add(offset).Format(time.RFC3339Nano),
			Action: "blocked",
			Rule:   "r-1",
		}
		st.Write(ev)
	}

	// Write is batched (~0.5s flush); poll until the events become visible.
	var got time.Time
	var ok bool
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, ok = st.OldestEventTime()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("oldest event not visible after 5s (async batch not flushed)")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if d := got.Sub(base).Abs(); d > time.Minute {
		t.Fatalf("oldest=%v, want ~%v (drift %v)", got, base, d)
	}
}
