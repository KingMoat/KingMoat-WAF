package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetDaily clears the shared daily-counter state so tests do not leak
// counts into each other (and registers a cleanup doing the same).
func resetDaily(t *testing.T) {
	t.Helper()
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)
}

// TestDailyReqIncRollover verifies the local-midnight rollover: when the
// cached day key no longer matches today, the live counters AND the
// recovered baseline are wiped before the new request is counted.
func TestDailyReqIncRollover(t *testing.T) {
	resetDaily(t)
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "forwarded")
	dailyBaseMu.Lock()
	dailyBase = map[string]int64{"c.local\x00forwarded": 9}
	dailyBaseMu.Unlock()

	if m := SnapshotDailyRequestsBySite(); m["a.local"] != 2 || m["c.local"] != 9 {
		t.Fatalf("pre-rollover snapshot wrong: %+v", m)
	}

	// Simulate a date change: pretend the live counters belong to yesterday.
	dailyDay.Store(localDayKey(time.Now().AddDate(0, 0, -1)))
	DailyReqInc("b.local", "blocked")

	m := SnapshotDailyRequestsBySite()
	if m["a.local"] != 0 || m["c.local"] != 0 {
		t.Fatalf("rollover must wipe live counters and baseline: %+v", m)
	}
	if m["b.local"] != 1 {
		t.Fatalf("post-rollover b.local = %d, want 1", m["b.local"])
	}
}

// TestLoadDailyRequestsBaseDateGate verifies that only a state file dated
// today (local time) is restored as the baseline; a file from a previous
// day (or a fresh start) contributes nothing.
func TestLoadDailyRequestsBaseDateGate(t *testing.T) {
	resetDaily(t)
	dir := t.TempDir()
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	write := func(name, date string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		b, err := json.Marshal(dailyReqState{Date: date, Counts: map[string]int64{"a.local\x00forwarded": 100}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	LoadDailyRequestsBase(write("today.json", today))
	if m := SnapshotDailyRequestsBySite(); m["a.local"] != 100 {
		t.Fatalf("today's base not restored: %+v", m)
	}

	resetDaily(t)
	LoadDailyRequestsBase(write("yesterday.json", yesterday))
	if m := SnapshotDailyRequestsBySite(); len(m) != 0 {
		t.Fatalf("stale base must be discarded: %+v", m)
	}
}

// TestDailyRequestsPersist verifies the flush loop merges baseline+live
// into the state file with today's date, so a restart within the same day
// carries the counts forward.
func TestDailyRequestsPersist(t *testing.T) {
	resetDaily(t)
	path := filepath.Join(t.TempDir(), "requests_daily.json")
	today := time.Now().Format("2006-01-02")
	b, err := json.Marshal(dailyReqState{Date: today, Counts: map[string]int64{"a.local\x00forwarded": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	LoadDailyRequestsBase(path)
	DailyReqInc("a.local", "forwarded")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartDailyRequestsPersist(ctx, path, 50*time.Millisecond)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)

	raw, err := os.ReadFile(path)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var st dailyReqState
	if err := json.Unmarshal(raw, &st); err != nil {
		cancel()
		t.Fatal(err)
	}
	// Stop the flush loop and wait for its final flush so the TempDir
	// cleanup never races a concurrent writer (Windows unlink).
	cancel()
	<-done
	if st.Date != today {
		t.Fatalf("persisted date = %q, want %q", st.Date, today)
	}
	if got := st.Counts["a.local\x00forwarded"]; got != 8 {
		t.Fatalf("persisted count = %d, want 8 (base 7 + live 1)", got)
	}
}

// TestSnapshotDailyRequestsBySiteMerge verifies the per-site aggregation:
// baseline and live counters sum across all outcome labels.
func TestSnapshotDailyRequestsBySiteMerge(t *testing.T) {
	resetDaily(t)
	dailyBaseMu.Lock()
	dailyBase = map[string]int64{
		"a.local\x00forwarded": 10,
		"a.local\x00blocked":   2,
		"b.local\x00forwarded": 5,
	}
	dailyBaseMu.Unlock()
	// Arm the day key so the next increment does not roll over (and wipe)
	// the manually seeded baseline, mirroring LoadDailyRequestsBase.
	dailyDay.Store(localDayKey(time.Now()))
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("c.local", "challenged")

	m := SnapshotDailyRequestsBySite()
	if m["a.local"] != 13 || m["b.local"] != 5 || m["c.local"] != 1 {
		t.Fatalf("merge wrong: %+v", m)
	}
}
