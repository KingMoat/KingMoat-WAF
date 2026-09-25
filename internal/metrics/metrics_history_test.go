package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRecordDailyHistoryFoldsAndPrunes verifies the per-day history fold:
// counters land on the day they belong to (yesterday after midnight), the
// same-day fold refreshes in place and days beyond the retention window
// are pruned.
func TestRecordDailyHistoryFoldsAndPrunes(t *testing.T) {
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)

	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("b.local", "blocked")

	yesterday := time.Now().AddDate(0, 0, -1)
	yKey := localDayKey(yesterday)
	// Simulate the post-midnight flush: the pending counters belong to
	// yesterday's day key.
	dailyDay.Store(yKey)
	recordDailyHistory(dayKeyString(yKey))

	hist := SnapshotRequestsHistory()
	yDate := yesterday.Format("2006-01-02")
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("yesterday fold wrong: %+v", hist[yDate])
	}

	// A day beyond retention is pruned on the next fold.
	old := time.Now().AddDate(0, 0, -(dailyHistoryRetention + 5))
	dailyHistoryMu.Lock()
	dailyHistory[old.Format("2006-01-02")] = map[string]int64{"forwarded": 9}
	dailyHistoryMu.Unlock()
	recordDailyHistory(time.Now().Format("2006-01-02"))
	hist = SnapshotRequestsHistory()
	if _, ok := hist[old.Format("2006-01-02")]; ok {
		t.Fatalf("stale day survived pruning: %+v", hist)
	}
	if h := hist[time.Now().Format("2006-01-02")]; h == nil || h["forwarded"] != 2 {
		t.Fatalf("today fold wrong: %+v", hist[time.Now().Format("2006-01-02")])
	}
}

// TestRolloverFoldsFinalCountsIntoHistory verifies that the request-side
// rollover folds the final counts into the previous day's history key before
// wiping the live counters, and that subsequent same-day folds (flushes) no
// longer overwrite that old day.
func TestRolloverFoldsFinalCountsIntoHistory(t *testing.T) {
	resetDaily(t)

	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "blocked")

	yDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	// Pretend the live counters belong to yesterday and let the next
	// request trigger the rollover.
	dailyDay.Store(localDayKey(time.Now().AddDate(0, 0, -1)))
	DailyReqInc("b.local", "challenged")

	hist := SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("rollover must fold final counts into history[%s]: %+v", yDate, hist[yDate])
	}

	// A later fold for the new day must not touch the old day.
	recordDailyHistory(time.Now().Format("2006-01-02"))
	hist = SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 2 || h["blocked"] != 1 {
		t.Fatalf("later fold must not overwrite history[%s]: %+v", yDate, hist[yDate])
	}
	if h := hist[time.Now().Format("2006-01-02")]; h == nil || h["challenged"] != 1 {
		t.Fatalf("post-rollover fold must land on today: %+v", hist[time.Now().Format("2006-01-02")])
	}
}

// TestFlushFoldKeepsYesterdayFinalCounts exercises the flush critical
// section (foldDailyAndRoll) on the post-midnight path: the pending counts
// belong to yesterday, and the fold-then-roll sequence must preserve them
// on yesterday's history key instead of overwriting it with the post-roll
// (empty) snapshot.
func TestFlushFoldKeepsYesterdayFinalCounts(t *testing.T) {
	resetDaily(t)

	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "challenged")
	yDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	dailyDay.Store(localDayKey(time.Now().AddDate(0, 0, -1)))

	foldDailyAndRoll()

	hist := SnapshotRequestsHistory()
	if h := hist[yDate]; h == nil || h["forwarded"] != 1 || h["challenged"] != 1 {
		t.Fatalf("flush must keep yesterday's final counts in history[%s]: %+v", yDate, hist[yDate])
	}
	if dailyDay.Load() != localDayKey(time.Now()) {
		t.Fatalf("day key not advanced: %d", dailyDay.Load())
	}
	if m := SnapshotDailyRequestsBySite(); len(m) != 0 {
		t.Fatalf("live counters must be reset after the rollover: %+v", m)
	}
}

// TestRequestsHistoryPersist verifies the flush writes the history file and
// LoadRequestsHistory restores it.
func TestRequestsHistoryPersist(t *testing.T) {
	ResetDailyForTest()
	t.Cleanup(ResetDailyForTest)

	dir := t.TempDir()
	DailyReqInc("a.local", "forwarded")
	DailyReqInc("a.local", "challenged")

	ctx, cancel := context.WithCancel(context.Background())
	histPath := filepath.Join(dir, "requests_history.json")
	done := make(chan struct{})
	go func() {
		StartDailyRequestsPersist(ctx, filepath.Join(dir, "requests_daily.json"), histPath, time.Hour)
		close(done)
	}()
	// The first flush runs synchronously at startup; give it a moment.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(histPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	b, err := os.ReadFile(histPath)
	if err != nil {
		t.Fatalf("history file missing: %v", err)
	}
	var onDisk map[string]map[string]int64
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	today := time.Now().Format("2006-01-02")
	if h := onDisk[today]; h == nil || h["forwarded"] != 1 || h["challenged"] != 1 {
		t.Fatalf("persisted history wrong: %+v", onDisk[today])
	}

	// A fresh process restores it from disk.
	ResetDailyForTest()
	LoadRequestsHistory(histPath)
	hist := SnapshotRequestsHistory()
	if h := hist[today]; h == nil || h["forwarded"] != 1 || h["challenged"] != 1 {
		t.Fatalf("restored history wrong: %+v", hist[today])
	}
}
