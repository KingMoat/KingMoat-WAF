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
