package logstore

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), quietLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func evAt(base time.Time, offset time.Duration, action, site, ip, rule, path string) *Event {
	return &Event{
		TS:       base.Add(offset).Format(time.RFC3339Nano),
		Action:   action,
		Site:     site,
		ClientIP: ip,
		Method:   "GET",
		Path:     path,
		Rule:     rule,
		Reason:   "test",
	}
}

func TestSQLiteStoreWriteAndRecent(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-time.Hour)
	s.Write(evAt(base, 0, "blocked", "a.example.com", "10.1.1.5", "r1", "/login"))
	s.Write(evAt(base, 1, "monitor", "a.example.com", "10.1.1.5", "r1", "/login"))
	s.Write(evAt(base, 2, "blocked", "a.example.com", "10.1.1.6", "r2", "/admin"))
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	rec := s.Recent(2)
	if len(rec) != 2 {
		t.Fatalf("expected 2 events, got %d", len(rec))
	}
	if rec[0].Action != "blocked" || rec[0].Path != "/admin" {
		t.Fatalf("newest-first violated: %+v", rec[0])
	}
	if rec[1].Action != "monitor" {
		t.Fatalf("unexpected second event: %+v", rec[1])
	}
}

func TestSQLiteStoreAutoTimestamp(t *testing.T) {
	s := newTestStore(t)
	s.Write(&Event{Action: "blocked"})
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	rec := s.Recent(1)
	if len(rec) != 1 {
		t.Fatal("event lost")
	}
	if _, err := time.Parse(time.RFC3339Nano, rec[0].TS); err != nil {
		t.Fatalf("timestamp not auto-filled: %q", rec[0].TS)
	}
}

func TestSQLiteStoreQueryFilters(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-time.Hour)
	s.Write(evAt(base, 0, "blocked", "app.example.com", "203.0.113.7", "coraza/rule-942100", "/admin/login.php"))
	s.Write(evAt(base, 60*time.Second, "monitor", "app.example.com", "198.51.100.9", "", "/health"))
	s.Write(evAt(base, 120*time.Second, "challenged", "other.example.com", "203.0.113.7", "bot/challenge", "/"))
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		q    LogQuery
		want int
	}{
		{"action", LogQuery{Action: "blocked"}, 1},
		{"site substring", LogQuery{Site: "app.example"}, 2},
		{"ip prefix", LogQuery{SrcIP: "203.0.113."}, 2},
		{"rule substring", LogQuery{Rule: "942100"}, 1},
		{"fts path", LogQuery{Text: "login"}, 1},
		{"fts rule prefix", LogQuery{Text: "94210*"}, 1},
		{"window open", LogQuery{Since: base.Add(-time.Minute), Until: base.Add(-time.Second)}, 0},
		{"window inclusive", LogQuery{Since: base, Until: base}, 1},
		{"window all", LogQuery{Since: base.Add(-time.Minute), Until: base.Add(3 * time.Minute)}, 3},
	}
	for _, c := range cases {
		got, err := s.Query(c.q)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != c.want {
			t.Fatalf("%s: expected %d events, got %d", c.name, c.want, len(got))
		}
	}
}

func TestSQLiteStoreQueryLimit(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		s.Write(evAt(base, time.Duration(i)*time.Second, "blocked", "a.com", "10.0.0.1", "r", "/p"))
	}
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := s.Query(LogQuery{Action: "blocked", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0].TS == "" || got[0].TS < got[len(got)-1].TS {
		t.Fatalf("newest-first violated: %v", got)
	}
}

func TestSQLiteStoreAggregate(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.Write(evAt(now.Add(-2*time.Hour), 0, "blocked", "a.com", "10.0.0.1", "rule/x", "/a"))
	s.Write(evAt(now.Add(-2*time.Hour), 1, "blocked", "a.com", "10.0.0.2", "rule/x", "/b"))
	s.Write(evAt(now.Add(-2*time.Hour), 2, "monitor", "b.com", "10.0.0.3", "", "/c"))
	for i := 0; i < 22; i++ {
		s.Write(evAt(now.Add(-2*time.Hour), time.Duration(3+i)*time.Second, "blocked",
			"a.com", "10.9.9.9", "coraza/rule-920280", "/scan"))
	}
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	sum, err := s.Aggregate(now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 25 {
		t.Fatalf("total: expected 25, got %d", sum.Total)
	}
	if sum.ByAction["blocked"] != 24 || sum.ByAction["monitor"] != 1 {
		t.Fatalf("by_action: %+v", sum.ByAction)
	}
	if len(sum.TopRules) == 0 || sum.TopRules[0].Key != "coraza/rule-920280" {
		t.Fatalf("top rules: %+v", sum.TopRules)
	}
	if sum.SuspectedFP < 20 {
		t.Fatalf("suspected fp: %d", sum.SuspectedFP)
	}
	if sum.FirstTS == "" || sum.LastTS == "" {
		t.Fatal("first/last ts missing")
	}
}

func TestSQLiteStorePurge(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	old := evAt(now.Add(-48*time.Hour), 0, "blocked", "a.com", "10.0.0.1", "r", "/p")
	old.TS = now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
	s.Write(old)
	s.Write(evAt(now, 0, "blocked", "a.com", "10.0.0.1", "r", "/p"))
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	n, err := s.Purge(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purge, got %d", n)
	}
	if rec := s.Recent(10); len(rec) != 1 {
		t.Fatalf("expected 1 event after purge, got %d", len(rec))
	}
}

func TestSQLiteStoreOverflowDrops(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 20000; i++ {
		s.Write(&Event{Action: "blocked", Rule: "x"})
	}
	if s.Dropped() == 0 {
		t.Fatal("expected drops when queue overflows")
	}
}

func TestArchiverSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(filepath.Join(dir, "audit.db"), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Write(&Event{TS: time.Now().Add(-time.Hour).Format(time.RFC3339Nano),
		Action: "blocked", Path: "/x", Site: "a.com"})
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}

	archDir := filepath.Join(dir, "archive")
	a := NewArchiver(s, ArchiveOptions{Snapshot: true, Dir: archDir}, quietLogger())
	now := time.Now()
	if err := a.RunOnce(now); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	target := filepath.Join(archDir, "audit-"+now.AddDate(0, 0, -1).Format("20060102")+".db.gz")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	// Idempotent per day.
	if err := a.RunOnce(now); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	entries, _ := os.ReadDir(archDir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 archive file, got %d", len(entries))
	}

	// The snapshot must be a valid SQLite DB containing the event.
	gz, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	zr, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	snapPath := filepath.Join(dir, "snap.db")
	out, err := os.Create(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, zr); err != nil {
		t.Fatal(err)
	}
	out.Close()
	db, err := sql.Open("sqlite", "file:"+snapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event in snapshot, got %d", count)
	}
	var raw string
	if err := db.QueryRow(`SELECT raw FROM events LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var ev Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil || ev.Action != "blocked" {
		t.Fatalf("snapshot raw payload invalid: %q (%v)", raw, err)
	}
}

func TestArchiverRetentionAndPurge(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(filepath.Join(dir, "audit.db"), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	stale := &Event{TS: now.Add(-48 * time.Hour).Format(time.RFC3339Nano), Action: "blocked"}
	s.Write(stale)
	s.Write(evAt(now, 0, "blocked", "a.com", "10.0.0.1", "r", "/p"))
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}

	archDir := filepath.Join(dir, "archive")
	staleArch := filepath.Join(archDir, "audit-20200101.db.gz")
	if err := os.MkdirAll(archDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleArch, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewArchiver(s, ArchiveOptions{
		Snapshot: true, Dir: archDir,
		RetentionDays: 30, // prunes the 2020 fake snapshot
		PurgeDays:     1,  // purges the 48h-old event
	}, quietLogger())
	if err := a.RunOnce(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staleArch); !os.IsNotExist(err) {
		t.Fatal("stale archive not pruned")
	}
	if rec := s.Recent(10); len(rec) != 1 {
		t.Fatalf("expected 1 event after retention purge, got %d", len(rec))
	}
}
