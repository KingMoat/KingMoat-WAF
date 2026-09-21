package logstore

import (
	"testing"
	"time"
)

func TestTrendBuckets(t *testing.T) {
	s := newTestStore(t)
	base := time.Now()
	s.Write(evAt(base.Add(-8*time.Minute), 0, "blocked", "a.example.com", "10.1.1.5", "r1", "/login"))
	s.Write(evAt(base.Add(-7*time.Minute), 0, "blocked", "a.example.com", "10.1.1.6", "r2", "/admin"))
	s.Write(evAt(base.Add(-7*time.Minute), 0, "challenged", "a.example.com", "10.1.1.7", "bot/challenge", "/"))
	s.Write(evAt(base.Add(-90*time.Second), 0, "blocked", "b.example.com", "10.2.0.1", "r1", "/x"))
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	until := base
	since := until.Add(-10 * time.Minute)
	buckets, err := s.Trend(since, until, 120)
	if err != nil {
		t.Fatalf("Trend: %v", err)
	}
	if len(buckets) == 0 {
		t.Fatal("expected non-empty trend buckets")
	}
	var blocked, challenged int
	for _, b := range buckets {
		if b.ByAction == nil {
			t.Fatalf("bucket %d has nil ByAction", b.BucketMs)
		}
		blocked += b.ByAction["blocked"]
		challenged += b.ByAction["challenged"]
		if b.BucketMs%120_000 != 0 {
			t.Fatalf("bucket %d not aligned to 120s", b.BucketMs)
		}
	}
	if blocked != 3 {
		t.Fatalf("blocked = %d, want 3", blocked)
	}
	if challenged != 1 {
		t.Fatalf("challenged = %d, want 1", challenged)
	}

	// Buckets are sorted ascending.
	for i := 1; i < len(buckets); i++ {
		if buckets[i].BucketMs <= buckets[i-1].BucketMs {
			t.Fatalf("buckets not sorted: %v then %v", buckets[i-1].BucketMs, buckets[i].BucketMs)
		}
	}

	// Inverted window is an error.
	if _, err := s.Trend(until, since, 60); err == nil {
		t.Fatal("inverted window should error")
	}
}
