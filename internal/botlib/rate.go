package botlib

import (
	"sync"
	"time"
)

// RateCounter tracks per-fingerprint request counts in sliding windows,
// sharded to keep the lock contention low on hot paths.
type RateCounter struct {
	shards  [shardCount]*rateShard
	window  time.Duration
	quota   int
	nowFunc func() time.Time
}

const shardCount = 16

type rateShard struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

// NewRateCounter builds a counter with the given quota per sliding window.
func NewRateCounter(quota int, window time.Duration) *RateCounter {
	if window <= 0 {
		window = time.Minute
	}
	rc := &RateCounter{window: window, quota: quota, nowFunc: time.Now}
	for i := range rc.shards {
		rc.shards[i] = &rateShard{buckets: map[string][]time.Time{}}
	}
	return rc
}

// Over records one hit for key and reports whether the key is over the quota
// within the window.
func (rc *RateCounter) Over(key string) bool {
	now := rc.nowFunc()
	shard := rc.shards[keyHash(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	ts := shard.buckets[key]
	// Drop expired samples from the front.
	cutoff := now.Add(-rc.window)
	i := 0
	for ; i < len(ts) && ts[i].Before(cutoff); i++ {
	}
	ts = append(ts[i:], now)
	shard.buckets[key] = ts
	return len(ts) > rc.quota
}

// Count returns the current in-window hit count for key.
func (rc *RateCounter) Count(key string) int {
	now := rc.nowFunc()
	shard := rc.shards[keyHash(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	ts := shard.buckets[key]
	cutoff := now.Add(-rc.window)
	n := 0
	for _, t := range ts {
		if !t.Before(cutoff) {
			n++
		}
	}
	return n
}

func keyHash(k string) int {
	if len(k) == 0 {
		return 0
	}
	h := 0
	for i := 0; i < len(k); i++ {
		h = h*31 + int(k[i])
	}
	if h < 0 {
		h = -h
	}
	return h % shardCount
}
