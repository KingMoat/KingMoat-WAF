package proxy

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// logSampler rate-limits per-request warning logs: within every one-second
// window the first `limit` messages pass, afterwards one in ten is still let
// through so sustained storms keep a visible trace. limit <= 0 disables
// sampling (every message passes). Audit records and the access log are NOT
// affected — this only throttles the runtime logger, which would otherwise
// serialize the hot path on slog's internal mutex during attack storms.
type logSampler struct {
	windowStart atomic.Int64 // unix seconds of the current window
	granted     atomic.Int64 // messages granted in the current window
	limit       int
}

func newLogSampler(limit int) *logSampler {
	return &logSampler{limit: limit}
}

// logSamplePerSecEnv is the per-second warning-log budget. Unset or 0 keeps
// the default; a negative value disables sampling entirely.
const logSamplePerSecEnv = "KINGMOAT_LOG_SAMPLE_PER_SEC"

func logSampleLimitFromEnv() int {
	raw := os.Getenv(logSamplePerSecEnv)
	if raw == "" {
		return 20
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 20
	}
	return n
}

func (s *logSampler) Allow() bool {
	if s == nil || s.limit < 0 {
		return true // disabled: everything passes
	}
	now := time.Now().Unix()
	start := s.windowStart.Load()
	if now != start {
		if s.windowStart.CompareAndSwap(start, now) {
			s.granted.Store(0)
		}
	}
	if s.limit == 0 {
		return true
	}
	n := s.granted.Add(1)
	if n <= int64(s.limit) {
		return true
	}
	// Sustained storm: keep a 1-in-10 trace flowing so operators still see
	// what the block pattern looks like without stalling the hot path.
	return n%10 == 0
}
