// Dashboard extensions: /api/stats/trend serves zero-filled time buckets
// for the attack trend chart (SQL aggregation on the SQLite store), and
// /api/stats gains the cumulative data-plane request counters read from the
// Prometheus registry.
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kingmoat/kingmoat/internal/logstore"
)

// trendResponse is the /api/stats/trend payload: buckets are aligned to
// epoch multiples of bucket_sec and fully zero-filled over the window so the
// console can chart them directly.
type trendResponse struct {
	Since     string                 `json:"since"`
	Until     string                 `json:"until"`
	BucketSec int                    `json:"bucket_sec"`
	Buckets   []logstore.TrendBucket `json:"buckets"`
}

// defaultBucketSec picks a bucket width that keeps the chart at a readable
// point count for the requested window.
func defaultBucketSec(hours int) int {
	switch {
	case hours <= 1:
		return 60
	case hours <= 6:
		return 300
	case hours <= 24:
		return 900
	default:
		return 3600
	}
}

// handleStatsTrend serves GET /api/stats/trend?hours=24&bucket_sec=900
// (hours: 1..168, bucket_sec optional; defaults are chosen per window).
func (s *Server) handleStatsTrend(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hours = n
		}
	}
	if hours < 1 {
		hours = 1
	}
	if hours > 168 {
		hours = 168
	}
	bucketSec := 0
	if v := r.URL.Query().Get("bucket_sec"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			bucketSec = n
		}
	}
	if bucketSec == 0 {
		bucketSec = defaultBucketSec(hours)
	}
	if bucketSec < 60 {
		bucketSec = 60
	}
	if bucketSec > 24*3600 {
		bucketSec = 24 * 3600
	}

	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)

	out := trendResponse{
		Since:     since.UTC().Format(time.RFC3339),
		Until:     until.UTC().Format(time.RFC3339),
		BucketSec: bucketSec,
		Buckets:   []logstore.TrendBucket{},
	}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	trender, ok := s.opts.Logs.(logstore.Trender)
	if !ok {
		writeJSON(w, http.StatusOK, out)
		return
	}
	_, cfg := s.opts.Center.Current()
	release, timeout, gated := s.auditQueryGate(cfg)
	if !gated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return
	}
	defer release()
	type trendResult struct {
		rows []logstore.TrendBucket
		err  error
	}
	done := make(chan trendResult, 1)
	go func() {
		rows, err := trender.Trend(since, until, bucketSec)
		done <- trendResult{rows, err}
	}()
	var rows []logstore.TrendBucket
	select {
	case res := <-done:
		if res.err != nil {
			writeErr(w, http.StatusInternalServerError, res.err)
			return
		}
		rows = res.rows
	case <-time.After(timeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{
			"error": "trend query timed out; narrow the window or ship logs to an external store",
		})
		return
	}

	byMs := make(map[int64]logstore.TrendBucket, len(rows))
	for _, b := range rows {
		prev, seen := byMs[b.BucketMs]
		if !seen {
			byMs[b.BucketMs] = b
			continue
		}
		for k, v := range b.ByAction {
			prev.ByAction[k] += v
		}
		byMs[b.BucketMs] = prev
	}
	bs := int64(bucketSec) * 1000
	start := since.UnixMilli() / bs * bs
	for ms := start; ms < until.UnixMilli(); ms += bs {
		b, seen := byMs[ms]
		if !seen {
			b = logstore.TrendBucket{BucketMs: ms, ByAction: map[string]int{}}
		}
		out.Buckets = append(out.Buckets, b)
	}
	writeJSON(w, http.StatusOK, out)
}
