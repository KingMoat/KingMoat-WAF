// Package metrics holds the KingMoat data-plane counters and observability
// gauges as plain in-process atomics (no Prometheus client dependency):
// consumers are the console API (/api/stats, /api/host/stats) and the
// anomaly-alert engine. Hot-path Inc is lock-free for existing label keys.
package metrics

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// counterVec is a tiny labeled counter: existing label combinations are
// incremented with a single atomic add; new combinations take the write lock
// once to create their cell.
type counterVec struct {
	mu   sync.RWMutex
	vals map[string]*atomic.Uint64
}

func (c *counterVec) cell(key string) *atomic.Uint64 {
	c.mu.RLock()
	if v, ok := c.vals[key]; ok {
		c.mu.RUnlock()
		return v
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.vals[key]; ok {
		return v
	}
	if c.vals == nil {
		c.vals = map[string]*atomic.Uint64{}
	}
	v := &atomic.Uint64{}
	c.vals[key] = v
	return v
}

func (c *counterVec) Inc(labels ...string) {
	c.cell(strings.Join(labels, "\x00")).Add(1)
}

// Sum returns the total across all label combinations.
func (c *counterVec) Sum() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sum uint64
	for _, v := range c.vals {
		sum += v.Load()
	}
	return float64(sum)
}

// Snapshot returns every label combination with its count.
func (c *counterVec) Snapshot() map[string]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]uint64, len(c.vals))
	for k, v := range c.vals {
		out[k] = v.Load()
	}
	return out
}

// gauge stores a float64 in an atomic uint64 (bit pattern); Set is called by
// slow background pollers only.
type gauge struct {
	bits atomic.Uint64
}

func (g *gauge) Set(v float64)      { g.bits.Store(math.Float64bits(v)) }
func (g *gauge) Get() float64       { return math.Float64frombits(g.bits.Load()) }

// Data-plane request counters.
var (
	RequestsTotal    = &counterVec{} // labels: site, outcome
	StageHits        = &counterVec{} // labels: stage
	UpstreamErrors   = &counterVec{} // labels: site
	Reloads          = &counterVec{} // labels: outcome
	BotRequestsTotal = &counterVec{} // labels: site, class
	BotDeniedTotal   = &counterVec{} // labels: site
	BotChallengedTotal = &counterVec{} // labels: site
)

// Observability gauges (set by the 15s poller in the entrypoint).
var (
	AuditDropped         gauge
	AuditQueueDepth      gauge
	AccessLogDropped     gauge
	AccessLogQueueDepth  gauge
	LogShipperDropped    gauge
	LogShipperQueueDepth gauge
)

// SnapshotRequests sums RequestsTotal by outcome label (forwarded / blocked /
// challenged / redirected / monitor_forwarded) for the console dashboard.
// The result INCLUDES the persisted base loaded by LoadRequestsBase, so the
// dashboard's cumulative counters survive process restarts.
func SnapshotRequests() map[string]int64 {
	live := map[string]int64{}
	for key, v := range RequestsTotal.Snapshot() {
		parts := strings.Split(key, "\x00")
		outcome := parts[len(parts)-1]
		live[outcome] += int64(v)
	}
	reqBaseMu.RLock()
	defer reqBaseMu.RUnlock()
	if len(reqBase) == 0 {
		return live
	}
	out := make(map[string]int64, len(live)+len(reqBase))
	for k, v := range reqBase {
		out[k] += v
	}
	for k, v := range live {
		out[k] += v
	}
	return out
}

// Persisted cumulative request counters: the live in-process counters reset
// on restart, so the dashboard's cumulative card would drop to zero. The
// base is loaded from a small JSON state file at boot and re-flushed
// periodically (base + live), making the displayed total monotonic across
// restarts (at most one persist-interval of hard-kill loss).
var (
	reqBaseMu    sync.RWMutex
	reqBase      map[string]int64
	reqStatePath string
)

// LoadRequestsBase loads the persisted cumulative counters as the display
// baseline. Missing/corrupt file = fresh start (no base).
func LoadRequestsBase(path string) {
	reqStatePath = path
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return
	}
	reqBaseMu.Lock()
	reqBase = m
	reqBaseMu.Unlock()
}

// StartRequestsPersist flushes base+live to the state file every interval
// and once on shutdown, until ctx is cancelled.
func StartRequestsPersist(ctx context.Context, path string, interval time.Duration) {
	if path == "" {
		return
	}
	reqStatePath = path
	flush := func() {
		m := SnapshotRequests()
		b, err := json.Marshal(m)
		if err != nil {
			return
		}
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	flush()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-t.C:
			flush()
		}
	}
}

// Daily per-site request counters feed /api/stats/per-site ("requests
// today" per site). Unlike RequestsTotal these reset at local midnight and
// persist per day: the state file carries the calendar date, so a restart
// only restores counts that belong to today.
var (
	DailyRequestsTotal = &counterVec{} // labels: site, outcome
	dailyDay           atomic.Int64    // local calendar day of the live counters, encoded as YYYYMMDD
	dailyDayMu         sync.Mutex
	dailyBaseMu        sync.RWMutex
	dailyBase          map[string]int64
)

// resetAll drops every live counter cell (daily rollover). Increments that
// raced the reset may add into a discarded cell and are lost, matching the
// accepted at-boundary drift of the other counters.
func (c *counterVec) resetAll() {
	c.mu.Lock()
	c.vals = nil
	c.mu.Unlock()
}

// localDayKey encodes a time's local calendar date as a comparable number
// (e.g. 20260923) so the hot path compares ints instead of formatting date
// strings per request.
func localDayKey(t time.Time) int64 {
	return int64(t.Year())*10000 + int64(t.Month())*100 + int64(t.Day())
}

// DailyReqInc counts one request for the per-site "today" card. The live
// counters roll over (reset to zero) on the first request after local
// midnight; the unchanged-day path stays lock-free.
func DailyReqInc(site, outcome string) {
	day := localDayKey(time.Now())
	if dailyDay.Load() != day {
		dailyDayMu.Lock()
		if dailyDay.Load() != day {
			DailyRequestsTotal.resetAll()
			// The recovered baseline belongs to the previous day once the
			// clock crossed midnight; drop it along with the live counters.
			dailyBaseMu.Lock()
			dailyBase = nil
			dailyBaseMu.Unlock()
			dailyDay.Store(day)
		}
		dailyDayMu.Unlock()
	}
	DailyRequestsTotal.Inc(site, outcome)
}

// dailyReqState is the persisted per-day state file shape.
type dailyReqState struct {
	Date   string           `json:"date"`
	Counts map[string]int64 `json:"counts"`
}

// LoadDailyRequestsBase loads the persisted daily counters as the baseline,
// but only when the state file belongs to today (local time); a file from a
// previous day is discarded so "today" never mixes in stale counts.
func LoadDailyRequestsBase(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st dailyReqState
	if json.Unmarshal(b, &st) != nil || len(st.Counts) == 0 {
		return
	}
	if st.Date != time.Now().Format("2006-01-02") {
		return
	}
	dailyBaseMu.Lock()
	dailyBase = st.Counts
	dailyBaseMu.Unlock()
	// Arm the day key so the first request does not trigger a rollover
	// that would immediately wipe the just-restored baseline.
	dailyDay.Store(localDayKey(time.Now()))
}

// StartDailyRequestsPersist flushes baseline+live daily counters to the
// state file every interval and once on shutdown, until ctx is cancelled.
func StartDailyRequestsPersist(ctx context.Context, path string, interval time.Duration) {
	if path == "" {
		return
	}
	flush := func() {
		st := dailyReqState{Date: time.Now().Format("2006-01-02"), Counts: map[string]int64{}}
		dailyBaseMu.RLock()
		for k, v := range dailyBase {
			st.Counts[k] += v
		}
		dailyBaseMu.RUnlock()
		for k, v := range DailyRequestsTotal.Snapshot() {
			st.Counts[k] += int64(v)
		}
		b, err := json.Marshal(st)
		if err != nil {
			return
		}
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	flush()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-t.C:
			flush()
		}
	}
}

// SnapshotDailyRequestsBySite sums the persisted baseline and the live daily
// counters per site label (all outcomes), for /api/stats/per-site. Empty
// site labels (no_site rows) are kept here; the API merge step filters them.
func SnapshotDailyRequestsBySite() map[string]int64 {
	out := map[string]int64{}
	for key, v := range DailyRequestsTotal.Snapshot() {
		site := strings.SplitN(key, "\x00", 2)[0]
		out[site] += int64(v)
	}
	dailyBaseMu.RLock()
	defer dailyBaseMu.RUnlock()
	for key, v := range dailyBase {
		site := strings.SplitN(key, "\x00", 2)[0]
		out[site] += v
	}
	return out
}

// SortedKeys returns the counter's label keys in stable order (tests/debug).
func (c *counterVec) SortedKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
