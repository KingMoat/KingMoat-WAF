// Package metrics holds the KingMoat data-plane counters and observability
// gauges as plain in-process atomics (no Prometheus client dependency):
// consumers are the console API (/api/stats, /api/host/stats) and the
// anomaly-alert engine. Hot-path Inc is lock-free for existing label keys.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
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

// rollDailyDay resets the live daily counters when the local calendar day
// has changed (first request or first persistence flush after local
// midnight). The unchanged-day path stays lock-free.
func rollDailyDay() {
	day := localDayKey(time.Now())
	if dailyDay.Load() == day {
		return
	}
	dailyDayMu.Lock()
	defer dailyDayMu.Unlock()
	rollDailyDayLocked(day)
}

// rollDailyDayLocked performs the rollover with dailyDayMu held: the final
// counts are folded into the previous day's history key before the live
// counters are dropped, so a request-side rollover no longer loses the last
// flush interval, and the fold cannot interleave with a concurrent flush's
// history-key selection (overwrite semantics make repeated folds idempotent).
func rollDailyDayLocked(day int64) {
	if dailyDay.Load() == day {
		return
	}
	if cur := dailyDay.Load(); cur != 0 {
		recordDailyHistoryLocked(dayKeyString(cur))
	}
	DailyRequestsTotal.resetAll()
	// The recovered baseline belongs to the previous day once the
	// clock crossed midnight; drop it along with the live counters.
	dailyBaseMu.Lock()
	dailyBase = nil
	dailyBaseMu.Unlock()
	dailyDay.Store(day)
}

// DailyReqInc counts one request for the per-site "today" card.
func DailyReqInc(site, outcome string) {
	rollDailyDay()
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

// foldDailyAndRoll folds the live daily counters into the per-day history
// and rolls the day forward as one critical section under dailyDayMu:
// right after local midnight the pending counts belong to the previous day
// and must land on that date, and the history-key selection and the counter
// read must not interleave with a concurrent rollover — a reset in between
// would make the fold overwrite the previous day's history with zeros.
func foldDailyAndRoll() {
	dailyDayMu.Lock()
	defer dailyDayMu.Unlock()
	histKey := time.Now().Format("2006-01-02")
	if cur := dailyDay.Load(); cur != 0 && cur != localDayKey(time.Now()) {
		histKey = dayKeyString(cur)
	}
	recordDailyHistoryLocked(histKey)
	rollDailyDayLocked(localDayKey(time.Now()))
}

// StartDailyRequestsPersist flushes baseline+live daily counters to the
// state file every interval and once on shutdown, until ctx is cancelled.
// When historyPath is non-empty the same flush also folds the counters into
// the per-day request history (dashboard time-range cards).
func StartDailyRequestsPersist(ctx context.Context, dailyPath, historyPath string, interval time.Duration) {
	if dailyPath == "" {
		return
	}
	flush := func() {
		foldDailyAndRoll()
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
		tmp := dailyPath + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, dailyPath)
		}
		if historyPath != "" {
			if hb, err := json.Marshal(SnapshotRequestsHistory()); err == nil {
				htmp := historyPath + ".tmp"
				if os.WriteFile(htmp, hb, 0o600) == nil {
					_ = os.Rename(htmp, historyPath)
				}
			}
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

// dailyHistoryRetention caps the per-day request history (days kept);
// 35 covers the widest dashboard range (30) plus headroom.
const dailyHistoryRetention = 35

var (
	dailyHistoryMu sync.RWMutex
	dailyHistory   = map[string]map[string]int64{} // date → outcome → count
)

// dayKeyString renders the YYYYMMDD day encoding as a date string.
func dayKeyString(cur int64) string {
	return fmt.Sprintf("%04d-%02d-%02d", cur/10000, (cur/100)%100, cur%100)
}

// recordDailyHistory folds the current daily counters (baseline+live,
// keyed site\x00outcome) into history[dayKey] by outcome and prunes days
// older than the retention window. The dailyDayMu round-trip keeps the
// standalone form safe for tests and future callers; the flush path uses
// recordDailyHistoryLocked under its own dailyDayMu hold.
func recordDailyHistory(dayKey string) {
	dailyDayMu.Lock()
	defer dailyDayMu.Unlock()
	recordDailyHistoryLocked(dayKey)
}

// recordDailyHistoryLocked is recordDailyHistory for callers already holding
// dailyDayMu: the counter read and the history overwrite must stay atomic
// relative to rollDailyDayLocked, or a midnight reset in between would be
// folded as an empty snapshot over the previous day's history.
func recordDailyHistoryLocked(dayKey string) {
	sums := map[string]int64{}
	dailyBaseMu.RLock()
	for k, v := range dailyBase {
		if parts := strings.SplitN(k, "\x00", 2); len(parts) == 2 {
			sums[parts[1]] += v
		}
	}
	dailyBaseMu.RUnlock()
	for k, v := range DailyRequestsTotal.Snapshot() {
		if parts := strings.SplitN(k, "\x00", 2); len(parts) == 2 {
			sums[parts[1]] += int64(v)
		}
	}
	dailyHistoryMu.Lock()
	dailyHistory[dayKey] = sums
	cutoff := time.Now().AddDate(0, 0, -dailyHistoryRetention).Format("2006-01-02")
	for d := range dailyHistory {
		if d < cutoff {
			delete(dailyHistory, d)
		}
	}
	dailyHistoryMu.Unlock()
}

// LoadRequestsHistory loads persisted per-day request totals (JSON map of
// date → outcome → count).
func LoadRequestsHistory(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var hist map[string]map[string]int64
	if json.Unmarshal(b, &hist) != nil || len(hist) == 0 {
		return
	}
	dailyHistoryMu.Lock()
	dailyHistory = hist
	dailyHistoryMu.Unlock()
}

// SnapshotRequestsHistory returns a copy of the per-day request history.
func SnapshotRequestsHistory() map[string]map[string]int64 {
	dailyHistoryMu.RLock()
	defer dailyHistoryMu.RUnlock()
	out := make(map[string]map[string]int64, len(dailyHistory))
	for d, m := range dailyHistory {
		cp := make(map[string]int64, len(m))
		for k, v := range m {
			cp[k] = v
		}
		out[d] = cp
	}
	return out
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

// ResetDailyForTest clears the shared daily-counter state (live counters,
// persisted-day baseline and the per-day request history). Test hook for
// consumer packages that share these process-global counters; pair with
// t.Cleanup.
func ResetDailyForTest() {
	DailyRequestsTotal.resetAll()
	dailyBaseMu.Lock()
	dailyBase = nil
	dailyBaseMu.Unlock()
	dailyDay.Store(0)
	dailyHistoryMu.Lock()
	dailyHistory = map[string]map[string]int64{}
	dailyHistoryMu.Unlock()
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
