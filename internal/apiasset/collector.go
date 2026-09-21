package apiasset

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/botlib"
)

// AccessTick is one sampled observation emitted by the proxy after the
// upstream response completes. It carries no request bodies and no parameter
// values 鈥?only names 鈥?so the side-channel never persists user content.
type AccessTick struct {
	Site      string
	Method    string
	Path      string
	QueryKeys []string
	BodyKeys  []string
	Status    int
	RespCT    string
	RespBytes int64
	UA        string
	ClientIP  string
	TLS       bool
	HasAuth   bool
	BotClass  string
	TS        time.Time
}

// BruteForceFunc is invoked (throttled per key) when a login endpoint sees
// an IP exceed the failure threshold 鈥?the R3 hook.
type BruteForceFunc func(site, path, ip string, count int)

// Collector aggregates ticks in memory and periodically flushes to SQLite.
type Collector struct {
	store   *Store
	minHits int
	ch      chan AccessTick
	dropped chan struct{}
	logger  *slog.Logger
	nowFunc func() time.Time

	mu         sync.Mutex
	entries    map[string]*entry
	rfHits     map[respKey]int
	bruteforce *botlib.RateCounter
	onBrute    BruteForceFunc
	bruteSeen  map[string]time.Time
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
}

type respKey struct{ site, normPath, pattern string }

type entry struct {
	site, method, normPath string
	hits                   int64
	statusDist             map[string]int
	params                 map[string]int
	respCT                 map[string]int
	uaTop                  map[string]int
	authedCount            int64
	anonOK                 int64          // unauthenticated + 200/2xx
	publicHits             int64          // non-private source IP
	adminPublic            int64          // admin-tagged asset hit from a public IP
	sensitiveParams        map[string]int // R7 evidence (HTTP only)
	firstSeen, lastSeen    time.Time
}

const (
	tickQueueSize   = 4096
	flushInterval   = 30 * time.Second
	uaTopLimit      = 5
	bodyKeyMaxBytes = 64 << 10
	bruteWindowSec  = 300
	bruteThreshold  = 30
)

// NewCollector builds the collector; ticks must be fed via Submit.
func NewCollector(store *Store, minHits int, logger *slog.Logger) *Collector {
	if minHits <= 0 {
		minHits = 5
	}
	if logger == nil {
		logger = slog.Default()
	}
	c := &Collector{
		store:      store,
		minHits:    minHits,
		ch:         make(chan AccessTick, tickQueueSize),
		dropped:    make(chan struct{}, tickQueueSize),
		logger:     logger,
		entries:    map[string]*entry{},
		rfHits:     map[respKey]int{},
		bruteforce: botlib.NewRateCounter(bruteThreshold, bruteWindowSec*time.Second),
		bruteSeen:  map[string]time.Time{},
		nowFunc:    time.Now,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go c.loop()
	return c
}

// SetBruteForceHook registers the R3 realtime callback.
func (c *Collector) SetBruteForceHook(fn BruteForceFunc) {
	c.mu.Lock()
	c.onBrute = fn
	c.mu.Unlock()
}

// Submit enqueues a tick without ever blocking; drops are counted.
func (c *Collector) Submit(t AccessTick) {
	if t.TS.IsZero() {
		t.TS = c.nowFunc()
	}
	select {
	case c.ch <- t:
	default:
		select {
		case c.dropped <- struct{}{}:
		default:
		}
	}
}

// Dropped returns the number of ticks dropped under backpressure.
func (c *Collector) Dropped() int {
	return len(c.dropped)
}

// RespFilterHit records one observe-only sensitive-data detection (R1
// signal). The path is normalized; only pattern names are kept.
func (c *Collector) RespFilterHit(site, path, pattern string) {
	c.mu.Lock()
	c.rfHits[respKey{site, NormalizePath(path), pattern}]++
	c.mu.Unlock()
}

// FlushNow forces an immediate aggregation flush (risk engine "scan now").
func (c *Collector) FlushNow() { c.flush() }

// Close stops the flush loop, waits for the final flush and returns.
func (c *Collector) Close() error {
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
	return nil
}

func (c *Collector) loop() {
	defer close(c.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			c.flush()
			return
		case t := <-c.ch:
			c.ingest(&t)
		case <-ticker.C:
			c.flush()
		}
	}
}

func entryKey(site, method, normPath string) string {
	return site + "|" + method + "|" + normPath
}

func (c *Collector) ingest(t *AccessTick) {
	norm := NormalizePath(t.Path)
	key := entryKey(t.Site, t.Method, norm)
	isAdmin := false
	tags := ClassifyTags(norm)
	for _, tg := range tags {
		if tg == TagAdmin {
			isAdmin = true
		}
	}

	c.mu.Lock()
	e := c.entries[key]
	if e == nil {
		e = &entry{
			site: t.Site, method: t.Method, normPath: norm,
			statusDist: map[string]int{}, params: map[string]int{},
			respCT: map[string]int{}, uaTop: map[string]int{},
			sensitiveParams: map[string]int{},
			firstSeen:       t.TS, lastSeen: t.TS,
		}
		c.entries[key] = e
	}
	e.lastSeen = t.TS
	e.hits++
	if t.Status >= 100 && t.Status < 600 {
		e.statusDist[statusClass(t.Status)]++
	} else {
		e.statusDist["other"]++
	}
	if t.RespCT != "" {
		e.respCT[t.RespCT]++
	}
	if t.UA != "" {
		e.uaTop[shortUA(t.UA)]++
	}
	for _, k := range t.QueryKeys {
		e.params[k]++
	}
	for _, k := range t.BodyKeys {
		e.params[k]++
	}
	if t.HasAuth {
		e.authedCount++
	} else if t.Status >= 200 && t.Status < 300 {
		e.anonOK++
	}
	if !isPrivateIP(t.ClientIP) {
		e.publicHits++
		if isAdmin {
			e.adminPublic++
		}
	}
	if !t.TLS {
		for _, k := range t.QueryKeys {
			if sensitiveParamName(k) {
				e.sensitiveParams[k]++
			}
		}
		for _, k := range t.BodyKeys {
			if sensitiveParamName(k) {
				e.sensitiveParams[k]++
			}
		}
	}

	// R3 realtime brute-force detection on login endpoints.
	if IsLoginEndpoint(t.Method, norm) && !t.HasAuth {
		switch t.Status {
		case 401, 403, 429:
			bkey := t.Site + "|" + norm + "|" + t.ClientIP
			if c.bruteforce.Over(bkey) {
				if c.onBrute != nil {
					last := c.bruteSeen[bkey]
					if c.nowFunc().Sub(last) > 5*time.Minute {
						c.bruteSeen[bkey] = c.nowFunc()
						fn := c.onBrute
						c.mu.Unlock()
						fn(t.Site, norm, t.ClientIP, bruteThreshold)
						return
					}
				}
			}
		}
	}
	c.mu.Unlock()
}

// flush persists the aggregated entries: candidates below minHits, confirmed
// assets at or above.
func (c *Collector) flush() {
	c.mu.Lock()
	if len(c.entries) == 0 && len(c.rfHits) == 0 {
		c.mu.Unlock()
		return
	}
	flushed := c.entries
	c.entries = map[string]*entry{}
	rfFlushed := c.rfHits
	c.rfHits = map[respKey]int{}
	c.mu.Unlock()

	for k, n := range rfFlushed {
		if err := c.store.UpsertRespFilterHit(k.site, k.normPath, k.pattern, n); err != nil {
			c.logger.Error("apiasset: flush respfilter hit failed", "err", err)
		}
	}

	for _, e := range flushed {
		a := &Asset{
			Site: e.site, Method: e.method, NormPath: e.normPath,
			Tags: ClassifyTags(e.normPath),
			Hits: e.hits, StatusDist: e.statusDist,
			AuthedRatio: ratio(e.authedCount, e.hits),
			RespCT:      topK(e.respCT, 3), UATop: topK(e.uaTop, uaTopLimit),
			AnonOK: e.anonOK, PublicHits: e.publicHits, AdminPublic: e.adminPublic,
			Sensitive: e.sensitiveParams,
			FirstSeen: e.firstSeen, LastSeen: e.lastSeen,
		}
		a.Params = topKeys(e.params, 20)
		candidate := e.hits < int64(c.minHits)
		if err := c.store.UpsertAsset(a, candidate); err != nil {
			c.logger.Error("apiasset: flush asset failed", "err", err)
			continue
		}
		if !candidate {
			if _, err := c.store.PromoteCandidate(e.site, e.method, e.normPath); err != nil {
				// Not found in candidates is normal (already promoted).
				c.logger.Debug("apiasset: promote skipped", "path", e.normPath, "err", err)
			}
		}
	}
}

// Stats returns in-memory counters for the console.
func (c *Collector) Stats() (tracked int, dropped int) {
	c.mu.Lock()
	tracked = len(c.entries)
	c.mu.Unlock()
	return tracked, c.Dropped()
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return strconv.Itoa(status)
	case status >= 500:
		return "5xx"
	}
	return "other"
}

func shortUA(ua string) string {
	if len(ua) > 60 {
		return ua[:60]
	}
	return ua
}

func ratio(part, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func topK(m map[string]int, n int) map[string]int {
	if len(m) <= n {
		return m
	}
	// Simple selection: n is tiny.
	out := map[string]int{}
	for i := 0; i < n; i++ {
		bk, bv := "", -1
		for k, v := range m {
			if _, taken := out[k]; !taken && v > bv {
				bk, bv = k, v
			}
		}
		if bk == "" {
			break
		}
		out[bk] = bv
	}
	return out
}

func topKeys(m map[string]int, n int) []string {
	top := topK(m, n)
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	return keys
}

// IsPrivateIP reports whether the address falls in a private/loopback/
// link-local/CGNAT range (RFC1918 + shared address space). Exported for the
// geo attack-origin aggregation (private origins have no mmdb country).
func IsPrivateIP(ipStr string) bool { return isPrivateIP(ipStr) }

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	private := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	// CGNAT + shared ranges commonly used inside enterprises.
	if !private && ip.To4() != nil {
		oct := ip.To4()
		if oct[0] == 100 && oct[1] >= 64 && oct[1] <= 127 {
			private = true
		}
	}
	return private
}

func sensitiveParamName(name string) bool {
	l := strings.ToLower(name)
	for _, s := range []string{"password", "passwd", "pwd", "token", "secret", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}
