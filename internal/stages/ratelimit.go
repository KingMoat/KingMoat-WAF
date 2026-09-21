package stages

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// RateLimit is the per-site CC protection stage: fixed-window counters keyed
// by client IP (or IP+URI). A sweeper goroutine evicts expired buckets;
// Close() stops it (invoked by the proxy on config hot-reload).
type RateLimit struct {
	byDomain map[string]*rlSite
	logger   *slog.Logger
	stop     chan struct{}
	stopOnce sync.Once
}

type rlSite struct {
	requests int
	window   time.Duration
	keyURI   bool
	deny     bool // true → 403, false → 429
	buckets  sync.Map
}

type rlBucket struct {
	mu    sync.Mutex
	start time.Time
	count int
}

// NewRateLimit builds the stage; sites without ratelimit config are skipped.
func NewRateLimit(cfg *config.Config, logger *slog.Logger) (*RateLimit, error) {
	if logger == nil {
		logger = slog.Default()
	}
	rl := &RateLimit{
		byDomain: make(map[string]*rlSite),
		logger:   logger,
		stop:     make(chan struct{}),
	}
	maxWindow := time.Minute
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.RateLimit == nil {
			continue
		}
		rs := s.Security.RateLimit
		window := time.Duration(rs.WindowSec) * time.Second
		if window <= 0 {
			window = time.Minute
		}
		site := &rlSite{
			requests: rs.Requests,
			window:   window,
			keyURI:   rs.Key == "ip+uri",
			deny:     rs.Action != "throttle",
		}
		for _, d := range s.Domains {
			rl.byDomain[strings.ToLower(strings.TrimSpace(d))] = site
		}
		if window > maxWindow {
			maxWindow = window
		}
	}
	if len(rl.byDomain) > 0 {
		go rl.sweeper(maxWindow)
	}
	return rl, nil
}

// sweeper periodically drops buckets idle for two windows, bounding memory.
func (rl *RateLimit) sweeper(maxWindow time.Duration) {
	t := time.NewTicker(maxWindow * 2)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case now := <-t.C:
			rl.byDomainRange(func(site *rlSite) {
				site.buckets.Range(func(key, value any) bool {
					b := value.(*rlBucket)
					b.mu.Lock()
					expired := now.Sub(b.start) > site.window*2
					b.mu.Unlock()
					if expired {
						site.buckets.Delete(key)
					}
					return true
				})
			})
		}
	}
}

func (rl *RateLimit) byDomainRange(fn func(*rlSite)) {
	seen := map[*rlSite]struct{}{}
	for _, s := range rl.byDomain {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			fn(s)
		}
	}
}

// Name implements pipeline.Stage.
func (rl *RateLimit) Name() string { return "ratelimit" }

// Close stops the background sweeper.
func (rl *RateLimit) Close() error {
	rl.stopOnce.Do(func() { close(rl.stop) })
	return nil
}

// Inspect implements pipeline.Stage.
func (rl *RateLimit) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true {
		return pipeline.Allow()
	}
	site := rl.byDomain[strings.ToLower(rc.Site.Domain)]
	if site == nil {
		return pipeline.Allow()
	}

	ip := clientIP(rc.Request)
	if ip == nil {
		return pipeline.Allow()
	}
	key := ip.String()
	if site.keyURI {
		key += "|" + rc.Request.URL.Path
	}

	over := false
	now := time.Now()
	bAny, _ := site.buckets.LoadOrStore(key, &rlBucket{start: now})
	b := bAny.(*rlBucket)
	b.mu.Lock()
	if now.Sub(b.start) >= site.window {
		b.start = now
		b.count = 0
	}
	b.count++
	if b.count > site.requests {
		over = true
	}
	b.mu.Unlock()

	if !over {
		return pipeline.Allow()
	}

	action := "deny"
	status := http.StatusForbidden
	if !site.deny {
		action = "throttle"
		status = http.StatusTooManyRequests
	}
	rl.logger.Warn("ratelimit: threshold exceeded",
		"ip", ip, "site", rc.Site.Domain, "action", action, "trace", rc.Values["trace_id"])
	return pipeline.Verdict{
		Action: pipeline.ActionDeny,
		Status: status,
		Rule:   "ratelimit/" + action,
		Reason: fmt.Sprintf("rate limit exceeded (%d requests / %s)", site.requests, site.window),
	}
}

var _ io.Closer = (*RateLimit)(nil)
