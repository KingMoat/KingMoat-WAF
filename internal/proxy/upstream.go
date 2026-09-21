package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// nodeState is the runtime state of one upstream node.
type nodeState struct {
	url    *url.URL
	weight int
	cw     int // current weight for smooth WRR

	inflight  atomic.Int64 // least-conn in-flight requests
	healthy   atomic.Bool
	fails     atomic.Int32
	downUntil atomic.Int64 // unix nanos, passive cooldown deadline
}

// available reports whether the node may take traffic right now.
func (n *nodeState) available() bool {
	return n.healthy.Load() && time.Now().UnixNano() >= n.downUntil.Load()
}

// Pool is an upstream pool with pluggable load balancing (smooth weighted
// round-robin / least-conn / source-IP pinning), active health probing and a
// passive circuit breaker. It implements io.Closer; reloads stop the previous
// pool's probe goroutine.
type Pool struct {
	mu        sync.Mutex
	site      string
	algorithm string // "" / "wrr" | "least_conn" | "source_ip"
	nodes     []*nodeState
	cursor    int
	hc        *config.HealthSettings
	verifyTLS bool // mirror the site's upstream verify_tls policy (data-plane parity)
	logger    *slog.Logger
	stop      chan struct{}
}

// NewPool parses and validates the configured upstream nodes and starts
// the active health prober when enabled.
func NewPool(u config.Upstream, h *config.HealthSettings, site string, logger *slog.Logger) (*Pool, error) {
	if len(u.Nodes) == 0 {
		return nil, fmt.Errorf("upstream: no nodes configured")
	}
	if logger == nil {
		logger = slog.Default()
	}
	p := &Pool{site: site, algorithm: u.Algorithm, hc: h, verifyTLS: u.VerifyTLS, logger: logger, stop: make(chan struct{})}
	for _, n := range u.Nodes {
		target := n.Address
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		parsed, err := url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("upstream: parse %q: %w", n.Address, err)
		}
		if parsed.Hostname() == "" {
			return nil, fmt.Errorf("upstream: %q is missing a host", n.Address)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("upstream: %q must use http or https scheme", n.Address)
		}
		w := n.Weight
		if w <= 0 {
			w = 1
		}
		ns := &nodeState{url: parsed, weight: w}
		ns.healthy.Store(true)
		p.nodes = append(p.nodes, ns)
	}
	if h != nil && h.Enabled {
		go p.probeLoop()
	}
	return p, nil
}

// Next returns the next healthy upstream target via the configured
// algorithm. When every node is unavailable it fails open with plain
// round-robin so errors surface at the upstream instead of stalling.
func (p *Pool) Next() *url.URL {
	n := p.pickNode()
	if n == nil {
		return nil
	}
	return n.url
}

// pickNode selects a node by the configured algorithm (client-affinity
// algorithms get the request IP via PickForRequest).
func (p *Pool) pickNode() *nodeState {
	switch p.algorithm {
	case "least_conn":
		return p.pickLeastConn()
	default:
		return p.pickWRR()
	}
}

// pickWRR is smooth weighted round-robin over healthy nodes.
func (p *Pool) pickWRR() *nodeState {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *nodeState
	total := 0
	for _, n := range p.nodes {
		if !n.available() {
			continue
		}
		n.cw += n.weight
		total += n.weight
		if best == nil || n.cw > best.cw {
			best = n
		}
	}
	if best == nil {
		n := p.nodes[p.cursor%len(p.nodes)]
		p.cursor++
		return n
	}
	best.cw -= total
	return best
}

// pickLeastConn selects the healthy node with the fewest in-flight requests
// (weighted: min in-flight per unit weight). Tie-breaks fall back to WRR.
func (p *Pool) pickLeastConn() *nodeState {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *nodeState
	var bestCost float64
	total := 0
	for _, n := range p.nodes {
		if !n.available() {
			continue
		}
		n.cw += n.weight
		total += n.weight
		cost := float64(n.inflight.Load()+1) / float64(n.weight)
		if best == nil || cost < bestCost {
			best, bestCost = n, cost
		}
	}
	if best == nil {
		n := p.nodes[p.cursor%len(p.nodes)]
		p.cursor++
		return n
	}
	best.cw -= total
	return best
}

// pickSourceIP pins a client IP to one healthy node (stable across requests
// for session affinity); falls back to plain rotation when no client IP.
func (p *Pool) pickSourceIP(clientIP string) *nodeState {
	p.mu.Lock()
	defer p.mu.Unlock()
	var healthy []*nodeState
	for _, n := range p.nodes {
		if n.available() {
			healthy = append(healthy, n)
		}
	}
	if len(healthy) == 0 {
		n := p.nodes[p.cursor%len(p.nodes)]
		p.cursor++
		return n
	}
	if clientIP == "" {
		n := healthy[p.cursor%len(healthy)]
		p.cursor++
		return n
	}
	var h uint32
	for i := 0; i < len(clientIP); i++ {
		h = h*31 + uint32(clientIP[i])
	}
	return healthy[int(h)%len(healthy)]
}

// PickForRequest selects a node for an inbound request (algorithm-aware) and
// maintains least-conn in-flight accounting when that algorithm is active.
func (p *Pool) PickForRequest(clientIP string) *nodeState {
	if p.algorithm == "source_ip" {
		return p.pickSourceIP(clientIP)
	}
	n := p.pickNode()
	if n != nil && p.algorithm == "least_conn" {
		n.inflight.Add(1)
	}
	return n
}

// ReportDone releases an in-flight slot (least_conn algorithm only).
func (p *Pool) ReportDone(n *nodeState) {
	if n != nil && p.algorithm == "least_conn" {
		for {
			v := n.inflight.Load()
			if v == 0 || n.inflight.CompareAndSwap(v, v-1) {
				return
			}
		}
	}
}

// ReportSuccess marks a node healthy (any response with status < 500).
func (p *Pool) ReportSuccess(n *nodeState) {
	if n == nil {
		return
	}
	if !n.healthy.Swap(true) {
		p.logger.Info("upstream recovered", "site", p.site, "addr", n.url.Host)
	}
	n.fails.Store(0)
	n.downUntil.Store(0)
}

// ReportFailure records a failed exchange; after fail_threshold consecutive
// failures the node cools down for cooldown_sec (passive circuit breaker).
func (p *Pool) ReportFailure(n *nodeState, reason string) {
	if n == nil {
		return
	}
	fails := n.fails.Add(1)
	threshold, cooldown := p.passiveSettings()
	if p.passiveEnabled() && int(fails) >= threshold {
		down := time.Duration(cooldown) * time.Second
		n.downUntil.Store(time.Now().Add(down).UnixNano())
		n.fails.Store(0)
		p.logger.Warn("upstream circuit opened (passive)",
			"site", p.site, "addr", n.url.Host, "reason", reason, "cooldown_sec", cooldown)
	}
}

// NodeFromRequest extracts the selected node from an outbound request set
// by Rewrite.
func (p *Pool) nodeFromRequest(r *http.Request) *nodeState {
	if r == nil {
		return nil
	}
	if n, ok := r.Context().Value(ctxNodeKey{}).(*nodeState); ok {
		return n
	}
	return nil
}

// nodeFromResponse extracts the selected node from an upstream response
// (the response carries the outbound request).
func (p *Pool) nodeFromResponse(resp *http.Response) *nodeState {
	if resp == nil {
		return nil
	}
	return p.nodeFromRequest(resp.Request)
}

func withNode(ctx context.Context, n *nodeState) context.Context {
	return context.WithValue(ctx, ctxNodeKey{}, n)
}

type ctxNodeKey struct{}

func (p *Pool) probeLoop() {
	interval := time.Duration(p.hc.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	path := p.hc.Path
	if path == "" {
		path = "/"
	}
	timeout := time.Duration(p.hc.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	// TLS policy must match the data plane: the forward path skips upstream
	// certificate verification unless the site opts in (verify_tls), and the
	// probe has to agree — otherwise a self-signed/internal-CA upstream serves
	// traffic fine while the probe keeps marking it unhealthy.
	client := &http.Client{Timeout: timeout}
	if !p.verifyTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // mirrors the data-plane per-site default
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		nodes := append([]*nodeState(nil), p.nodes...)
		p.mu.Unlock()
		for _, n := range nodes {
			probeURL := n.url.Scheme + "://" + n.url.Host + path
			resp, err := client.Get(probeURL)
			if err != nil {
				if n.healthy.Swap(false) {
					p.logger.Warn("upstream probe failed",
						"site", p.site, "addr", n.url.Host, "err", err)
				}
				continue
			}
			ok := resp.StatusCode < 500
			resp.Body.Close()
			if ok {
				p.ReportSuccess(n)
			} else if n.healthy.Swap(false) {
				p.logger.Warn("upstream probe unhealthy",
					"site", p.site, "addr", n.url.Host, "status", resp.StatusCode)
			}
		}
	}
}

func (p *Pool) passiveEnabled() bool {
	return p.hc == nil || p.hc.Passive // passive defaults to on
}

func (p *Pool) passiveSettings() (threshold, cooldown int) {
	threshold, cooldown = 3, 30
	if p.hc != nil {
		if p.hc.FailThreshold > 0 {
			threshold = p.hc.FailThreshold
		}
		if p.hc.CooldownSec > 0 {
			cooldown = p.hc.CooldownSec
		}
	}
	return threshold, cooldown
}

// Close stops the active health prober (implements io.Closer).
func (p *Pool) Close() error {
	if p.stop != nil {
		select {
		case <-p.stop:
		default:
			close(p.stop)
		}
	}
	return nil
}

// Len returns the number of upstream nodes.
func (p *Pool) Len() int { return len(p.nodes) }
