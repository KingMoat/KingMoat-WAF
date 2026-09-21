// Package pipeline defines the detection pipeline contract shared by all
// protection stages. M0 ships the plumbing only; concrete stages (ACL, rate
// limit, Coraza) are added from M1 on (see docs/ARCHITECTURE.md §3.1).
package pipeline

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
)

// realIPKey is the context key under which the proxy stores the site-scoped
// resolved real client IP (see config.Site.RealIP). Stages read it via
// ClientIPFromContext so ACL, GeoIP, rate limiting, bot detection, matcher
// rules and logs all operate on the same resolved address.
type realIPKey struct{}

// WithClientIP stores the resolved real client IP in the request context.
func WithClientIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, realIPKey{}, ip)
}

// ClientIPFromContext returns the real client IP resolved by the proxy,
// or nil when the site has no real-ip resolution for this request.
func ClientIPFromContext(ctx context.Context) net.IP {
	ip, _ := ctx.Value(realIPKey{}).(net.IP)
	return ip
}

// Action is what a stage asks the proxy to do with a request.
type Action int

const (
	ActionAllow Action = iota
	ActionDeny
	// ActionChallenge is reserved for M3 bot verification (JS challenge /
	// captcha). Until then the proxy treats it like a deny verdict.
	ActionChallenge
)

func (a Action) String() string {
	switch a {
	case ActionDeny:
		return "deny"
	case ActionChallenge:
		return "challenge"
	default:
		return "allow"
	}
}

// Verdict is the outcome of pipeline inspection.
type Verdict struct {
	Action Action
	Status int    // HTTP status used for block pages (0 → 403)
	Rule   string // "<stage>/<rule>" identifier, exposed on the block page
	Reason string // human readable explanation for logs and the block page
}

// Allow reports that the request may proceed to the next stage.
func Allow() Verdict { return Verdict{Action: ActionAllow} }

// Deny reports that the request must be blocked (default status 403).
func Deny(rule, reason string) Verdict {
	return Verdict{Action: ActionDeny, Status: http.StatusForbidden, Rule: rule, Reason: reason}
}

// SiteView is the minimal site context stages may rely on.
type SiteView struct {
	Domain  string
	Monitor bool // true → deny verdicts are recorded but the request forwards
}

// RequestContext carries per-request inspection state shared across stages.
// Stages may stash values (trace id, fingerprint, CC counters, ...) in Values.
// Body holds the buffered request body when the proxy decided to inspect it;
// nil means the body was not buffered (no body / over-limit bypass / upgrade).
type RequestContext struct {
	Request *http.Request
	Site    SiteView
	Body    []byte
	Values  map[string]any
}

// Stage is one inspection phase in the pipeline.
type Stage interface {
	Name() string
	Inspect(ctx context.Context, rc *RequestContext) Verdict
}

// StageGate lets the pipeline skip stages for specific sites (detection
// modules disabled by matcher "disable" rules).
type StageGate interface {
	Disabled(site, stage string) bool
}

// Pipeline runs stages in order; the first non-allow verdict wins.
type Pipeline struct {
	stages []Stage
	gate   atomic.Value // StageGate
}

// New builds a pipeline from ordered stages.
func New(stages ...Stage) *Pipeline {
	return &Pipeline{stages: stages}
}

// SetGate attaches (or replaces) the stage gate; passing nil clears it.
func (p *Pipeline) SetGate(g StageGate) { p.gate.Store(g) }

func (p *Pipeline) currentGate() StageGate {
	if g, ok := p.gate.Load().(StageGate); ok {
		return g
	}
	return nil
}

// Inspect runs every stage until one returns a non-allow verdict. Stages
// disabled for the request's site (via the gate) are skipped.
func (p *Pipeline) Inspect(ctx context.Context, rc *RequestContext) Verdict {
	if rc.Values == nil {
		rc.Values = make(map[string]any)
	}
	gate := p.currentGate()
	for _, s := range p.stages {
		if gate != nil && gate.Disabled(rc.Site.Domain, s.Name()) {
			continue
		}
		v := s.Inspect(ctx, rc)
		if v.Action != ActionAllow {
			return v
		}
	}
	return Allow()
}

// Len returns the number of registered stages.
func (p *Pipeline) Len() int { return len(p.stages) }
