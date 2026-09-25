// Daily proactive ACME renewal: a background loop checks every ACME domain
// (site-managed or cached "request first, attach site later") once a day so
// certificates on long-idle sites renew before expiry instead of only when a
// TLS handshake happens to ask for them. Each pass shares the certificate
// library's issuance budget, and per-domain outcomes surface as cert-library
// entry fields (last_renew_attempt / last_renew_error).
package certmgr

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

const (
	// defaultRenewFirstDelay delays the first renewal pass after boot so a
	// restarting service does not race its own startup work against the
	// ACME endpoints.
	defaultRenewFirstDelay = 10 * time.Minute
	// defaultRenewEvery is the daily check interval. autocert itself renews
	// inside its 30-day window; the daily pass merely triggers
	// GetCertificate for domains no handshake touches.
	defaultRenewEvery = 24 * time.Hour
)

// RenewalResult records the outcome of one daily renewal attempt for a
// domain (per staging mode).
type RenewalResult struct {
	At    string `json:"at"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// renewalTarget is one domain checked by the daily pass.
type renewalTarget struct {
	domain  string
	staging bool
	email   string
}

// renewalKey namespaces the renewal bookkeeping by staging mode (same
// convention as taskKey).
func renewalKey(staging bool, domain string) string {
	return taskKey(staging, domain)
}

// collectRenewalTargets merges the site ACME domains (staging flag and email
// per site, email falling back to the global contact) with every domain
// already cached in either cache directory. Site entries win over
// cache-derived duplicates; staging and production stay independent keys.
func collectRenewalTargets(cfg *config.Config, base, globalEmail string) []renewalTarget {
	var out []renewalTarget
	seen := map[string]bool{}
	add := func(domain string, staging bool, email string) {
		key := renewalKey(staging, domain)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, renewalTarget{domain: domain, staging: staging, email: email})
	}
	if cfg != nil {
		for i := range cfg.Sites {
			s := &cfg.Sites[i]
			if s.ACME == nil {
				continue
			}
			email := s.ACME.Email
			if email == "" {
				email = globalEmail
			}
			for _, d := range s.Domains {
				add(d, s.ACME.Staging, email)
			}
		}
	}
	for _, d := range CachedHosts(cacheDirFor(base, false)) {
		add(d, false, globalEmail)
	}
	for _, d := range CachedHosts(cacheDirFor(base, true)) {
		add(d, true, globalEmail)
	}
	return out
}

// RestartRenewer (re)starts the daily renewal loop, cancelling any previous
// one first so exactly one pass ever runs. It is called at boot and after
// every ACME rebuild: the loop works on the config snapshot captured here
// (site changes hot-apply through the same rebuild path), so no per-pass
// config reload is needed.
func (s *Service) RestartRenewer(parent context.Context, cfg *config.Config, globalEmail string) {
	if s.renewCancel != nil {
		s.renewCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	targets := collectRenewalTargets(cfg, s.base, s.emailFor(globalEmail))
	s.mu.Lock()
	s.renewCancel = cancel
	s.mu.Unlock()
	slog.Info("ACME daily renewal scheduled", "domains", len(targets))
	go s.renewLoop(ctx, targets)
}

// renewLoop runs one pass after the first delay, then every renewEvery,
// until ctx is cancelled (superseded by a newer RestartRenewer or shutdown).
func (s *Service) renewLoop(ctx context.Context, targets []renewalTarget) {
	timer := time.NewTimer(s.renewFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.runRenewalPass(ctx, targets)
		}
		timer.Reset(s.renewEvery)
	}
}

// runRenewalPass checks every target once: each domain gets one issuance
// attempt through the shared issueFn (an unexpired certificate is a no-op
// inside autocert; a domain inside the 30-day window renews). Concurrency is
// bounded by the shared issuance semaphore so a sweep can never stampede the
// ACME endpoints, and pending domains are skipped once the pass context is
// cancelled (superseded or shutdown). An empty target set is a no-op.
func (s *Service) runRenewalPass(ctx context.Context, targets []renewalTarget) {
	if len(targets) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t renewalTarget) {
			defer wg.Done()
			select {
			case s.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-s.sem }()

			ictx, cancel := context.WithTimeout(ctx, issueTimeout)
			defer cancel()
			_, err := s.issueFn(ictx, t.domain, t.email, t.staging)
			res := RenewalResult{At: rfc3339(time.Now()), OK: err == nil}
			if err != nil {
				res.Error = err.Error()
				slog.Warn("ACME renewal check failed", "domain", t.domain, "staging", t.staging, "err", err)
			}
			s.mu.Lock()
			s.renewals[renewalKey(t.staging, t.domain)] = res
			s.mu.Unlock()
		}(t)
	}
	wg.Wait()
}

// RenewalSnapshot returns the latest renewal result per domain+mode key.
func (s *Service) RenewalSnapshot() map[string]RenewalResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]RenewalResult, len(s.renewals))
	for k, v := range s.renewals {
		out[k] = v
	}
	return out
}
