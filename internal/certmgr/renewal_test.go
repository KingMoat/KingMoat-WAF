package certmgr

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// waitFor polls cond until true or a bounded deadline expires.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// acmeSite builds a one-site config for renewal tests.
func acmeSite(domains []string, staging bool) *config.Config {
	return &config.Config{
		Sites: []config.Site{{Domains: domains, ACME: &config.ACMESettings{Staging: staging}}},
	}
}

// TestCollectRenewalTargets covers the target merge: site domains (staging
// flag and email per site, global-email fallback), cache-derived entries for
// both directories, and site-wins dedup by domain+mode.
func TestCollectRenewalTargets(t *testing.T) {
	base := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(base, "cached-prod.local"), genTestCertPEM(t, []string{"cached-prod.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base+stagingCacheSuffix, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base+stagingCacheSuffix, "cached-stag.local"), genTestCertPEM(t, []string{"cached-stag.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Sites: []config.Site{
			{Domains: []string{"site-a.local", "shared.local"}, ACME: &config.ACMESettings{Email: "site-a@x"}},
			{Domains: []string{"shared.local", "site-c.local"}, ACME: &config.ACMESettings{Staging: true}},
		},
	}
	targets := collectRenewalTargets(cfg, base, "global@x")

	got := map[string]renewalTarget{}
	for _, tg := range targets {
		got[renewalKey(tg.staging, tg.domain)] = tg
	}
	want := map[string]renewalTarget{
		"prod|site-a.local":         {domain: "site-a.local", staging: false, email: "site-a@x"},
		"prod|shared.local":         {domain: "shared.local", staging: false, email: "site-a@x"},
		"staging|shared.local":      {domain: "shared.local", staging: true, email: "global@x"},
		"staging|site-c.local":      {domain: "site-c.local", staging: true, email: "global@x"},
		"prod|cached-prod.local":    {domain: "cached-prod.local", staging: false, email: "global@x"},
		"staging|cached-stag.local": {domain: "cached-stag.local", staging: true, email: "global@x"},
	}
	if len(targets) != len(want) {
		t.Fatalf("collected %d targets, want %d: %+v", len(targets), len(want), targets)
	}
	for k, w := range want {
		if g := got[k]; g != w {
			t.Fatalf("target %q = %+v, want %+v", k, g, w)
		}
	}
}

// TestRenewalPassRecordsResults covers the per-domain outcome recording:
// successes carry a timestamp, failures carry the error text.
func TestRenewalPassRecordsResults(t *testing.T) {
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			if domain == "bad.local" {
				return nil, errors.New("acme: boom")
			}
			return okLeaf(t, domain), nil
		}))
	s.runRenewalPass(context.Background(), []renewalTarget{
		{domain: "good.local", email: "e@x"},
		{domain: "bad.local", email: "e@x"},
	})

	snap := s.RenewalSnapshot()
	good := snap[renewalKey(false, "good.local")]
	if !good.OK || good.At == "" || good.Error != "" {
		t.Fatalf("good.local result = %+v, want ok with timestamp", good)
	}
	bad := snap[renewalKey(false, "bad.local")]
	if bad.OK || bad.Error == "" {
		t.Fatalf("bad.local result = %+v, want failure with error", bad)
	}
}

// TestEntriesMergeRenewalResults covers the cert-library merge: entries pick
// up last_renew_attempt / last_renew_error from the renewal results.
func TestEntriesMergeRenewalResults(t *testing.T) {
	base := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(base, "a.local"), genTestCertPEM(t, []string{"a.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewService(NewACMEHolder(base), nil)

	s.mu.Lock()
	s.renewals[renewalKey(false, "a.local")] = RenewalResult{At: "2026-09-26T00:00:00Z", OK: true}
	s.mu.Unlock()
	e := s.Entries()[0]
	if e.LastRenewalCheck != "2026-09-26T00:00:00Z" || e.LastRenewError != "" {
		t.Fatalf("merged ok entry = %+v", e)
	}

	s.mu.Lock()
	s.renewals[renewalKey(false, "a.local")] = RenewalResult{At: "2026-09-26T01:00:00Z", Error: "acme: boom"}
	s.mu.Unlock()
	e = s.Entries()[0]
	if e.LastRenewalCheck != "2026-09-26T01:00:00Z" || e.LastRenewError != "acme: boom" {
		t.Fatalf("merged failed entry = %+v", e)
	}
}

// TestRestartRenewerSupersedesLoop covers loop handover: after a restart with
// a changed domain set the old loop must stop checking removed domains.
func TestRestartRenewerSupersedesLoop(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	s := NewService(NewACMEHolder(t.TempDir()), nil,
		WithIssuer(func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			calls[domain]++
			mu.Unlock()
			return okLeaf(t, domain), nil
		}),
		WithRenewalTiming(20*time.Millisecond, time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.RestartRenewer(ctx, acmeSite([]string{"a.local"}, false), "")
	waitFor(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.renewals[renewalKey(false, "a.local")].At != ""
	})

	// Supersede with a new domain set: a.local leaves the targets.
	s.RestartRenewer(ctx, acmeSite([]string{"b.local"}, false), "")
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls["b.local"] > 0
	})
	time.Sleep(150 * time.Millisecond) // grace window for a cancelled loop to misbehave
	mu.Lock()
	defer mu.Unlock()
	if calls["a.local"] != 1 {
		t.Fatalf("a.local checked %d times, want 1 (old loop must not keep running)", calls["a.local"])
	}
}

// TestRestartRenewerEmptyTargetsSafe covers the no-ACME bootstrap: an empty
// target set must not reach the issuer nor panic.
func TestRestartRenewerEmptyTargetsSafe(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s := NewService(NewACMEHolder(t.TempDir()), nil,
		WithIssuer(func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return okLeaf(t, domain), nil
		}),
		WithRenewalTiming(20*time.Millisecond, time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.RestartRenewer(ctx, &config.Config{}, "")
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("issuer called %d times with empty target set, want 0", calls)
	}
	if snap := s.RenewalSnapshot(); len(snap) != 0 {
		t.Fatalf("renewal results recorded for empty pass: %+v", snap)
	}
}
