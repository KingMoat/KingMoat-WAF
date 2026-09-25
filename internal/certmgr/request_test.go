package certmgr

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// okLeaf builds a valid leaf certificate for the fake issuer.
func okLeaf(t *testing.T, domain string) *x509.Certificate {
	t.Helper()
	pemBytes := genTestCertPEM(t, []string{domain}, time.Now().Add(90*24*time.Hour))
	// Reuse the cache parser: the PEM holds exactly one CERTIFICATE block.
	leaf, err := leafFromPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// waitTask polls the task until it reaches want (bounded).
func waitTask(t *testing.T, s *Service, id, want string) RequestTask {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if task, ok := s.Task(id); ok && task.Status == want {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s in time", id, want)
	return RequestTask{}
}

// TestValidateDomain covers the request-time domain checks.
func TestValidateDomain(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"km.example.com", true},
		{"a-b.example.co.uk", true},
		{"xn--fiq228c.example.com", true}, // punycode label
		{"", false},
		{"*.example.com", false},  // wildcard (DNS-01 only)
		{"example.com:443", false}, // port baggage
		{"https://example.com", false},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
		{"a..b.com", false},
		{"not allowed.com", false},
	}
	for _, tc := range cases {
		err := validateDomain(tc.in)
		if tc.valid != (err == nil) {
			t.Fatalf("validateDomain(%q) = %v, want valid=%v", tc.in, err, tc.valid)
		}
	}
}

// TestRequestSingleFlight covers the in-flight dedup: a second submission for
// the same domain while the first is issuing returns the SAME task id, and
// the fake issuer runs exactly once.
func TestRequestSingleFlight(t *testing.T) {
	var calls int
	var mu sync.Mutex
	started := make(chan struct{})
	release := make(chan struct{})
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			started <- struct{}{}
			<-release
			return okLeaf(t, domain), nil
		}))

	t1, err := s.Request("sf.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := s.Request("sf.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if t1.ID != t2.ID {
		t.Fatalf("single-flight split: %s vs %s", t1.ID, t2.ID)
	}
	<-started // first attempt entered the issuer
	close(release)
	task := waitTask(t, s, t1.ID, TaskSuccess)
	if task.NotAfter == "" {
		t.Fatalf("success task without not_after: %+v", task)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("issuer called %d times, want 1", calls)
	}
}

// TestRequestFailureCooldown covers the per-domain cooldown after a failed
// attempt and its expiry.
func TestRequestFailureCooldown(t *testing.T) {
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			return nil, errors.New("acme: boom")
		}))
	t1, err := s.Request("cd.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	task := waitTask(t, s, t1.ID, TaskFailed)
	if task.Error == "" {
		t.Fatal("failed task without error message")
	}
	if _, err := s.Request("cd.local", "", false); !errors.Is(err, ErrCooldown) {
		t.Fatalf("request during cooldown = %v, want ErrCooldown", err)
	}
	// The cooldown only covers the failing mode: staging is independent.
	t2, err := s.Request("cd.local", "", true)
	if err != nil {
		t.Fatalf("staging request blocked by prod cooldown: %v", err)
	}
	waitTask(t, s, t2.ID, TaskFailed)
	// Force-expire the cooldown: the domain may be retried.
	s.mu.Lock()
	s.cooldown[taskKey(false, "cd.local")] = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if _, err := s.Request("cd.local", "", false); err != nil {
		t.Fatalf("request after cooldown expiry = %v, want accepted", err)
	}
}

// TestRequestCacheIdempotent covers the cache-hit path: a certificate well
// outside the renewal window answers the request immediately without an ACME
// round-trip (no duplicate-certificate rate-limit burn).
func TestRequestCacheIdempotent(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cached.local"),
		genTestCertPEM(t, []string{"cached.local"}, time.Now().Add(90*24*time.Hour)), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int
	s := NewService(NewACMEHolder(base), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			calls++
			return okLeaf(t, domain), nil
		}))
	task, err := s.Request("cached.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != TaskSuccess || !task.Reused || task.NotAfter == "" {
		t.Fatalf("cache-hit task = %+v, want success+reused", task)
	}
	time.Sleep(20 * time.Millisecond) // no issuer run must have started
	if calls != 0 {
		t.Fatalf("issuer called %d times on cache hit, want 0", calls)
	}
	// A nearly-expired cached certificate must NOT answer idempotently.
	if err := os.WriteFile(filepath.Join(base, "old.local"),
		genTestCertPEM(t, []string{"old.local"}, time.Now().Add(10*24*time.Hour)), 0o600); err != nil {
		t.Fatal(err)
	}
	t2, err := s.Request("old.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, t2.ID, TaskSuccess)
	if calls != 1 {
		t.Fatalf("issuer calls = %d, want 1 (expiring entry re-issues)", calls)
	}
}

// TestRequestConcurrencyLimit covers the process-wide issuance cap of 2
// shared by certificate-library requests.
func TestRequestConcurrencyLimit(t *testing.T) {
	var mu sync.Mutex
	running, maxSeen := 0, 0
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			running++
			if running > maxSeen {
				maxSeen = running
			}
			mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
			return okLeaf(t, domain), nil
		}))
	ids := make([]string, 6)
	for i := range ids {
		task, err := s.Request(fmt.Sprintf("c%d.local", i), "", false)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = task.ID
	}
	for _, id := range ids {
		waitTask(t, s, id, TaskSuccess)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxSeen > maxConcurrentIssues {
		t.Fatalf("max concurrent issuances = %d, want <= %d", maxSeen, maxConcurrentIssues)
	}
}

// TestRequestTaskHistoryCap covers the bounded task history (oldest evicted).
func TestRequestTaskHistoryCap(t *testing.T) {
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			return okLeaf(t, domain), nil
		}))
	for i := 0; i < maxRecentTasks+5; i++ {
		task, err := s.Request(fmt.Sprintf("h%d.local", i), "", false)
		if err != nil {
			t.Fatal(err)
		}
		waitTask(t, s, task.ID, TaskSuccess)
	}
	s.mu.Lock()
	n := len(s.tasks)
	s.mu.Unlock()
	if n != maxRecentTasks {
		t.Fatalf("task history = %d, want capped at %d", n, maxRecentTasks)
	}
}

// TestACMEManagerMergesCachedHosts covers the "request first, attach site
// later" guarantee: cached certificate domains (production AND staging
// directories) stay in the rebuilt manager's whitelist even without any
// ACME site, so the manager keeps serving and renewing them, including
// across restarts.
func TestACMEManagerMergesCachedHosts(t *testing.T) {
	base := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(base, "e.local"), genTestCertPEM(t, []string{"e.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	stagingDir := cacheDirFor(base, true)
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "f.local"), genTestCertPEM(t, []string{"f.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}

	// No ACME site at all, but cached certificates keep ACME enabled.
	m := ACMEManager(&config.Config{}, base, "")
	if m == nil {
		t.Fatal("ACMEManager = nil, want manager for cached certificates")
	}
	for _, host := range []string{"e.local", "f.local"} {
		if err := m.HostPolicy(context.Background(), host); err != nil {
			t.Fatalf("HostPolicy(%q) = %v, want allowed", host, err)
		}
	}
	if err := m.HostPolicy(context.Background(), "other.local"); err == nil {
		t.Fatal("HostPolicy(other.local) = nil, want rejected")
	}

	// With an ACME site, both site domains and cached domains are allowed.
	cfg := &config.Config{Sites: []config.Site{
		{Domains: []string{"site.local"}, ACME: &config.ACMESettings{}},
	}}
	m = ACMEManager(cfg, base, "")
	for _, host := range []string{"site.local", "e.local", "f.local"} {
		if err := m.HostPolicy(context.Background(), host); err != nil {
			t.Fatalf("HostPolicy(%q) = %v, want allowed", host, err)
		}
	}
}

// TestRequestConcurrentSubmit hammers Request from many goroutines. Same-
// domain submissions must collapse into one single-flight task and every
// returned snapshot must be a coherent copy taken under the service lock.
// Under `go test -race` this is the regression guard for the historical
// unlocked `return *t` that raced run()'s Status write; without -race it
// still pins the single-flight and snapshot-validity behavior.
func TestRequestConcurrentSubmit(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	s := NewService(NewACMEHolder(t.TempDir()), nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return okLeaf(t, domain), nil
		}))

	// Phase 1: concurrent submissions of ONE domain share one in-flight
	// task; the issuer blocks so every submission must observe it.
	const same = 16
	snapshots := make([]RequestTask, same)
	var wg sync.WaitGroup
	for i := 0; i < same; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			task, err := s.Request("race.local", "", false)
			if err != nil {
				t.Errorf("concurrent request: %v", err)
				return
			}
			snapshots[i] = task
		}(i)
	}
	<-started // the issuer is running: run() already flipped Status under the lock
	wg.Wait()
	for i := 1; i < same; i++ {
		if snapshots[i].ID != snapshots[0].ID {
			t.Fatalf("single-flight split under concurrency: %s vs %s", snapshots[0].ID, snapshots[i].ID)
		}
		if st := snapshots[i].Status; st != TaskPending && st != TaskRunning {
			t.Fatalf("incoherent snapshot status %q: %+v", st, snapshots[i])
		}
		if snapshots[i].Domain != "race.local" || snapshots[i].CreatedAt == "" {
			t.Fatalf("incoherent snapshot: %+v", snapshots[i])
		}
	}
	close(release)
	waitTask(t, s, snapshots[0].ID, TaskSuccess)

	// Phase 2: distinct domains — every submission takes the async path,
	// maximizing the return-path vs run() overlap the race detector watches.
	const distinct = 24
	ids := make([]string, distinct)
	for i := 0; i < distinct; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			task, err := s.Request(fmt.Sprintf("r%d.local", i), "", false)
			if err != nil {
				t.Errorf("request r%d.local: %v", i, err)
				return
			}
			ids[i] = task.ID
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("distinct domains shared a task id: %s", id)
		}
		seen[id] = true
	}
	for _, id := range ids {
		waitTask(t, s, id, TaskSuccess)
	}
}
