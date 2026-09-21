package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// supervisorSettings builds an enabled settings block pointed at a mock LLM.
func supervisorSettings(t *testing.T) *Settings {
	t.Helper()
	calls := 0
	srv := mockLLM(t, &calls)
	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	cfg.ApplyDefaults()
	t.Cleanup(srv.Close)
	return cfg
}

// TestSupervisorRefUnblockedDuringRebuildSwap pins the rebuild ordering: the
// live-service swap must never sit behind a lock that a slow rebuild holds
// (the old implementation held s.mu across the whole swap, including the old
// instance's Close — Analyzer.Stop waits for a running cron report, minutes
// in the worst case — so every Ref()/KEK() call stalled).
func TestSupervisorRefUnblockedDuringRebuildSwap(t *testing.T) {
	sup := NewSupervisor(quietTestLogger())
	// Simulate a slow rebuild in flight: rebuildMu (the body serialization
	// lock) is held by another goroutine. Ref() must not depend on it —
	// regressions that route Ref() through the rebuild lock fail here.
	sup.rebuildMu.Lock()
	release := make(chan struct{})
	go func() {
		<-release
		sup.rebuildMu.Unlock()
	}()
	start := time.Now()
	if svc := sup.Ref(); svc != nil {
		t.Fatal("fresh supervisor must hand out nil (no live service yet)")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Ref() blocked %v behind an in-flight rebuild swap", d)
	}
	close(release)
}

// TestSupervisorRebuildAppliesModelChange pins the hot-rebuild contract:
// after a config publish the next Rebuild swaps the live service so chat
// immediately uses the new model (the console model tag reads the live
// instance, never the on-disk config).
func TestSupervisorRebuildAppliesModelChange(t *testing.T) {
	sup := NewSupervisor(quietTestLogger())
	dir := t.TempDir()

	mk := func(model string) *Settings {
		calls := 0
		srv := mockLLM(t, &calls)
		t.Cleanup(srv.Close)
		cfg := &Settings{Enabled: true}
		cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: model}
		cfg.ApplyDefaults()
		return cfg
	}

	sup.Rebuild(mk("model-a"), testSources(), filepath.Join(dir, "a.db"), config.EmailSettings{})
	if svc := sup.Ref(); svc == nil || svc.ModelName() != "model-a" {
		t.Fatalf("after first rebuild ModelName = %v, want model-a", sup.Ref())
	}

	sup.Rebuild(mk("model-b"), testSources(), filepath.Join(dir, "b.db"), config.EmailSettings{})
	if svc := sup.Ref(); svc == nil || svc.ModelName() != "model-b" {
		t.Fatalf("after republish ModelName = %v, want model-b (hot rebuild must apply the new model)", sup.Ref())
	}

	sup.Close()
}

// TestSupervisorRebuildFailureKeepsPreviousInstance pins the fail-open
// behavior: a failed NewService keeps the previous instance alive (a broken
// AI config must not kill a working assistant); an explicit disable swaps
// nil in and closes the live instance.
func TestSupervisorRebuildFailureKeepsPreviousInstance(t *testing.T) {
	sup := NewSupervisor(quietTestLogger())
	sup.Rebuild(supervisorSettings(t), testSources(), filepath.Join(t.TempDir(), "ai.db"), config.EmailSettings{})
	live := sup.Ref()
	if live == nil {
		t.Fatal("precondition: live assistant after first rebuild")
	}

	// A non-database file at the AI store path makes OpenStore fail.
	blocked := filepath.Join(t.TempDir(), "blocked.db")
	if err := os.WriteFile(blocked, []byte("this is not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	sup.Rebuild(supervisorSettings(t), testSources(), blocked, config.EmailSettings{})
	if got := sup.Ref(); got != live {
		t.Fatal("a failed rebuild must keep the previous instance (fail-open)")
	}

	sup.Rebuild(nil, nil, "", config.EmailSettings{})
	if got := sup.Ref(); got != nil {
		t.Fatal("explicit disable must turn the assistant off")
	}
}

// TestSupervisorConcurrentRebuildRef exercises overlapping rebuilds against
// concurrent Ref()/KEK() consumers; under -race any unsynchronized access or
// deadlock fails the test. Rebuilds and disables interleave; the final state
// is whatever the last completed rebuild left — both nil and live are fine,
// as long as Ref() stays consistent.
func TestSupervisorConcurrentRebuildRef(t *testing.T) {
	sup := NewSupervisor(quietTestLogger())
	dir := t.TempDir()

	stop := make(chan struct{})
	var hammer sync.WaitGroup
	hammer.Add(1)
	go func() {
		defer hammer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sup.Ref()
			_, _ = sup.KEK()
		}
	}()

	var rebuilders sync.WaitGroup
	for g := 0; g < 3; g++ {
		rebuilders.Add(1)
		go func(g int) {
			defer rebuilders.Done()
			for i := 0; i < 5; i++ {
				if (g+i)%4 == 3 {
					sup.Rebuild(nil, nil, "", config.EmailSettings{})
					continue
				}
				sup.Rebuild(supervisorSettings(t), testSources(),
					filepath.Join(dir, fmt.Sprintf("ai-%d-%d.db", g, i)), config.EmailSettings{})
			}
		}(g)
	}
	rebuilders.Wait()
	close(stop)
	hammer.Wait()
	sup.Close() // process-shutdown path closes whatever the last swap left live
}
