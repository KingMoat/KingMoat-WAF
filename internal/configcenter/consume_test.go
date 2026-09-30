package configcenter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// fakeApplier records every Reload in order and mimics *proxy.Handler's
// revision bookkeeping: the running revision only advances when a reload
// succeeds.
type fakeApplier struct {
	mu       sync.Mutex
	applied  []int64
	snapshots []int // len(cfg.Sites) per apply (snapshot pairing check)
	running  int64
	failRevs map[int64]bool
	delay    time.Duration
}

func (f *fakeApplier) Reload(cfg *config.Config, rev int64) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	f.applied = append(f.applied, rev)
	f.snapshots = append(f.snapshots, len(cfg.Sites))
	if !f.failRevs[rev] {
		f.running = rev
	}
	f.mu.Unlock()
	if f.failRevs[rev] {
		return errors.New("reload failed for test")
	}
	return nil
}

func (f *fakeApplier) RunningRevision() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

// record returns the apply sequence and, for one revision, how often it was
// applied plus the snapshot size of its LAST apply.
func (f *fakeApplier) record(rev int64) (seq []int64, count, lastSites int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.applied...), func() int {
		n := 0
		for _, r := range f.applied {
			if r == rev {
				n++
			}
		}
		return n
	}(), func() int {
		for i := len(f.applied) - 1; i >= 0; i-- {
			if f.applied[i] == rev {
				return f.snapshots[i]
			}
		}
		return -1
	}()
}

// burstCfg builds a config with 1+n sites (each call differs from the previous
// one so Publish never hits ErrNoChanges).
func burstCfg(n int) *config.Config {
	c := seedCfg()
	for i := 0; i < n; i++ {
		c.Sites = append(c.Sites, config.Site{
			Domains:  []string{fmt.Sprintf("burst-%d.local", n*100+i)},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9002"}}},
		})
	}
	return c
}

// runConsume starts Consume and returns a cancel func that stops it (bounded
// wait; the test fails if the loop does not exit).
func runConsume(t *testing.T, c *Center, applier *fakeApplier) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Consume(ctx, applier, nil)
		close(done)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Consume did not exit after ctx cancel")
		}
	}
}

// waitFor polls cond until it holds or the budget runs out.
func waitFor(t *testing.T, budget time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestConsumeCatchesUpAfterBufferOverflow is the C1 regression: a slow reload
// while publishes burst in overflows the bounded subscribe buffer (8) and the
// overflowed events are dropped — the data plane must still converge to the
// center's latest revision via the catch-up reload.
func TestConsumeCatchesUpAfterBufferOverflow(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	applier := &fakeApplier{delay: 30 * time.Millisecond} // slow reload
	stop := runConsume(t, c, applier)
	defer stop()

	// Let the first event settle so the loop is inside a slow Reload when the
	// burst arrives.
	if _, err := c.Publish(burstCfg(1), "t", "v1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		_, n, _ := applier.record(2)
		return n >= 1
	}, "first event never consumed")

	const burst = 19
	latest := int64(2) // seed(rev1) + the settling publish(rev2)
	for i := 2; i <= 1+burst; i++ {
		time.Sleep(2 * time.Millisecond) // far faster than the 30ms reload
		rev, err := c.Publish(burstCfg(i), "t", fmt.Sprintf("v%d", i))
		if err != nil {
			t.Fatal(err)
		}
		latest = rev
	}

	// The buffer can only hold 8 events, so some of the burst was dropped;
	// the consumer must still converge to the latest revision.
	waitFor(t, 5*time.Second, func() bool {
		return applier.RunningRevision() == latest
	}, "consumer did not catch up to the latest revision after buffer overflow")

	// The catch-up reload must have applied the LATEST revision's own config
	// snapshot (not a stale one): the last apply carries all burst sites.
	_, _, lastSites := applier.record(latest)
	if lastSites != 1+1+burst {
		t.Fatalf("catch-up snapshot sites = %d, want %d (stale snapshot applied)", lastSites, 1+1+burst)
	}

	// Every applied revision got its own apply outcome (no mispairing).
	seq, _, _ := applier.record(0)
	for _, rev := range seq {
		st, ok := c.ApplyStatusFor(rev)
		if !ok || st.Revision != rev {
			t.Fatalf("applied revision %d has no paired apply outcome (got %+v ok=%v)", rev, st, ok)
		}
	}
}

// TestConsumeNormalOrdering pins the non-regression half: without buffer
// overflow every event is applied exactly once, in publish order, with no
// catch-up reloads in between.
func TestConsumeNormalOrdering(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	applier := &fakeApplier{} // fast consumer
	stop := runConsume(t, c, applier)
	defer stop()

	want := []int64{}
	for i := 1; i <= 3; i++ {
		time.Sleep(80 * time.Millisecond) // slow publish cadence: no drops
		rev, err := c.Publish(burstCfg(i), "t", fmt.Sprintf("v%d", i+1))
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, rev)
	}
	waitFor(t, 2*time.Second, func() bool {
		return applier.RunningRevision() == want[len(want)-1]
	}, "consumer did not reach the last revision")

	seq, _, _ := applier.record(0)
	if len(seq) != len(want) {
		t.Fatalf("apply sequence = %v, want exactly %v (unexpected catch-up reloads)", seq, want)
	}
	for i, rev := range want {
		if seq[i] != rev {
			t.Fatalf("apply sequence = %v, want %v (order broken)", seq, want)
		}
	}
}

// TestConsumeFailedReloadStopsAndConverges: a failed catch-up reload must not
// spin (the running revision cannot advance), must report the failure for its
// own revision, and the next published event must re-arm convergence.
func TestConsumeFailedReloadStopsAndConverges(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	applier := &fakeApplier{failRevs: map[int64]bool{2: true}}
	stop := runConsume(t, c, applier)
	defer stop()

	rev2, err := c.Publish(burstCfg(1), "t", "v2-fails")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		_, n, _ := applier.record(rev2)
		return n >= 2 // event apply + one catch-up retry, then stop
	}, "failed revision was not retried once by the catch-up check")

	// No spin: give a would-be infinite retry loop time to show up.
	time.Sleep(150 * time.Millisecond)
	seq, n, _ := applier.record(rev2)
	if n != 2 {
		t.Fatalf("revision %d applied %d times, want exactly 2 (event + one catch-up retry): %v", rev2, n, seq)
	}
	if st := c.WaitForApply(rev2, time.Second); st.Status != "failed" {
		t.Fatalf("apply status for %d = %q, want failed", rev2, st.Status)
	}

	rev3, err := c.Publish(burstCfg(2), "t", "v3-recovers")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		return applier.RunningRevision() == rev3
	}, "consumer did not converge after a later successful publish")
	if st := c.WaitForApply(rev3, time.Second); st.Status != "applied" || st.Revision != rev3 {
		t.Fatalf("apply status for %d = %+v, want applied", rev3, st)
	}
}

// TestMissedSince pins the catch-up decision: behind the active revision =
// missed (events were dropped); caught up or no active config = not missed.
func TestMissedSince(t *testing.T) {
	c, err := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if !c.MissedSince(0) {
		t.Fatal("rev 0 behind active revision must count as missed")
	}
	cur, _ := c.Current()
	if c.MissedSince(cur) {
		t.Fatalf("running at the active revision %d must not count as missed", cur)
	}
	next, err := c.Publish(burstCfg(1), "t", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if !c.MissedSince(cur) {
		t.Fatal("running behind the newly published revision must count as missed")
	}
	if c.MissedSince(next) {
		t.Fatalf("running at %d must not count as missed", next)
	}
}
