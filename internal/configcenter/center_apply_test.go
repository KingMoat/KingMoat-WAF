package configcenter

import (
	"errors"
	"testing"
	"time"
)

// consume drains one event from ch (bounded wait).
func consume(t *testing.T, ch <-chan RevEvent) RevEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber not notified")
		return RevEvent{}
	}
}

// TestWaitForApplyExactRevision locks the corrected matching semantics: a
// newer revision's outcome must never settle the wait for an older revision
// (the old ">= rev" check turned "N failed, N+1 applied" into "N applied").
func TestWaitForApplyExactRevision(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	ch, cancel := c.Subscribe()
	defer cancel()

	rev2, err := c.Publish(twoSiteCfg(), "t", "v2")
	if err != nil {
		t.Fatal(err)
	}
	_ = consume(t, ch)

	// Consumer reports rev2 applied first (out-of-order-ish arrival).
	c.SetApplyStatus(rev2, nil)

	// A waiter for the older revision 1 must NOT read rev2's applied result.
	if st := c.WaitForApply(1, 150*time.Millisecond); st.Status != "pending" {
		t.Fatalf("wait for rev1 got %q (rev %d), want pending (rev2 result must not match)", st.Status, st.Revision)
	}

	// Now the consumer reports rev1 failed: exactly rev1's outcome settles.
	errBoom := errors.New("site router: read tls_cert: open /data/c.pem: no such file")
	c.SetApplyStatus(1, errBoom)
	if st := c.WaitForApply(1, time.Second); st.Status != "failed" || st.Error != errBoom.Error() || st.Revision != 1 {
		t.Fatalf("wait for rev1 = %+v, want failed with exact error", st)
	}
	// And rev2 keeps its own applied outcome.
	if st := c.WaitForApply(2, time.Second); st.Status != "applied" || st.Revision != 2 {
		t.Fatalf("wait for rev2 = %+v, want applied", st)
	}
}

// TestWaitForApplyTimeoutPending: no outcome for the requested revision within
// the budget → pending (even when an older or newer revision has a result).
func TestWaitForApplyTimeoutPending(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	ch, cancel := c.Subscribe()
	defer cancel()

	rev2, err := c.Publish(twoSiteCfg(), "t", "v2")
	if err != nil {
		t.Fatal(err)
	}
	_ = consume(t, ch)

	c.SetApplyStatus(1, nil) // only rev1 reported
	if st := c.WaitForApply(rev2, 150*time.Millisecond); st.Status != "pending" || st.Revision != rev2 {
		t.Fatalf("wait for rev2 = %+v, want pending for rev %d", st, rev2)
	}
}

// TestWaitForApplyNoSubscribers: remote/API-only mode has no in-process
// consumer → pending immediately (no timeout wait).
func TestWaitForApplyNoSubscribers(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	start := time.Now()
	if st := c.WaitForApply(1, 3*time.Second); st.Status != "pending" {
		t.Fatalf("status = %q, want pending", st.Status)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("no-subscriber wait took %v, want immediate", elapsed)
	}
}

// TestEventCarriesRevisionSnapshot: each event carries the config of ITS
// revision, so a consumer draining a burst of publishes applies/reports the
// right pairing (main.go hot-reload race regression).
func TestEventCarriesRevisionSnapshot(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	ch, cancel := c.Subscribe()
	defer cancel()

	if _, err := c.Publish(twoSiteCfg(), "t", "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(seedCfg(), "t", "v3 back to one site"); err != nil {
		t.Fatal(err)
	}

	ev2 := consume(t, ch)
	if ev2.Rev != 2 || len(ev2.Config.Sites) != 2 {
		t.Fatalf("event rev=%d sites=%d, want rev2 with 2 sites", ev2.Rev, len(ev2.Config.Sites))
	}
	ev3 := consume(t, ch)
	if ev3.Rev != 3 || len(ev3.Config.Sites) != 1 {
		t.Fatalf("event rev=%d sites=%d, want rev3 with 1 site", ev3.Rev, len(ev3.Config.Sites))
	}
	// The center's current config is rev3's, but ev2's snapshot must still be
	// the two-site one (Current() would have mispaired it before the fix).
	if cur, curCfg := c.Current(); cur != 3 || len(curCfg.Sites) != 1 {
		t.Fatalf("current rev=%d sites=%d, want rev3 with 1 site", cur, len(curCfg.Sites))
	}
}

// TestRevConfig: per-revision snapshots come from the store, so any revision
// (not just the active one) can be rebuilt for targeted reloads.
func TestRevConfig(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	if _, err := c.Publish(twoSiteCfg(), "t", "v2"); err != nil {
		t.Fatal(err)
	}
	cfg1, err := c.RevConfig(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg1.Sites) != 1 {
		t.Fatalf("rev1 sites=%d, want 1", len(cfg1.Sites))
	}
	cfg2, err := c.RevConfig(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Sites) != 2 {
		t.Fatalf("rev2 sites=%d, want 2", len(cfg2.Sites))
	}
	if _, err := c.RevConfig(99); err == nil {
		t.Fatal("unknown revision must error")
	}
}

// TestApplyStatusHistoryPruned: per-revision results are queryable and the
// registry stays bounded.
func TestApplyStatusHistoryPruned(t *testing.T) {
	c, _ := Open(t.TempDir()+"/cc.db", seedCfg(), quiet())
	defer c.Close()

	for i := int64(0); i < applyHistoryLimit+10; i++ {
		c.SetApplyStatus(i+2, nil)
	}
	if _, ok := c.ApplyStatusFor(2); ok {
		t.Fatal("oldest entry should have been pruned")
	}
	st, ok := c.ApplyStatusFor(applyHistoryLimit + 11)
	if !ok || st.Status != "applied" {
		t.Fatalf("newest entry = %+v ok=%v, want applied", st, ok)
	}
}
