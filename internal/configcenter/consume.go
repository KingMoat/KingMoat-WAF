package configcenter

import (
	"context"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Applier is the data-plane surface the consume loop drives (satisfied by
// *proxy.Handler). Reload must apply exactly the (cfg, rev) pair it receives
// and RunningRevision must report the revision the CURRENT plane state was
// built from, so the catch-up logic can tell applied revisions from dropped
// ones.
type Applier interface {
	Reload(cfg *config.Config, rev int64) error
	RunningRevision() int64
}

// MissedSince reports whether a consumer that has applied up to runningRev is
// behind the center's active revision — the signature of published events
// dropped by the bounded subscribe buffer — so the consumer must catch up by
// re-applying Current(). A center without an active config never counts as
// missed.
func (c *Center) MissedSince(runningRev int64) bool {
	rev, cfg := c.Current()
	return cfg != nil && runningRev < rev
}

// Consume runs the hot-reload consumer loop until ctx is done. Every received
// RevEvent is applied with its own snapshot — never Current(): by the time a
// slow consumer handles revision N a newer revision may already be active,
// and applying Current() would mispair the reload result reported for N.
//
// The subscribe channel is bounded; a burst of publishes while a reload is
// slow can overflow it and silently drop events (the old "subscriber will
// pick the revision up on next read" default-branch comment never held:
// consumers only react to channel receipts). After each event the loop
// therefore checks MissedSince and, while the data plane is behind, re-applies
// the center's current (revision, config) snapshot until it catches up. The
// catch-up snapshot is read atomically, so the apply outcome reported through
// SetApplyStatus is always paired with the exact revision it belongs to; a
// failed catch-up reload stops the loop (the running revision cannot advance,
// and retrying the same config inline would spin) — the next published event
// re-arms the check.
//
// A revision monotonicity guard wraps both receive paths (the main select
// and the post-apply drain): an event whose revision is not newer than the
// running one is skipped outright — no apply, no SetApplyStatus write, no
// after callback. Without the guard, a catch-up that jumped ahead while a
// failed drain apply left older events queued would re-apply those stale
// snapshots afterwards and roll the data plane back to an older revision —
// a transient but real config regression (security-relevant: rules briefly
// revert to an older set). A failed apply never advances the running
// revision, so the guard cannot suppress a genuine retry of the same
// revision.
//
// SetApplyStatus is called here, not by the caller, so every revision the
// loop actually applies gets an apply outcome for WaitForApply. Revisions
// that were dropped by the buffer overflow and closed over by a catch-up
// jump intentionally have none (they were never applied) — publishers
// waiting on such a revision observe pending, which is the honest outcome.
// The after callback (may be nil) runs after every apply attempt, success
// or failure, with the event that was applied.
func (c *Center) Consume(ctx context.Context, applier Applier, after func(ev RevEvent, applyErr error)) {
	ch, cancel := c.Subscribe()
	defer cancel()

	applyOne := func(rev int64, cfg *config.Config) bool {
		err := applier.Reload(cfg, rev)
		c.SetApplyStatus(rev, err)
		if after != nil {
			after(RevEvent{Rev: rev, Config: cfg}, err)
		}
		return err == nil
	}
	catchUp := func() {
		for c.MissedSince(applier.RunningRevision()) {
			rev, cfg := c.Current()
			if cfg == nil {
				return
			}
			if !applyOne(rev, cfg) {
				return
			}
		}
	}

	// Boot catch-up: revisions published before this call had no subscriber
	// to fan out to, so the loop would idle at the boot revision until the
	// NEXT publish re-arms the check. One catch-up here converges
	// immediately (a no-op when the plane already runs the active revision).
	catchUp()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			// Monotonic guard (see the doc comment above): never re-apply a
			// revision the plane already runs or has moved past.
			if ev.Rev <= applier.RunningRevision() {
				continue
			}
			if !applyOne(ev.Rev, ev.Config) {
				catchUp() // failed reload: try to converge to the center's revision
				continue
			}
			// Drain already-queued events first, so every queued revision
			// keeps its own apply outcome before any catch-up jumps ahead.
		drain:
			for {
				select {
				case ev2 := <-ch:
					if ev2.Rev <= applier.RunningRevision() {
						continue
					}
					if !applyOne(ev2.Rev, ev2.Config) {
						break drain
					}
				default:
					break drain
				}
			}
			catchUp()
		}
	}
}
