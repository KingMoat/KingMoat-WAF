// In-memory hit counters for micro-engine (matcher) rules. Counters are
// process-level (surviving config hot-reloads, reset on restart) so the
// console can show per-rule hit counts independently of audit logging:
// rules with logging disabled are still counted.
package stages

import (
	"sort"
	"sync"
	"sync/atomic"
)

// matcherHits maps a matcher rule name to its monotonic hit counter.
// Entries for rules removed from the config stay behind (bounded by the
// number of distinct rule names ever seen); the API layer filters them out
// against the live configuration.
var matcherHits sync.Map // rule name → *atomic.Int64

// matcherHitInc bumps the hit counter of one matcher rule (no-op on empty
// names).
func matcherHitInc(name string) {
	if name == "" {
		return
	}
	v, _ := matcherHits.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// MatcherHitCounts returns a snapshot of the per-rule hit counters
// (rule name → count). In-memory only: resets on process restart.
func MatcherHitCounts() map[string]int64 {
	out := make(map[string]int64)
	matcherHits.Range(func(k, v any) bool {
		name, _ := k.(string)
		if c, ok := v.(*atomic.Int64); ok {
			out[name] = c.Load()
		}
		return true
	})
	return out
}

// MatcherHitNames returns the rule names that have a counter registered,
// sorted (diagnostics helper).
func MatcherHitNames() []string {
	names := make([]string, 0, 8)
	matcherHits.Range(func(k, _ any) bool {
		if name, ok := k.(string); ok {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names
}
