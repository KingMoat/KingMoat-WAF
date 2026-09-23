// StageDisableRegistry tracks per-site detection-module disable state set by
// matcher "disable" rules. A fresh registry is created per configuration
// build, so publishing a config resets the disable state (documented
// behaviour: disabling is re-declared by the rules that produced it).
package stages

import (
	"sort"
	"strings"
	"sync"
)

// StageDisableRegistry maps site domain -> set of disabled stage names.
type StageDisableRegistry struct {
	mu sync.RWMutex
	m  map[string]map[string]struct{}
}

// NewStageDisableRegistry creates an empty registry.
func NewStageDisableRegistry() *StageDisableRegistry {
	return &StageDisableRegistry{}
}

// Disable switches the stage off for the site.
func (r *StageDisableRegistry) Disable(site, stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = make(map[string]map[string]struct{})
	}
	site = strings.ToLower(site)
	if r.m[site] == nil {
		r.m[site] = make(map[string]struct{})
	}
	r.m[site][stage] = struct{}{}
}

// Disabled reports whether the stage is switched off for the site.
// Implements pipeline.StageGate.
func (r *StageDisableRegistry) Disabled(site, stage string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := r.m[strings.ToLower(site)]
	_, ok := set[stage]
	return ok
}

// Snapshot returns a read-only copy of the current per-site disable state
// (site domain → sorted disabled stage/category names), for the
// /api/policy/disable-state visibility endpoint. The fresh registry per
// config build means a snapshot always describes the live process state
// since the last publish.
func (r *StageDisableRegistry) Snapshot() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]string, len(r.m))
	for site, set := range r.m {
		list := make([]string, 0, len(set))
		for st := range set {
			list = append(list, st)
		}
		sort.Strings(list)
		out[site] = list
	}
	return out
}