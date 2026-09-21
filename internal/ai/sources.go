// Shared assembly of the assistant DataSources for every management-plane
// wiring point (all-in-one console and standalone kingmoat-server). Both
// assembly points must expose the SAME field set to the tool layer: building
// them here means a new DataSources field is wired once and the parity test
// (TestNewCenterSourcesWiresEveryField) fails if anyone forgets — the two
// mains previously drifted three times (missing rebuild, nil func, missing
// Logs), each surfacing as "tool unavailable" in production.
package ai

import (
	"encoding/json"
	"time"

	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// LogSource serves audit-event queries to the assistant tools. It is the
// same method set the DataSources.Logs anonymous interface always had,
// promoted to a named type so assembly points can pass their store.
type LogSource interface {
	Query(q logstore.LogQuery) ([]logstore.Event, error)
	Aggregate(since, until time.Time) (*logstore.Summary, error)
	Recent(n int) []logstore.Event
}

// NewCenterSources builds the assistant data sources for a center-backed
// wiring point. `logs` may be nil (the log tools then degrade to
// "log source not wired" — acceptable only when a form truly has no audit
// store); `stats` is the one genuinely form-specific closure (the all-in-one
// exposes full counters, the standalone server reports that counters live on
// data planes).
func NewCenterSources(center *configcenter.Center, logs LogSource, version string, stats func() map[string]any) *DataSources {
	return &DataSources{
		Version: version,
		Logs:    logs,
		Current: func() (int64, json.RawMessage) {
			rev, cfg := center.Current()
			b, merr := json.Marshal(cfg)
			if merr != nil {
				return rev, nil
			}
			return rev, b
		},
		Revisions: func(limit int) ([]RevisionInfo, error) {
			revs, rerr := center.Store().ListRevisions(limit)
			if rerr != nil {
				return nil, rerr
			}
			out := make([]RevisionInfo, 0, len(revs))
			for _, rv := range revs {
				out = append(out, RevisionInfo{ID: rv.ID, CreatedAt: rv.CreatedAt, Author: rv.Author, Note: rv.Note})
			}
			return out, nil
		},
		Stats: stats,
		Status: func() map[string]any {
			rev, cfg := center.Current()
			domains := make([]string, 0, len(cfg.Sites))
			for i := range cfg.Sites {
				domains = append(domains, cfg.Sites[i].Domains...)
			}
			return map[string]any{
				"version": version, "revision": rev, "sites": len(cfg.Sites),
				"site_domains": domains, "time": time.Now().UTC().Format(time.RFC3339),
			}
		},
	}
}

// compile-time guard: the shared builder must keep satisfying the tool
// contract for the concrete store the two assembly points pass in.
var _ LogSource = (*logstore.SQLiteStore)(nil)
