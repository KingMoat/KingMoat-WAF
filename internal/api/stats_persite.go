// Per-site daily statistics: /api/stats/per-site merges today's per-site
// request counters (metrics, restart-safe within the day) with today's
// attack counts from the audit store, feeding the site-list badges.
package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/metrics"
)

// perSiteStat is one row of the /api/stats/per-site payload.
type perSiteStat struct {
	Site     string `json:"site"`
	Requests int64  `json:"requests"`
	Attacks  int    `json:"attacks"`
}

// perSiteResponse is the /api/stats/per-site payload.
type perSiteResponse struct {
	WindowStart string        `json:"window_start"`
	WindowEnd   string        `json:"window_end"`
	Sites       []perSiteStat `json:"sites"`
}

// handleStatsPerSite serves GET /api/stats/per-site: requests come from the
// daily per-site counters (rolled over at local midnight), attacks from the
// audit store under the same criteria as the rule-hit card. Configured
// sites without traffic today are reported with zero counts.
func (s *Server) handleStatsPerSite(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	out := perSiteResponse{
		WindowStart: dayStart.Format(time.RFC3339),
		WindowEnd:   now.Format(time.RFC3339),
		Sites:       []perSiteStat{},
	}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	_, cfg := s.opts.Center.Current()

	// Attack counts from the audit store, gated + time-bounded like every
	// audit query; a store without the site-attack capability (noop) simply
	// contributes no attack counts.
	var hits []logstore.TopHit
	if counter, ok := s.opts.Logs.(logstore.SiteAttackCounter); ok {
		release, timeout, gated := s.auditQueryGate(cfg)
		if !gated {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
				"degraded": true,
			})
			return
		}
		defer release()
		type attackResult struct {
			hits []logstore.TopHit
			err  error
		}
		done := make(chan attackResult, 1)
		go func() {
			h, err := counter.SiteAttackCounts(dayStart, now)
			done <- attackResult{h, err}
		}()
		select {
		case res := <-done:
			if res.err != nil {
				writeErr(w, http.StatusInternalServerError, res.err)
				return
			}
			hits = res.hits
		case <-time.After(timeout):
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{
				"error": "per-site attack query timed out; narrow the window or ship logs to an external store",
			})
			return
		}
	}

	out.Sites = mergePerSite(cfg, metrics.SnapshotDailyRequestsBySite(), hits)
	writeJSON(w, http.StatusOK, out)
}

// mergePerSite unions the daily request sites, the attack sites and the
// configured site list (first domain each, zero-filled), skips no_site
// entries and orders by requests desc, then site asc.
func mergePerSite(cfg *config.Config, requests map[string]int64, attacks []logstore.TopHit) []perSiteStat {
	rows := map[string]*perSiteStat{}
	get := func(site string) *perSiteStat {
		st, ok := rows[site]
		if !ok {
			st = &perSiteStat{Site: site}
			rows[site] = st
		}
		return st
	}
	for site, n := range requests {
		if site == "" {
			continue
		}
		get(site).Requests += n
	}
	for _, h := range attacks {
		if h.Key == "" {
			continue
		}
		get(h.Key).Attacks += h.Count
	}
	if cfg != nil {
		for i := range cfg.Sites {
			if len(cfg.Sites[i].Domains) == 0 || cfg.Sites[i].Domains[0] == "" {
				continue
			}
			get(cfg.Sites[i].Domains[0])
		}
	}
	out := make([]perSiteStat, 0, len(rows))
	for _, st := range rows {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Site < out[j].Site
	})
	return out
}
