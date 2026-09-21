// Policy-page rule-hit analytics: /api/stats/rules ranks the most-hit rules
// over a bounded window (SQL aggregation on the SQLite audit store), feeding
// the micro-engine tab statistics card and one-click drill-down to the log
// view (?rule=<id>).
package api

import (
	"net/http"
	"time"

	"github.com/kingmoat/kingmoat/internal/logstore"
)

// ruleHitItem is one ranked rule entry of the /api/stats/rules payload.
type ruleHitItem struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// rulesStatsResponse is the /api/stats/rules payload: total is the number of
// attack events in the window under the same criteria as items (unbounded by
// the top limit).
type rulesStatsResponse struct {
	Total int64         `json:"total"`
	Items []ruleHitItem `json:"items"`
}

// handleStatsRules serves GET /api/stats/rules?hours=24&limit=10
// (hours: 1..720 default 24; limit: 1..50 default 10).
func (s *Server) handleStatsRules(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n := atoiSafe2(v); n > 0 {
			hours = n
		}
	}
	if hours > 720 {
		hours = 720
	}
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n := atoiSafe2(v); n > 0 {
			limit = n
		}
	}
	if limit > 50 {
		limit = 50
	}
	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)

	out := rulesStatsResponse{Items: []ruleHitItem{}}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	top, ok := s.opts.Logs.(logstore.RuleTopHitter)
	if !ok {
		writeJSON(w, http.StatusOK, out)
		return
	}
	_, cfg := s.opts.Center.Current()
	release, timeout, gated := s.auditQueryGate(cfg)
	if !gated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return
	}
	defer release()
	type ruleResult struct {
		hits  []logstore.TopHit
		total int64
		err   error
	}
	done := make(chan ruleResult, 1)
	go func() {
		hits, total, err := top.RuleTopHits(since, until, limit)
		done <- ruleResult{hits, total, err}
	}()
	var res ruleResult
	select {
	case res = <-done:
	case <-time.After(timeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{
			"error": "rule stats query timed out; narrow the window or ship logs to an external store",
		})
		return
	}
	if res.err != nil {
		writeErr(w, http.StatusInternalServerError, res.err)
		return
	}
	out.Total = res.total
	for _, h := range res.hits {
		out.Items = append(out.Items, ruleHitItem{Rule: h.Key, Count: h.Count})
	}
	writeJSON(w, http.StatusOK, out)
}
