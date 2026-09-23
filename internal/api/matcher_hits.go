// Micro-engine rule hit counters: GET /api/policy/micro-rules/hits reports
// the in-memory per-rule hit counts (config.Policy.Matchers), aligned with
// the live configuration so removed rules are not listed. Counters are
// process-level and reset on restart; they are independent of the per-rule
// audit toggle (log_enabled rules and silent rules are both counted).
package api

import (
	"net/http"

	"github.com/kingmoat/kingmoat/internal/stages"
)

// microRuleHit is one rule's hit-count entry.
type microRuleHit struct {
	Rule  string `json:"rule"`
	Count int64  `json:"count"`
}

// microRuleHitsResponse is the /api/policy/micro-rules/hits payload: one
// entry per configured micro-engine rule (including disabled ones), plus
// the sum over the listed rules.
type microRuleHitsResponse struct {
	Total int64          `json:"total"`
	Items []microRuleHit `json:"items"`
}

// handleMicroRuleHits serves GET /api/policy/micro-rules/hits.
func (s *Server) handleMicroRuleHits(w http.ResponseWriter, r *http.Request) {
	out := microRuleHitsResponse{Items: []microRuleHit{}}
	_, cfg := s.opts.Center.Current()
	counts := stages.MatcherHitCounts()
	if cfg != nil && cfg.Policy != nil {
		for i := range cfg.Policy.Matchers {
			name := cfg.Policy.Matchers[i].Name
			n := counts[name]
			out.Items = append(out.Items, microRuleHit{Rule: name, Count: n})
			out.Total += n
		}
	}
	writeJSON(w, http.StatusOK, out)
}
