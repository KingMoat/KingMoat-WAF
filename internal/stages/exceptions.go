package stages

import (
	"context"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Exceptions implements the false-positive whitelist ("一键加白"): requests
// matching a configured site+path exception skip the referenced rule or the
// whole detection chain (RuleID empty → trusted). Numeric Coraza rule IDs are
// handled statically via SecRuleRemoveById at WAF build time; stage-level
// rules ("semantic/sqli", ...) are skipped dynamically here.
type Exceptions struct {
	byDomain map[string][]config.Exception
}

// NewExceptions builds the stage from cfg.Policy.Exceptions.
func NewExceptions(cfg *config.Config) *Exceptions {
	byDomain := map[string][]config.Exception{}
	if cfg.Policy == nil {
		return &Exceptions{byDomain: byDomain}
	}
	for _, e := range cfg.Policy.Exceptions {
		key := strings.ToLower(e.Site) // empty key = all sites
		byDomain[key] = append(byDomain[key], e)
	}
	return &Exceptions{byDomain: byDomain}
}

// Name implements pipeline.Stage.
func (x *Exceptions) Name() string { return "exceptions" }

// Inspect implements pipeline.Stage.
func (x *Exceptions) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true {
		return pipeline.Allow()
	}
	domain := strings.ToLower(rc.Site.Domain)
	list := append(x.byDomain[domain], x.byDomain[""]...)
	if len(list) == 0 {
		return pipeline.Allow()
	}
	excepted := map[string]bool{}
	for _, e := range list {
		if !e.Matches(domain, rc.Request.URL.Path) {
			continue
		}
		if e.RuleID == "" {
			// Whole-path exception: mark trusted (skips every later stage).
			rc.Values["trusted"] = true
			rc.Values["exception_applied"] = e.Comment
			return pipeline.Allow()
		}
		excepted[e.RuleID] = true
	}
	if len(excepted) > 0 {
		rc.Values["excepted_rules"] = excepted
	}
	return pipeline.Allow()
}

// Excepted reports whether the rule is whitelisted for this request.
// rc may be nil (returns false).
func Excepted(rc *pipeline.RequestContext, ruleID string) bool {
	if rc == nil {
		return false
	}
	m, _ := rc.Values["excepted_rules"].(map[string]bool)
	return m[ruleID]
}
