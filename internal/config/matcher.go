// MicroEngine-style conditional rules: user-composed matching rules built
// from field/operator/value conditions combined with AND/OR logic, each with
// an action (deny / allow(trusted) / monitor). Managed from the strategy
// page's visual rule builder.
package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Matcher fields extract values from the request.
const (
	FieldClientIP  = "client_ip"
	FieldHostname  = "hostname"
	FieldPath      = "path"
	FieldURI       = "uri"
	FieldMethod    = "method"
	FieldUserAgent = "user_agent"
	FieldReferer   = "referer"
	FieldBody      = "body"
	// Composite fields: "header:Name", "query:Param", "cookie:Name"
)

// Matcher operators.
const (
	OpEq          = "eq"
	OpNotEq       = "neq"
	OpContains    = "contains"
	OpNotContains = "not_contains"
	OpPrefix      = "prefix"
	OpSuffix      = "suffix"
	OpRegex       = "regex"
	OpCIDR        = "cidr"
	OpIn          = "in" // value is a comma-separated list
)

// Matcher actions.
const (
	ActionDeny    = "deny"
	ActionAllow   = "allow"   // mark trusted, skip later stages
	ActionMonitor = "monitor" // record only, forward
	ActionDisable = "disable" // switch detection modules off for the matched sites
)

// StageCoraza is the signature-detection stage name. The scoped form
// "coraza:<category>" (e.g. "coraza:sqli") disables a single CRS detection
// category instead of the whole stage.
const StageCoraza = "coraza"

// MaxScopedCorazaRulesPerSite caps the per-site number of enabled matcher
// disable rules carrying coraza:<category> scopes: every non-empty subset
// union of their category sets (≤ 2^n-1 distinct sets, n ≤ cap) is
// pre-compiled into a variant engine at publish time, so any combination of
// simultaneously-hit rules resolves to an exact variant. Enforced at config
// validation (publish is rejected up front); the coraza stage build shares
// the same collector, so it can only observe a violation if validation was
// bypassed.
const MaxScopedCorazaRulesPerSite = 4

// MaxTotalCorazaVariants caps the global sum of pre-compiled variant engines
// across all sites (subset-union variants included). Enforced at config
// validation only (publish is rejected up front).
const MaxTotalCorazaVariants = 64

// DisableableStages lists the detection modules a "disable" rule may switch
// off for a site. Access-control stages (acl/exceptions/matcher/penalty) are
// deliberately NOT disableable - they guard the policy itself.
var DisableableStages = []string{
	"botdetect", "botchallenge", "captcha", "ratelimit", "semantic", StageCoraza,
}

func isDisableableStage(name string) bool {
	for _, s := range DisableableStages {
		if s == name {
			return true
		}
	}
	return false
}

// MatcherCondition is one field/op/value predicate.
type MatcherCondition struct {
	Field string `json:"field"` // client_ip|hostname|path|uri|method|user_agent|referer|body|header:X|query:Y|cookie:Z
	Op    string `json:"op"`    // eq|neq|contains|not_contains|prefix|suffix|regex|cidr|in
	Value string `json:"value"`
}

// MatcherRule is one conditional rule.
type MatcherRule struct {
	Name       string             `json:"name"`
	Enabled    bool               `json:"enabled"`
	Sites      []string           `json:"sites,omitempty"` // empty = all sites
	Action     string             `json:"action"`          // deny|allow|monitor|disable
	Logic      string             `json:"logic"`           // "and" | "or"
	Conditions []MatcherCondition `json:"conditions"`
	// DisableStages lists detection modules switched off for the matched
	// sites while this rule is enabled (Action = disable).
	DisableStages []string `json:"disable_stages,omitempty"`
	// LogEnabled controls audit logging for this rule's hits (default
	// false: hits are counted but produce no audit events; true: each hit
	// writes an audit event carrying "matcher/<name>", enabling per-rule
	// drill-down from the console). The rule action is unaffected.
	LogEnabled bool   `json:"log_enabled,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

// Validate checks one matcher rule.
func (m *MatcherRule) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("matcher: name is required")
	}
	switch m.Action {
	case ActionDeny, ActionAllow, ActionMonitor:
	case ActionDisable:
		if len(m.DisableStages) == 0 {
			return fmt.Errorf("matcher %q: disable action requires at least one module in disable_stages", m.Name)
		}
		hasCoraza, hasScoped := false, false
		for i, st := range m.DisableStages {
			if cat, ok := strings.CutPrefix(st, StageCoraza+":"); ok {
				cat = strings.ToLower(strings.TrimSpace(cat))
				if !ValidWAFCategory(cat) {
					return fmt.Errorf("matcher %q: stage %q is not a valid coraza category scope (valid categories: %s)", m.Name, st, strings.Join(WAFDetectionCategories, ", "))
				}
				m.DisableStages[i] = StageCoraza + ":" + cat
				hasScoped = true
				continue
			}
			if st == StageCoraza {
				hasCoraza = true
				continue
			}
			if !isDisableableStage(st) {
				return fmt.Errorf("matcher %q: stage %q is not disableable (allowed: botdetect, botchallenge, captcha, ratelimit, semantic, coraza, coraza:<category>)", m.Name, st)
			}
		}
		if hasCoraza && hasScoped {
			return fmt.Errorf("matcher %q: disable_stages cannot mix %q with %q forms; split into two rules (one disabling the whole coraza stage, one per category scope)", m.Name, StageCoraza, StageCoraza+":<category>")
		}
	default:
		return fmt.Errorf("matcher %q: action must be deny, allow, monitor or disable", m.Name)
	}
	m.Logic = strings.ToLower(m.Logic)
	if m.Logic == "" {
		m.Logic = "and"
	}
	if m.Logic != "and" && m.Logic != "or" {
		return fmt.Errorf("matcher %q: logic must be and or or", m.Name)
	}
	if len(m.Conditions) == 0 {
		return fmt.Errorf("matcher %q: at least one condition is required", m.Name)
	}
	for i := range m.Conditions {
		if err := m.Conditions[i].Validate(); err != nil {
			return fmt.Errorf("matcher %q conditions[%d]: %w", m.Name, i, err)
		}
	}
	return nil
}

// Validate checks one condition.
func (c *MatcherCondition) Validate() error {
	composite := strings.HasPrefix(c.Field, "header:") ||
		strings.HasPrefix(c.Field, "query:") || strings.HasPrefix(c.Field, "cookie:")
	switch {
	case composite:
		name := c.Field[strings.Index(c.Field, ":")+1:]
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("field %q: composite name is empty", c.Field)
		}
	case c.Field == FieldClientIP || c.Field == FieldHostname || c.Field == FieldPath ||
		c.Field == FieldURI || c.Field == FieldMethod || c.Field == FieldUserAgent ||
		c.Field == FieldReferer || c.Field == FieldBody:
	default:
		return fmt.Errorf("unknown field %q", c.Field)
	}
	switch c.Op {
	case OpEq, OpNotEq, OpContains, OpNotContains, OpPrefix, OpSuffix, OpRegex, OpCIDR, OpIn:
	default:
		return fmt.Errorf("unknown operator %q", c.Op)
	}
	if c.Op == OpCIDR && !isCIDRValue(c.Value) && !isIPValue(c.Value) {
		return fmt.Errorf("cidr operator requires an IP/CIDR value, got %q", c.Value)
	}
	if c.Op == OpRegex {
		if _, err := CompileRegex(c.Value); err != nil {
			return fmt.Errorf("regex: %w", err)
		}
	}
	return nil
}

// CompileRegex compiles a matcher regex (RE2).
func CompileRegex(v string) (func(string) bool, error) {
	re, err := regexp.Compile(v)
	if err != nil {
		return nil, err
	}
	return re.MatchString, nil
}

// helpers shared with the matcher stage.
func isCIDRValue(s string) bool { return strings.Contains(s, "/") }

func isIPValue(s string) bool { return net.ParseIP(strings.TrimSpace(s)) != nil }

// ScopedCorazaExclusionSets collects the de-duplicated CRS exclusion sets a
// site needs variant engines for: the union of every non-empty subset of the
// enabled coraza:<category> disable rules' category sets that apply to the
// site's FIRST domain. The disable registry reports exact unions of
// currently-hit rules, so each subset combination must resolve to a
// pre-compiled variant — enumerating only per-rule sets plus the full union
// would silently fall back to the main engine for partial multi-rule hits.
// Shared by config validation (publish-time caps) and the coraza stage build
// so both sides derive identical variant sets. An error means the per-site
// scoped-rule cap is exceeded.
func ScopedCorazaExclusionSets(p *Policy, domains []string) ([]map[string]bool, error) {
	if p == nil {
		return nil, nil
	}
	var ruleSets []map[string]bool
	for i := range p.Matchers {
		r := &p.Matchers[i]
		if !r.Enabled || r.Action != ActionDisable {
			continue
		}
		if !ruleAppliesToSite(r.Sites, domains) {
			continue
		}
		set := map[string]bool{}
		for _, st := range r.DisableStages {
			if cat, ok := strings.CutPrefix(st, StageCoraza+":"); ok {
				set[cat] = true
			}
		}
		if len(set) == 0 {
			continue
		}
		ruleSets = append(ruleSets, set)
		if len(ruleSets) > MaxScopedCorazaRulesPerSite {
			return nil, fmt.Errorf("too many coraza:<category> disable rules apply to this site (max %d, got %d): split or merge rules",
				MaxScopedCorazaRulesPerSite, len(ruleSets))
		}
	}
	if len(ruleSets) == 0 {
		return nil, nil
	}
	// Enumerate the union of every non-empty subset of rule sets. The disable
	// registry only ever reports exact unions of currently-hit rules, so each
	// subset combination must resolve to a pre-compiled variant.
	seen := make(map[string]bool)
	var out []map[string]bool
	for mask := 1; mask < 1<<len(ruleSets); mask++ {
		union := map[string]bool{}
		for bit := 0; bit < len(ruleSets); bit++ {
			if mask&(1<<bit) == 0 {
				continue
			}
			for cat := range ruleSets[bit] {
				union[cat] = true
			}
		}
		k := ScopedCorazaSetKey(union)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, union)
	}
	return out, nil
}

// ScopedCorazaSetKey canonicalizes an exclusion set to the variant map key:
// categories in detection-category order, comma-joined.
func ScopedCorazaSetKey(excluded map[string]bool) string {
	var sb strings.Builder
	for _, cat := range WAFDetectionCategories {
		if excluded[cat] {
			if sb.Len() > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(cat)
		}
	}
	return sb.String()
}

// ruleAppliesToSite mirrors the matcher stage's site scoping: the runtime
// records hits against the site's FIRST domain only (rc.Site.Domain is
// firstDomain(cfg)), so scoped rules only ever fire for sites whose first
// domain matches — counting any other domain would reserve variant engines
// the runtime can never select. Empty Sites = all sites.
func ruleAppliesToSite(sites, domains []string) bool {
	if len(sites) == 0 {
		return true
	}
	if len(domains) == 0 {
		return false
	}
	for _, s := range sites {
		if strings.EqualFold(s, domains[0]) {
			return true
		}
	}
	return false
}
