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

// DisableableStages lists the detection modules a "disable" rule may switch
// off for a site. Access-control stages (acl/exceptions/matcher/penalty) are
// deliberately NOT disableable - they guard the policy itself.
var DisableableStages = []string{
	"botdetect", "botchallenge", "captcha", "ratelimit", "semantic", "coraza",
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
		for _, st := range m.DisableStages {
			if !isDisableableStage(st) {
				return fmt.Errorf("matcher %q: stage %q is not disableable (allowed: botdetect, botchallenge, captcha, ratelimit, semantic, coraza)", m.Name, st)
			}
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
