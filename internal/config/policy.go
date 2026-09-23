package config

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

// Exception is a false-positive whitelist entry ("误报加白"): requests
// matching site+path skip a specific rule (RuleID) or the whole detection
// chain (RuleID empty → trusted).
type Exception struct {
	Site    string `json:"site"`              // domain; empty matches all sites
	Path    string `json:"path"`              // exact path or prefix
	Prefix  bool   `json:"prefix,omitempty"`  // true → prefix match
	RuleID  string `json:"rule_id,omitempty"` // "semantic/sqli" | "942100" | "" (all)
	Comment string `json:"comment,omitempty"`
}

// Matches reports whether the exception applies to the request.
func (e Exception) Matches(siteDomain, path string) bool {
	if e.Site != "" && !strings.EqualFold(e.Site, siteDomain) {
		return false
	}
	if e.Path == "" {
		return true
	}
	if e.Prefix {
		return strings.HasPrefix(path, e.Path)
	}
	return path == e.Path
}

// Validate checks one exception entry.
func (e Exception) Validate() error {
	if e.Path == "" {
		return fmt.Errorf("policy: exception path is required")
	}
	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("policy: exception path %q must start with /", e.Path)
	}
	return nil
}

// BlockPage customizes the interception page copy. HTML (when set) replaces
// the built-in page entirely; the copy fields only apply to the default page.
type BlockPage struct {
	Title   string `json:"title,omitempty"`   // default "请求被拦截 · Blocked by KingMoat"
	Message string `json:"message,omitempty"` // default explanation line
	Footer  string `json:"footer,omitempty"`  // default product footer
	// HTML is a full custom block page (≤256KB). It supports request-context
	// placeholders ({{request_id}} {{rule_id}} {{reason}} {{client_ip}}
	// {{method}} {{host}} {{url}} {{ua}} {{timestamp}}) that the engine
	// replaces per response. Scripts, inline event handlers and javascript:
	// URLs are rejected at validation time to prevent stored XSS.
	HTML string `json:"html,omitempty"`
}

const (
	maxBlockPageHTML = 256 << 10 // 256KB
)

var (
	// blockEventHandlerRe matches ANY inline event-handler attribute
	// (on<name> with optional whitespace before '='), so handlers beyond an
	// enumerated list (ontoggle, onpageshow, onanimationstart, ...) and
	// HTML5-tolerant spacing like "onload =..." are all rejected.
	blockEventHandlerRe = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
	// blockDangerousURLRe rejects script-executing URL schemes;
	// data:text/html alone is blocked (data: in prose is still allowed).
	blockDangerousURLRe = regexp.MustCompile(`(?i)(javascript|vbscript)\s*:`)
	blockDataHTMLRe     = regexp.MustCompile(`(?i)data\s*:\s*text/html`)
)

// validateBlockHTML rejects custom block-page HTML that embeds scripts,
// inline event handlers or script-executing URL schemes (stored-XSS
// guard; the page is served to every blocked client on the data plane).
// The check runs on the raw input and again on the entity-decoded form,
// so encodings like java&#115;cript: cannot smuggle a scheme or handler
// past a literal match. Defense in depth: the intercept renderer adds a
// script-free Content-Security-Policy on block responses.
func validateBlockHTML(s string) error {
	low := strings.ToLower(s)
	for _, bad := range []string{"<script", "<iframe", "<object", "<embed"} {
		if strings.Contains(low, bad) {
			return fmt.Errorf("block_page: custom html must not contain %q", bad)
		}
	}
	decoded := strings.ToLower(html.UnescapeString(s))
	for _, candidate := range []string{low, decoded} {
		if blockEventHandlerRe.MatchString(candidate) {
			return fmt.Errorf("block_page: custom html must not contain inline event handlers (on*=)")
		}
		if blockDangerousURLRe.MatchString(candidate) {
			return fmt.Errorf("block_page: custom html must not contain javascript:/vbscript: URLs")
		}
		if blockDataHTMLRe.MatchString(candidate) {
			return fmt.Errorf("block_page: custom html must not contain data:text/html URLs")
		}
	}
	return nil
}

// Console holds management-plane access restrictions.
type Console struct {
	// AllowedIPs restricts console/API access to these IPs/CIDRs
	// (empty = no restriction).
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// Validate checks the block-page and console blocks.
func (b *BlockPage) Validate() error {
	if b == nil {
		return nil
	}
	if len(b.HTML) > maxBlockPageHTML {
		return fmt.Errorf("block_page: html exceeds %dKB", maxBlockPageHTML>>10)
	}
	return validateBlockHTML(b.HTML)
}

func (c *Console) Validate() error {
	if c == nil {
		return nil
	}
	for _, cidr := range c.AllowedIPs {
		if !validCIDR(cidr) {
			return fmt.Errorf("console: allowed_ips %q is not a valid IP or CIDR", cidr)
		}
	}
	return nil
}

// ValidateExceptions checks the exception list.
func ValidateExceptions(list []Exception) error {
	for i, e := range list {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("policy: exceptions[%d]: %w", i, err)
		}
	}
	return nil
}

// Policy holds the global detection-policy settings managed from the console
// strategy page: CRS anomaly-score thresholds, custom SecLang rules, the
// global IP blacklist/whitelist and false-positive exceptions.
type Policy struct {
	// InboundThreshold / OutboundThreshold override the CRS anomaly-score
	// thresholds (defaults 5 / 4). Values <= 0 keep the defaults.
	InboundThreshold  int `json:"inbound_threshold,omitempty"`
	OutboundThreshold int `json:"outbound_threshold,omitempty"`
	// CustomRules is global SecLang rule text appended after the CRS for
	// every WAF-enabled site.
	CustomRules string `json:"custom_rules,omitempty"`
	// GlobalACL applies before per-site ACL: blacklist hits are denied,
	// whitelist hits mark the request trusted (skipping later stages).
	GlobalACL *ACLSettings `json:"global_acl,omitempty"`
	// Exceptions are false-positive whitelist entries (log 一键加白).
	Exceptions []Exception `json:"exceptions,omitempty"`
	// Matchers are MicroEngine-style conditional rules (strategy page builder).
	Matchers []MatcherRule `json:"matchers,omitempty"`
	// Penalty is the attack-penalty engine (strategy page): when one client IP
	// accumulates >= Threshold blocked/challenged events within WindowSec it
	// is temporarily banned (deny) or strictly throttled for BanSec.
	Penalty *PenaltySettings `json:"penalty,omitempty"`
	// WAFCategories is the global default CRS detection-category set applied
	// when a site does not configure its own categories (waf.categories).
	// nil = all categories enabled (backward compat); non-nil = the listed
	// categories form the default load set for sites without explicit
	// per-site configuration. Valid values: sqli, xss, rce, lfi, rfi, php,
	// generic, session, java, scanner.
	WAFCategories []string `json:"waf_categories,omitempty"`
}

// PenaltySettings configures the attack-penalty engine: repeated
// blocked/challenged events from one client IP within the window trigger a
// temporary ban (deny) or a strict per-minute throttle.
type PenaltySettings struct {
	// Enabled toggles the engine (default off).
	Enabled bool `json:"enabled"`
	// WindowSec is the counting window (default 600).
	WindowSec int `json:"window_sec,omitempty"`
	// Threshold is the blocked+challenged event count inside the window that
	// triggers the penalty (default 20).
	Threshold int `json:"threshold,omitempty"`
	// BanSec is the penalty duration (default 3600).
	BanSec int `json:"ban_sec,omitempty"`
	// Action selects the penalty mode: "deny" (temporary ban, default) or
	// "throttle" (allow at most ThrottlePerMin requests per minute).
	Action string `json:"action,omitempty"`
	// ThrottlePerMin is the allowed request rate during a throttle penalty
	// (default 10; extra requests get 429).
	ThrottlePerMin int `json:"throttle_per_min,omitempty"`
}

// WindowSecOrDefault returns the counting window (default 600s).
func (p *PenaltySettings) WindowSecOrDefault() int {
	if p == nil || p.WindowSec <= 0 {
		return 600
	}
	return p.WindowSec
}

// ThresholdOrDefault returns the trigger count (default 20).
func (p *PenaltySettings) ThresholdOrDefault() int {
	if p == nil || p.Threshold <= 0 {
		return 20
	}
	return p.Threshold
}

// BanSecOrDefault returns the penalty duration (default 3600s).
func (p *PenaltySettings) BanSecOrDefault() int {
	if p == nil || p.BanSec <= 0 {
		return 3600
	}
	return p.BanSec
}

// ActionOrDefault returns "deny" or "throttle" (default deny).
func (p *PenaltySettings) ActionOrDefault() string {
	if p != nil && p.Action == "throttle" {
		return "throttle"
	}
	return "deny"
}

// ThrottlePerMinOrDefault returns the throttle allowance (default 10/min).
func (p *PenaltySettings) ThrottlePerMinOrDefault() int {
	if p == nil || p.ThrottlePerMin <= 0 {
		return 10
	}
	return p.ThrottlePerMin
}

// InboundOrDefault returns the effective inbound threshold.
func (p *Policy) InboundOrDefault() int {
	if p == nil || p.InboundThreshold <= 0 {
		return 5
	}
	return p.InboundThreshold
}

// OutboundOrDefault returns the effective outbound threshold.
func (p *Policy) OutboundOrDefault() int {
	if p == nil || p.OutboundThreshold <= 0 {
		return 4
	}
	return p.OutboundThreshold
}

// Validate checks the policy block.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if p.InboundThreshold < 0 || p.OutboundThreshold < 0 {
		return fmt.Errorf("policy: thresholds must be >= 0")
	}
	if p.GlobalACL != nil {
		for _, c := range append(append([]string{}, p.GlobalACL.Blacklist...), p.GlobalACL.Whitelist...) {
			if isGroupRef(c) {
				continue
			}
			if !validCIDR(c) {
				return fmt.Errorf("policy: global_acl %q is not a valid IP or CIDR", c)
			}
		}
	}
	if err := ValidateExceptions(p.Exceptions); err != nil {
		return err
	}
	for i := range p.Matchers {
		if err := p.Matchers[i].Validate(); err != nil {
			return fmt.Errorf("policy: matchers[%d]: %w", i, err)
		}
	}
	// Matcher rules must be uniquely named: the console locates rules by name
	// for toggle/save/delete, and the audit trail tags hits as matcher/<name> —
	// duplicates would make those operations ambiguous.
	seenMatcherNames := make(map[string]bool, len(p.Matchers))
	for i := range p.Matchers {
		name := strings.TrimSpace(p.Matchers[i].Name)
		if seenMatcherNames[name] {
			return fmt.Errorf("policy: matchers[%d]: duplicate rule name %q (rule names must be unique)", i, name)
		}
		seenMatcherNames[name] = true
	}
	if p.Penalty != nil {
		if p.Penalty.Action != "" && p.Penalty.Action != "deny" && p.Penalty.Action != "throttle" {
			return fmt.Errorf("policy: penalty.action must be deny or throttle")
		}
		if p.Penalty.WindowSec < 0 || p.Penalty.Threshold < 0 || p.Penalty.BanSec < 0 || p.Penalty.ThrottlePerMin < 0 {
			return fmt.Errorf("policy: penalty values must be >= 0")
		}
	}
	if p.WAFCategories != nil {
		if len(p.WAFCategories) == 0 {
			return fmt.Errorf("policy: waf_categories must not be empty when present")
		}
		for _, c := range p.WAFCategories {
			if !ValidWAFCategory(c) {
				return fmt.Errorf("policy: waf_categories %q is not a valid category", c)
			}
		}
	}
	return nil
}
