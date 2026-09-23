// Package stages: MicroEngine-style conditional matcher stage. Conditions are
// field/operator/value predicates combined with AND/OR logic; the action
// (deny/allow/monitor) maps to pipeline verdicts. Field extraction covers
// client IP, host, path/URI, method, UA, referer, buffered body and composite
// header:X / query:Y / cookie:Z fields.
package stages

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Matcher is the conditional-rule stage.
type Matcher struct {
	rules    []compiledMatcher
	disabled *StageDisableRegistry
	logger   *slog.Logger
}

type compiledMatcher struct {
	rule      config.MatcherRule
	condRes   []compiledCond
}

type compiledCond struct {
	cond config.MatcherCondition
	re   func(string) bool // regex precompiled
	cidr []*net.IPNet      // cidr precompiled (value list)
	list []string          // "in" list split
}

// NewMatcher compiles the enabled rules from cfg.Policy.Matchers. The
// disable registry receives sites/modules from "disable" actions (nil
// registry disables nothing).
func NewMatcher(cfg *config.Config, disabled *StageDisableRegistry, logger *slog.Logger) (*Matcher, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Matcher{disabled: disabled, logger: logger}
	if cfg.Policy == nil {
		return m, nil
	}
	for i := range cfg.Policy.Matchers {
		r := cfg.Policy.Matchers[i]
		if !r.Enabled {
			continue
		}
		cm := compiledMatcher{rule: r}
		for _, c := range r.Conditions {
			cc := compiledCond{cond: c}
			if c.Op == config.OpRegex {
				fn, err := config.CompileRegex(c.Value)
				if err != nil {
					return nil, fmt.Errorf("matcher %q: regex %q: %w", r.Name, c.Value, err)
				}
				cc.re = fn
			}
			if c.Op == config.OpCIDR {
				for _, part := range strings.Split(c.Value, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					var ipnet *net.IPNet
					if _, ipnet, err := net.ParseCIDR(part); err == nil {
						cc.cidr = append(cc.cidr, ipnet)
						continue
					}
					if ip := net.ParseIP(part); ip != nil {
						if ip4 := ip.To4(); ip4 != nil {
							ipnet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
						} else {
							ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
						}
						cc.cidr = append(cc.cidr, ipnet)
					}
				}
			}
			if c.Op == config.OpIn {
				for _, part := range strings.Split(c.Value, ",") {
					if part = strings.TrimSpace(part); part != "" {
						cc.list = append(cc.list, part)
					}
				}
			}
			cm.condRes = append(cm.condRes, cc)
		}
		m.rules = append(m.rules, cm)
	}
	return m, nil
}

// Name implements pipeline.Stage.
func (m *Matcher) Name() string { return "matcher" }

// Inspect implements pipeline.Stage: first matching enabled rule wins.
func (m *Matcher) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true || len(m.rules) == 0 {
		return pipeline.Allow()
	}
	for _, cm := range m.rules {
		if !matcherAppliesToSite(cm.rule.Sites, rc.Site.Domain) {
			continue
		}
		if !conditionsMatch(cm, rc) {
			continue
		}
		matcherHitInc(cm.rule.Name)
		switch cm.rule.Action {
		case config.ActionDeny:
			m.logger.Warn("matcher: rule denied request",
				"rule", cm.rule.Name, "site", rc.Site.Domain, "trace", rc.Values["trace_id"])
			return pipeline.Deny("matcher/"+cm.rule.Name, "blocked by custom rule: "+cm.rule.Name)
		case config.ActionAllow:
			rc.Values["trusted"] = true
			rc.Values["exception_applied"] = cm.rule.Name
			rc.Values["matcher_rule"] = cm.rule.Name
			return pipeline.Allow()
		case config.ActionMonitor:
			m.logger.Info("matcher: rule matched (monitor)",
				"rule", cm.rule.Name, "site", rc.Site.Domain, "trace", rc.Values["trace_id"])
			rc.Values["matcher_rule"] = cm.rule.Name
			return pipeline.Allow()
		case config.ActionDisable:
			if m.disabled != nil {
				for _, st := range cm.rule.DisableStages {
					m.disabled.Disable(rc.Site.Domain, st)
				}
			}
			m.logger.Warn("matcher: detection modules disabled for site",
				"rule", cm.rule.Name, "site", rc.Site.Domain,
				"stages", strings.Join(cm.rule.DisableStages, ","), "trace", rc.Values["trace_id"])
			rc.Values["matcher_rule"] = cm.rule.Name
			return pipeline.Allow()
		}
	}
	return pipeline.Allow()
}

func matcherAppliesToSite(sites []string, domain string) bool {
	if len(sites) == 0 {
		return true
	}
	for _, s := range sites {
		if strings.EqualFold(s, domain) {
			return true
		}
	}
	return false
}

// conditionsMatch evaluates the rule's conditions with its logic.
func conditionsMatch(cm compiledMatcher, rc *pipeline.RequestContext) bool {
	and := cm.rule.Logic != "or"
	for _, cc := range cm.condRes {
		hit := condHit(cc, rc)
		if and && !hit {
			return false
		}
		if !and && hit {
			return true
		}
	}
	return and // all conditions true (and-logic) or none matched (or-logic)
}

// condHit evaluates one condition against the request.
func condHit(cc compiledCond, rc *pipeline.RequestContext) bool {
	r := rc.Request
	var val string
	switch {
	case cc.cond.Field == config.FieldClientIP:
		if ip := clientIP(r); ip != nil {
			val = ip.String()
		} else {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				val = r.RemoteAddr
			} else {
				val = host
			}
		}
	case cc.cond.Field == config.FieldHostname:
		val = r.Host
	case cc.cond.Field == config.FieldPath:
		val = r.URL.Path
	case cc.cond.Field == config.FieldURI:
		val = r.URL.RequestURI()
	case cc.cond.Field == config.FieldMethod:
		val = r.Method
	case cc.cond.Field == config.FieldUserAgent:
		val = r.UserAgent()
	case cc.cond.Field == config.FieldReferer:
		val = r.Header.Get("Referer")
	case cc.cond.Field == config.FieldBody:
		val = string(rc.Body)
	case strings.HasPrefix(cc.cond.Field, "header:"):
		val = r.Header.Get(strings.TrimPrefix(cc.cond.Field, "header:"))
	case strings.HasPrefix(cc.cond.Field, "query:"):
		val = r.URL.Query().Get(strings.TrimPrefix(cc.cond.Field, "query:"))
	case strings.HasPrefix(cc.cond.Field, "cookie:"):
		if ck, err := r.Cookie(strings.TrimPrefix(cc.cond.Field, "cookie:")); err == nil {
			val = ck.Value
		}
	}

	switch cc.cond.Op {
	case config.OpEq:
		return val == cc.cond.Value
	case config.OpNotEq:
		return val != cc.cond.Value
	case config.OpContains:
		return strings.Contains(strings.ToLower(val), strings.ToLower(cc.cond.Value))
	case config.OpNotContains:
		return !strings.Contains(strings.ToLower(val), strings.ToLower(cc.cond.Value))
	case config.OpPrefix:
		return strings.HasPrefix(val, cc.cond.Value)
	case config.OpSuffix:
		return strings.HasSuffix(val, cc.cond.Value)
	case config.OpRegex:
		if cc.re != nil {
			return cc.re(val)
		}
		return false
	case config.OpCIDR:
		ip := net.ParseIP(val)
		if ip == nil {
			return false
		}
		for _, n := range cc.cidr {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	case config.OpIn:
		for _, item := range cc.list {
			if strings.EqualFold(val, item) {
				return true
			}
		}
		return false
	}
	return false
}

// http import retained for the ResponseWriter-free field extraction helpers.
var _ = http.MethodGet
