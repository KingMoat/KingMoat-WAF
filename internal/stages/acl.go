// Package stages implements the KingMoat M3 protection stages on top of the
// pipeline contract: ACL (IP/CIDR), CC rate limiting, bot JS challenge, and
// response-body sensitive-information filtering.
package stages

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// clientIP returns the client IP for the request: the site-scoped real-IP
// resolution result (see config.Site.RealIP) when the proxy stored one in
// the request context, otherwise the TCP peer address from RemoteAddr.
func clientIP(r *http.Request) net.IP {
	if ip := pipeline.ClientIPFromContext(r.Context()); ip != nil {
		return ip
	}
	return peerIP(r)
}

// ACL is the per-site IP/CIDR access-control stage. Whitelist hits mark the
// request trusted (skipping the remaining stages); blacklist hits are denied.
// Entries may reference subscribed IP lists via "group:<name>".
type ACL struct {
	byDomain map[string]*aclSite
	groups   ipgroups.Provider
	global   *aclSite // console-managed global blacklist/whitelist (applies first)
	logger   *slog.Logger
}

type aclEntry struct {
	net   *net.IPNet
	group string // non-empty for "group:<name>" entries
}

type aclSite struct {
	blacklist []aclEntry
	whitelist []aclEntry
}

// NewACL builds the stage from site security configs. groups may be nil
// when no IP groups are configured.
func NewACL(cfg *config.Config, groups ipgroups.Provider, logger *slog.Logger) (*ACL, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := make(map[string]*aclSite)
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.ACL == nil {
			continue
		}
		as := &aclSite{}
		for _, c := range s.Security.ACL.Whitelist {
			e, err := parseACLEntry(c)
			if err != nil {
				return nil, fmt.Errorf("acl: site %d whitelist %q: %w", i, c, err)
			}
			as.whitelist = append(as.whitelist, e)
		}
		for _, c := range s.Security.ACL.Blacklist {
			e, err := parseACLEntry(c)
			if err != nil {
				return nil, fmt.Errorf("acl: site %d blacklist %q: %w", i, c, err)
			}
			as.blacklist = append(as.blacklist, e)
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = as
		}
	}
	return &ACL{byDomain: byDomain, groups: groups, global: buildGlobalACL(cfg), logger: logger}, nil
}

// buildGlobalACL materializes the console-managed global lists (nil when the
// policy block has no lists).
func buildGlobalACL(cfg *config.Config) *aclSite {
	if cfg.Policy == nil || cfg.Policy.GlobalACL == nil {
		return nil
	}
	g := cfg.Policy.GlobalACL
	as := &aclSite{}
	for _, c := range g.Whitelist {
		e, err := parseACLEntry(c)
		if err != nil {
			continue // validated at config load; ignore defensively
		}
		as.whitelist = append(as.whitelist, e)
	}
	for _, c := range g.Blacklist {
		e, err := parseACLEntry(c)
		if err != nil {
			continue
		}
		as.blacklist = append(as.blacklist, e)
	}
	if len(as.whitelist) == 0 && len(as.blacklist) == 0 {
		return nil
	}
	return as
}

func parseACLEntry(c string) (aclEntry, error) {
	if strings.HasPrefix(c, "group:") {
		return aclEntry{group: strings.TrimPrefix(c, "group:")}, nil
	}
	ipnet, err := config.ParseIPNet(c)
	if err != nil {
		return aclEntry{}, err
	}
	return aclEntry{net: ipnet}, nil
}

func (e aclEntry) matches(groups ipgroups.Provider, ip net.IP) bool {
	if e.group != "" {
		if groups == nil {
			return false
		}
		for _, n := range groups.Lookup(e.group) {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return e.net != nil && e.net.Contains(ip)
}

// Name implements pipeline.Stage.
func (a *ACL) Name() string { return "acl" }

// Inspect implements pipeline.Stage.
func (a *ACL) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	ip := clientIP(rc.Request)
	if ip == nil {
		return pipeline.Allow()
	}
	// Global lists (console strategy page) apply to every site — including
	// sites without a per-site ACL section, which are absent from byDomain.
	// This check must therefore run before the site lookup early-return.
	if a.global != nil {
		for _, e := range a.global.whitelist {
			if e.matches(a.groups, ip) {
				rc.Values["trusted"] = true
				return pipeline.Allow()
			}
		}
		for _, e := range a.global.blacklist {
			if e.matches(a.groups, ip) {
				a.logger.Warn("acl: globally blacklisted client denied",
					"ip", ip, "site", rc.Site.Domain, "trace", rc.Values["trace_id"])
				return pipeline.Deny("acl/global_blacklist", "client IP is globally blacklisted")
			}
		}
	}
	site := a.byDomain[strings.ToLower(rc.Site.Domain)]
	if site == nil {
		return pipeline.Allow()
	}
	for _, e := range site.whitelist {
		if e.matches(a.groups, ip) {
			rc.Values["trusted"] = true
			return pipeline.Allow()
		}
	}
	for _, e := range site.blacklist {
		if e.matches(a.groups, ip) {
			a.logger.Warn("acl: blacklisted client denied",
				"ip", ip, "site", rc.Site.Domain, "trace", rc.Values["trace_id"])
			return pipeline.Deny("acl/blacklist", "client IP is blacklisted")
		}
	}
	return pipeline.Allow()
}
