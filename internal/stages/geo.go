package stages

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/oschwald/maxminddb-golang"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Geo enforces country-level access control using a MaxMind mmdb database
// (user-supplied). Whitelist hits may mark the request trusted, skipping
// later stages, mirroring the ACL whitelist semantics.
type Geo struct {
	byDomain map[string]*geoSite
	logger   *slog.Logger
}

type geoSite struct {
	db      *maxminddb.Reader
	black   map[string]bool
	white   map[string]bool
	trusted bool // whitelist hits skip later stages
}

// NewGeo opens the configured mmdb files; a missing/invalid database fails
// the build (fail-static).
func NewGeo(cfg *config.Config, logger *slog.Logger) (*Geo, error) {
	if logger == nil {
		logger = slog.Default()
	}
	g := &Geo{byDomain: map[string]*geoSite{}, logger: logger}
	opened := map[string]*maxminddb.Reader{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.Geo == nil || !s.Security.Geo.Enabled {
			continue
		}
		geo := s.Security.Geo
		db, ok := opened[geo.DBPath]
		if !ok {
			var err error
			if geo.DBPath == "" {
				// Empty path → embedded country database (internal/geoip).
				db = geoip.Reader()
				if db == nil {
					_ = g.Close()
					return nil, fmt.Errorf("geo: site %d: embedded GeoIP database unavailable", i)
				}
			} else {
				db, err = maxminddb.Open(geo.DBPath)
				if err != nil {
					_ = g.Close()
					return nil, fmt.Errorf("geo: site %d: open %s: %w", i, geo.DBPath, err)
				}
			}
			opened[geo.DBPath] = db
		}
		gs := &geoSite{
			db:      db,
			black:   toSet(geo.Blacklist),
			white:   toSet(geo.Whitelist),
			trusted: geo.WhitelistTrusted,
		}
		for _, d := range s.Domains {
			g.byDomain[strings.ToLower(strings.TrimSpace(d))] = gs
		}
	}
	return g, nil
}

func toSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, c := range list {
		m[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	return m
}

// Name implements pipeline.Stage.
func (g *Geo) Name() string { return "geo" }

// Inspect implements pipeline.Stage.
func (g *Geo) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if trusted, _ := rc.Values["trusted"].(bool); trusted {
		return pipeline.Allow()
	}
	site, ok := g.byDomain[strings.ToLower(rc.Site.Domain)]
	if !ok {
		return pipeline.Allow()
	}
	ip := clientIP(rc.Request)
	if ip == nil {
		return pipeline.Allow()
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := site.db.Lookup(ip, &rec); err != nil {
		g.logger.Debug("geo: lookup failed", "ip", ip, "err", err)
		return pipeline.Allow()
	}
	cc := rec.Country.ISOCode
	if site.white[cc] {
		if site.trusted {
			rc.Values["trusted"] = true
		}
		return pipeline.Allow()
	}
	if len(site.white) > 0 {
		// whitelist mode: unknown countries are denied
		g.logger.Warn("geo: country not whitelisted", "country", cc, "site", rc.Site.Domain)
		return pipeline.Deny("geo/not_whitelisted", "client country is not whitelisted")
	}
	if site.black[cc] {
		g.logger.Warn("geo: blacklisted country", "country", cc, "site", rc.Site.Domain)
		return pipeline.Deny("geo/blacklist", "client country is blacklisted")
	}
	return pipeline.Allow()
}

// Close releases open mmdb handles (implements io.Closer).
func (g *Geo) Close() error {
	seen := map[*maxminddb.Reader]bool{}
	for _, gs := range g.byDomain {
		if gs.db != nil && !seen[gs.db] {
			seen[gs.db] = true
			_ = gs.db.Close()
		}
	}
	return nil
}
