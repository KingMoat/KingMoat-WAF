package stages

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// geoWarnEvery rate-limits the engine-missing warning per site domain: at
// most one warning per minute per domain, so a hot request path cannot flood
// the log while the misconfiguration persists.
const geoWarnEvery = time.Minute

// Geo enforces country-level access control using a MaxMind mmdb database
// (user-supplied, or the embedded DB-IP Country Lite when db_path is empty).
// Whitelist hits may mark the request trusted, skipping later stages,
// mirroring the ACL whitelist semantics.
type Geo struct {
	byDomain map[string]*geoSite
	// configured holds every domain of a geo-enabled site. It is written in
	// the SAME loop as byDomain (NewGeo), so "configured but not in byDomain"
	// is unreachable by construction in today's code; it exists purely as a
	// defensive invariant sentinel: if a future refactor ever introduces a
	// real desync between the configured domains and the running engine, the
	// rate-limited warning and the audit side channel keep the fail-open
	// observable instead of silent.
	configured map[string]bool
	// embedded is the process-wide geoip.Reader() singleton shared by every
	// geo site built with an empty db_path. It is owned by the geoip package
	// and must never be closed by an engine instance: a successful hot-reload
	// closes the previous engine, and closing the singleton would break every
	// Lookup in the new engine (production-verified silent geo loss).
	embedded *maxminddb.Reader
	logger   *slog.Logger

	warnMu    sync.Mutex
	warnLast  map[string]time.Time
	warnEvery time.Duration
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
	g := &Geo{
		byDomain:   map[string]*geoSite{},
		configured: map[string]bool{},
		warnLast:   map[string]time.Time{},
		warnEvery:  geoWarnEvery,
		logger:     logger,
	}
	opened := map[string]*maxminddb.Reader{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.Geo == nil || !s.Security.Geo.Enabled {
			continue
		}
		geo := s.Security.Geo
		dbPath := geo.DBPath
		if dbPath != "" {
			// Compat: resolve a pre-rename data-directory path to the current
			// layout when the file exists there (a v0.7.10 data-dir migration
			// straggler); each stale path is warned about once per process.
			dbPath = config.ResolveLegacyDataPath(dbPath, logger)
		}
		db, ok := opened[dbPath]
		if !ok {
			var err error
			if dbPath == "" {
				// Empty path → embedded country database (internal/geoip).
				// A process-wide singleton: recorded so Close skips it.
				db = geoip.Reader()
				if db == nil {
					_ = g.Close()
					return nil, fmt.Errorf("geo: site %d: embedded GeoIP database unavailable", i)
				}
				g.embedded = db
			} else {
				db, err = maxminddb.Open(dbPath)
				if err != nil {
					_ = g.Close()
					return nil, fmt.Errorf("geo: site %d: open %s: %w", i, dbPath, err)
				}
			}
			opened[dbPath] = db
		}
		gs := &geoSite{
			db:      db,
			black:   toSet(geo.Blacklist),
			white:   toSet(geo.Whitelist),
			trusted: geo.WhitelistTrusted,
		}
		mapped := 0
		for _, d := range s.Domains {
			key := strings.ToLower(strings.TrimSpace(d))
			if key == "" {
				continue
			}
			g.byDomain[key] = gs
			g.configured[key] = true
			mapped++
		}
		if mapped == 0 {
			// Defensive: a geo-enabled site that contributes no usable domain
			// can never be evaluated. Not expected to happen (config validation
			// requires domains); surface it instead of failing silently.
			g.logger.Warn("geo: site has geo enabled but no usable domains; geo will never evaluate for it",
				"site_index", i, "site", s.Name)
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
	domain := strings.ToLower(strings.TrimSpace(rc.Site.Domain))
	site, ok := g.byDomain[domain]
	if !ok {
		// Not a geo site → allow. If the config declared geo for this domain
		// and the running engine has no mapping for it, warn at a capped rate
		// instead of passing silently. Unreachable by construction today
		// (byDomain and configured are written in the same NewGeo loop): this
		// is a defensive sentinel for a future refactor introducing a real
		// desync, not a signal the current build can produce. Never deny
		// here — alerting only, no false positives.
		if g.configured[domain] {
			if g.warnEngineMissing(domain) {
				// Side channel for the proxy audit consumer (same pattern as
				// matcher_rule): follows the warn rate limit so the audit
				// store cannot flood on a hot request path.
				rc.Values["geo_engine_missing"] = true
			}
		}
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

// warnEngineMissing logs one warning per domain per interval (default 1/min)
// so the misconfiguration is observable without flooding the request path,
// and reports whether THIS call produced a warning — the proxy mirrors fired
// warnings into the audit trail (rc.Values["geo_engine_missing"]), so the
// flag must obey the same rate limit.
//
// Callers can only reach this when byDomain lost a domain that configured
// still holds, which today's NewGeo cannot produce (both maps are written in
// the same loop): keep this as the fail-open invariant sentinel — if a future
// refactor makes the desync real, this warning and the audit bypass stay the
// observable safety net.
func (g *Geo) warnEngineMissing(domain string) bool {
	g.warnMu.Lock()
	defer g.warnMu.Unlock()
	now := time.Now()
	if last, ok := g.warnLast[domain]; ok && now.Sub(last) < g.warnEvery {
		return false
	}
	g.warnLast[domain] = now
	g.logger.Warn("geo: configured but engine missing - check hot-reload failures", "site", domain)
	return true
}

// Close releases open mmdb handles (implements io.Closer). The embedded
// database singleton is intentionally left open: it is shared by every
// engine instance and owned by the geoip package for the process lifetime —
// closing it here would silently break geo lookups after a hot-reload.
func (g *Geo) Close() error {
	seen := map[*maxminddb.Reader]bool{}
	for _, gs := range g.byDomain {
		if gs.db == nil || gs.db == g.embedded || seen[gs.db] {
			continue
		}
		seen[gs.db] = true
		_ = gs.db.Close()
	}
	return nil
}
