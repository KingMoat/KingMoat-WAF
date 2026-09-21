// Geo attack-origin analytics and the OpenAPI specification endpoint.
package api

import (
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// handleGeoStats aggregates the origin countries of recent attack events.
// Requires a GeoIP mmdb (any site's geo.db_path, or the caller-provided
// GeoDBFn); without it the endpoint reports geo_available=false. The window
// is 24h by default, overridable with ?hours=N (1..720).
func (s *Server) handleGeoStats(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n := atoiSafe2(v); n > 0 && n <= 50 {
			limit = n
		}
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n := atoiSafe2(v); n > 0 && n <= 720 {
			hours = n
		}
	}
	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)

	dbPath := ""
	if s.opts.GeoDBFn != nil {
		dbPath = s.opts.GeoDBFn()
	}
	if dbPath == "" {
		// fall back to any site geo config
		_, cfg := s.opts.Center.Current()
		for i := range cfg.Sites {
			if s := &cfg.Sites[i]; s.Security != nil && s.Security.Geo != nil && s.Security.Geo.Enabled {
				dbPath = s.Security.Geo.DBPath
				break
			}
		}
	}
	if dbPath == "" {
		// No user-supplied mmdb → use the embedded country database
		// (internal/geoip); unavailable only when that failed to parse too.
		embedded := geoip.Reader()
		if embedded == nil {
			writeJSON(w, http.StatusOK, map[string]any{"geo_available": false, "items": []any{}})
			return
		}
		s.lookupCountry(embedded, limit, since, until, w)
		return
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		// Configured path unusable (missing file etc.) → embedded fallback
		// before giving up, so a broken path never silently kills the view.
		if embedded := geoip.Reader(); embedded != nil {
			s.lookupCountry(embedded, limit, since, until, w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"geo_available": false, "items": []any{}})
		return
	}
	defer db.Close()
	s.lookupCountry(db, limit, since, until, w)
}

// sourceIPAggregator is implemented by stores that can pre-aggregate the
// window's attack events per source IP (the SQLite audit store).
type sourceIPAggregator interface {
	TopSourceIPs(since, until time.Time, limit int) ([]logstore.TopHit, error)
	AttackTotal(since, until time.Time) (int64, error)
}

// geoSources returns the window's top attacking IPs and the total attack
// event count. It prefers the SQL aggregation (bounded, correct totals) and
// falls back to a Recent scan for stores without aggregation support.
func (s *Server) geoSources(since, until time.Time) ([]logstore.TopHit, int64) {
	if agg, ok := s.opts.Logs.(sourceIPAggregator); ok {
		hits, err := agg.TopSourceIPs(since, until, 200)
		if err == nil {
			total, terr := agg.AttackTotal(since, until)
			if terr != nil {
				for _, h := range hits {
					total += int64(h.Count)
				}
			}
			return hits, total
		}
	}
	// Fallback: scan recent events under the same criteria (action + rule
	// non-empty). Counts only the newest 1000 events — approximate, but the
	// SQLite store always provides the aggregation above.
	counts := map[string]int{}
	var total int64
	for _, ev := range s.opts.Logs.Recent(1000) {
		if ev.Action == "" || ev.Rule == "" || ev.ClientIP == "" {
			continue
		}
		counts[ev.ClientIP]++
		total++
	}
	hits := make([]logstore.TopHit, 0, len(counts))
	for ip, c := range counts {
		hits = append(hits, logstore.TopHit{Key: ip, Count: c})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Count > hits[j].Count })
	if len(hits) > 200 {
		hits = hits[:200]
	}
	return hits, total
}

// localLabel merges every private/loopback/link-local origin into one
// bucket: they carry no mmdb country, so they would otherwise silently
// disappear from the country distribution.
const localLabel = "本地局域网"

// topIPsLimit is the fixed size of the per-IP top list in the response.
const topIPsLimit = 5

// lookupCountry aggregates attack-event origin countries via the given db:
// SQL-side per-IP aggregation first, then one country resolution per source
// IP (Top200), merged into per-country counts. Private origins are merged
// into the single localLabel bucket; public IPs with no mmdb record keep
// the existing skip behavior. The response also carries top_ips: the same
// aggregation ranked per source IP (top 5) with country annotations.
type ipHit struct {
	ip      string
	count   int
	country string
}

// lookupCountry aggregates attack-event origin countries via the given db:
// SQL-side per-IP aggregation first, then one country resolution per source
// IP (Top200), merged into per-country counts. Private origins are merged
// into the single localLabel bucket; public IPs with no mmdb record keep
// the existing skip behavior. The response also carries top_ips: the same
// aggregation ranked per source IP (top 5) with country annotations.
func (s *Server) lookupCountry(db *maxminddb.Reader, limit int, since, until time.Time, w http.ResponseWriter) {
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	counts := map[string]int{}
	sources, total := s.geoSources(since, until)
	ipCounts := make(map[string]ipHit, len(sources))
	for _, src := range sources {
		ip := net.ParseIP(src.Key)
		if ip == nil {
			continue
		}
		if apiasset.IsPrivateIP(src.Key) {
			counts[localLabel] += src.Count
			ipCounts[src.Key] = ipHit{ip: src.Key, count: src.Count, country: localLabel}
			continue
		}
		if err := db.Lookup(ip, &rec); err != nil {
			ipCounts[src.Key] = ipHit{ip: src.Key, count: src.Count}
			continue
		}
		ipCounts[src.Key] = ipHit{ip: src.Key, count: src.Count, country: rec.Country.ISOCode}
		if rec.Country.ISOCode == "" {
			continue
		}
		counts[rec.Country.ISOCode] += src.Count
	}
	type item struct {
		Country string `json:"country"`
		Count   int    `json:"count"`
	}
	items := make([]item, 0, len(counts))
	for c, n := range counts {
		items = append(items, item{Country: c, Count: n})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		items = []item{}
	}
	topIPs := make([]ipHit, 0, len(ipCounts))
	for _, hit := range ipCounts {
		topIPs = append(topIPs, hit)
	}
	sort.Slice(topIPs, func(i, j int) bool {
		a, b := topIPs[i], topIPs[j]
		if a.count != b.count {
			return a.count > b.count
		}
		return a.ip < b.ip
	})
	if len(topIPs) > topIPsLimit {
		topIPs = topIPs[:topIPsLimit]
	}
	type topIP struct {
		IP      string `json:"ip"`
		Count   int    `json:"count"`
		Country string `json:"country"`
	}
	top := make([]topIP, 0, len(topIPs))
	for _, h := range topIPs {
		top = append(top, topIP{IP: h.ip, Count: h.count, Country: h.country})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"geo_available": true, "total": total, "items": items, "top_ips": top, "generated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func atoiSafe2(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
