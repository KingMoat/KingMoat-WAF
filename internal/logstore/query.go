package logstore

import (
	"sort"
	"time"
)

// LogQuery filters audit events for read-only consumers (console API and the
// AI assistant tools). Zero-valued fields mean "no filter". Site and Rule are
// substring matches; SrcIP is a prefix match; Text is an FTS5 full-text query
// over path / user-agent / reason / rule.
type LogQuery struct {
	Since  time.Time
	Until  time.Time
	Action string // exact match: blocked | monitor | challenged | redirected
	Rule   string // substring match on the rule identifier
	Site   string // substring match on the site domain
	SrcIP  string // prefix match on the client IP
	Text   string // FTS5 full-text query (tokens ANDed, trailing * = prefix)
	TraceID string // exact/prefix match on the trace id (console search)
	Limit  int    // default 100, capped at maxQueryLimit
	Offset int    // row offset for pagination (0 = newest page)
}

const (
	defaultQueryLimit = 100
	maxQueryLimit     = 1000
	topN              = 10
)

func (q *LogQuery) limit() int {
	if q.Limit <= 0 {
		return defaultQueryLimit
	}
	if q.Limit > maxQueryLimit {
		return maxQueryLimit
	}
	return q.Limit
}

// TopHit is one entry of an aggregate top-N list.
type TopHit struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Summary is the pre-aggregated view of a time window, feeding the AI
// assistant and the risk engine without raw log dumps.
type Summary struct {
	WindowStart string         `json:"window_start"`
	WindowEnd   string         `json:"window_end"`
	Total       int            `json:"total"`
	ByAction    map[string]int `json:"by_action"`
	TopRules    []TopHit       `json:"top_rules"`
	TopIPs      []TopHit       `json:"top_ips"`
	TopPaths    []TopHit       `json:"top_paths"`
	TopSites    []TopHit       `json:"top_sites"`
	TopBotClass map[string]int `json:"top_bot_class"`
	// SuspectedFP counts same-IP repeats of low-severity rules — a cheap
	// scanner/false-positive signal.
	SuspectedFP int    `json:"suspected_fp"`
	FirstTS     string `json:"first_ts,omitempty"`
	LastTS      string `json:"last_ts,omitempty"`
}

type counter map[string]int

func (c counter) add(k string) { c[k]++ }

func (c counter) top(n int) []TopHit {
	hits := make([]TopHit, 0, len(c))
	for k, v := range c {
		hits = append(hits, TopHit{Key: k, Count: v})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count != hits[j].Count {
			return hits[i].Count > hits[j].Count
		}
		return hits[i].Key < hits[j].Key
	})
	if len(hits) > n {
		hits = hits[:n]
	}
	return hits
}

// lowSeverityRules are high-volume informational signatures that repeat
// constantly from the same scanner IPs.
var lowSeverityRules = map[string]bool{
	"coraza/rule-920280": true, // missing host header variants
	"bot/challenge":      true,
}
