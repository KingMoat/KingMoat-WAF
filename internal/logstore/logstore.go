package logstore

import (
	"time"
)

// Event is the audit event (canonical schema subset, see §5.1).
type Event struct {
	TS        string `json:"ts"`
	TraceID   string `json:"trace_id,omitempty"`
	Site      string `json:"site,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	// URL is the full request target (host + path + query) as received by
	// the data plane, e.g. "app.local:8443/a?b=1". Older events (pre-v0.6.9)
	// carry only Path; the console falls back to it when URL is empty.
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Action    string `json:"action"` // "blocked" | "monitor" | "challenged" | "redirected"
	Rule      string `json:"rule,omitempty"`
	Reason    string `json:"reason,omitempty"`
	BodyBytes int    `json:"body_bytes,omitempty"`
	// Request snapshot (capture_requests enabled): sanitized headers and a
	// truncated body sample, for replay in the console/API.
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// Bot classification labels from the botdetect stage.
	BotClass string `json:"bot_class,omitempty"` // "good" | "unknown" | "bad"
	BotName  string `json:"bot_name,omitempty"`
	BotScore int    `json:"bot_score,omitempty"`
	// AttackType is the human-readable category (XSS/SQL注入/CC攻击/...),
	// derived from the rule identifier.
	AttackType string `json:"attack_type,omitempty"`
}

// Store accepts audit events; implementations must be safe for concurrent use
// and never block the hot path.
type Store interface {
	Write(ev *Event)
	Close() error
}

// Queryable is implemented by stores that can serve recent events to the
// control plane (console log view).
type Queryable interface {
	Recent(n int) []Event
}

// Searcher is implemented by stores that support filtered history queries
// (console API and the AI assistant tools).
type Searcher interface {
	Query(q LogQuery) ([]Event, error)
}

// Aggregator is implemented by stores that can pre-aggregate a time window.
type Aggregator interface {
	Aggregate(since, until time.Time) (*Summary, error)
}

// PagedSearcher is implemented by stores that expose a pagination total for
// the console log view (Count ignores Limit/Offset).
type PagedSearcher interface {
	Searcher
	Count(q LogQuery) (int, error)
}

// TypeDistributor is implemented by stores that can group a time window by
// derived attack type (dashboard donut).
type TypeDistributor interface {
	TypeDistribution(since, until time.Time, topN int) ([]TopHit, error)
}

// TrendBucket is one time bucket of activity counts by action, feeding the
// dashboard trend chart (zero-filled by the API layer).
type TrendBucket struct {
	BucketMs int64          `json:"bucket_ms"`
	ByAction map[string]int `json:"by_action"`
}

// Trender is implemented by stores that can bucket activity over time.
type Trender interface {
	Trend(since, until time.Time, bucketSec int) ([]TrendBucket, error)
}

// Dropper is implemented by stores that expose queue-overflow drop counts.
type Dropper interface {
	Dropped() int64
}

// Purger is implemented by stores that support retention-based deletion of
// events older than the given timestamp. Returns the number of deleted rows.
type Purger interface {
	Purge(before time.Time) (int64, error)
}

// RuleTopHitter is implemented by stores that can rank the window's most-hit
// rules (policy page rule-hit statistics card). The returned total is the
// number of attack events in the same window under the same criteria,
// unbounded by topN.
type RuleTopHitter interface {
	RuleTopHits(since, until time.Time, topN int) ([]TopHit, int64, error)
}

// noop is used when auditing is disabled.
type noopStore struct{}

func (noopStore) Write(*Event) {}
func (noopStore) Close() error { return nil }

// Noop returns a Store that discards everything (auditing disabled).
func Noop() Store { return noopStore{} }

// multiStore fans events out to several backends (local + webhook + shipper).
type multiStore struct{ stores []Store }

// Multi combines stores; Close closes all of them in order.
func Multi(stores ...Store) Store {
	filtered := stores[:0]
	for _, s := range stores {
		if _, isNoop := s.(noopStore); s != nil && !isNoop {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return Noop()
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return multiStore{stores: filtered}
}

func (m multiStore) Write(ev *Event) {
	for _, s := range m.stores {
		s.Write(ev)
	}
}

func (m multiStore) Close() error {
	for _, s := range m.stores {
		_ = s.Close()
	}
	return nil
}

// AttackTypeOf maps a rule identifier to an attack category (see
// attacktype.go); exported for the proxy and shippers.
func AttackTypeOf(rule string) string { return attackTypeOf(rule) }
