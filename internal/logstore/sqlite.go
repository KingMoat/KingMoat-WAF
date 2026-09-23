package logstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sqliteQueueSize   = 1024
	sqliteBatchSize   = 256
	sqliteFlushEvery  = 500 * time.Millisecond
	sqliteReadTimeout = 5 * time.Second
)

// SQLiteStore persists audit events to an embedded SQLite database (pure-Go
// modernc driver, no CGO) with an FTS5 full-text index over path / UA /
// reason / rule. Writes are batched through a bounded queue; Recent, Query
// and Aggregate are served with SQL instead of file scans.
type SQLiteStore struct {
	db      *sql.DB // single writer connection (serialized, WAL)
	rdb     *sql.DB // read pool (query_only): console queries never starve writes
	dbPath  string
	logger  *slog.Logger
	ch      chan Event
	dropped atomic.Int64
	pending atomic.Int64
	done    chan struct{}
	// writeHook is invoked synchronously at enqueue time for every accepted
	// event (penalty engine counts attacks here; nil = no hook).
	writeHook atomic.Value // func(Event)

	closeOnce sync.Once
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ms      INTEGER NOT NULL,
	trace_id   TEXT NOT NULL DEFAULT '',
	site       TEXT NOT NULL DEFAULT '',
	client_ip  TEXT NOT NULL DEFAULT '',
	method     TEXT NOT NULL DEFAULT '',
	path       TEXT NOT NULL DEFAULT '',
	url        TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL DEFAULT '',
	rule       TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	status     INTEGER NOT NULL DEFAULT 0,
	body_bytes INTEGER NOT NULL DEFAULT 0,
	ua         TEXT NOT NULL DEFAULT '',
	bot_class  TEXT NOT NULL DEFAULT '',
	raw        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_site_ts ON events(site, ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_action_ts ON events(action, ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_rule_ts ON events(rule, ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(client_ip, ts_ms);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
	path, ua, reason, rule,
	content='events', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS events_fts_ai AFTER INSERT ON events BEGIN
	INSERT INTO events_fts(rowid, path, ua, reason, rule)
	VALUES (new.id, new.path, new.ua, new.reason, new.rule);
END;
CREATE TRIGGER IF NOT EXISTS events_fts_ad AFTER DELETE ON events BEGIN
	INSERT INTO events_fts(events_fts, rowid, path, ua, reason, rule)
	VALUES ('delete', old.id, old.path, old.ua, old.reason, old.rule);
END;
`

// sqliteMigrations upgrades databases created before the current schema.
// Each statement is idempotent-tolerant: "duplicate column"
// / "already exists" errors mean the upgrade already ran.
var sqliteMigrations = []string{
	`ALTER TABLE events ADD COLUMN url TEXT NOT NULL DEFAULT ''`,
}

// migrate applies sqliteMigrations, ignoring already-applied steps.
func migrate(db *sql.DB, logger *slog.Logger) {
	for _, stmt := range sqliteMigrations {
		if _, err := db.Exec(stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") || strings.Contains(msg, "already exists") {
				continue
			}
			logger.Error("audit log: schema migration failed", "err", err)
		}
	}
}

// NewSQLiteStore opens (and initializes) the audit database and starts the
// batch writer.
func NewSQLiteStore(dbPath string, logger *slog.Logger) (*SQLiteStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("logstore: create dir: %w", err)
	}
	dsn := "file:" + dbPath +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("logstore: open %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1) // sqlite: serialize writers, avoid busy locks
	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("logstore: init schema: %w", err)
	}
	migrate(db, logger)
	// Read pool: query_only connections on the same WAL database. Console
	// queries (FTS/LIKE scans) run here and can no longer starve the audit
	// writer of the single write connection.
	rdsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=query_only(true)"
	rdb, err := sql.Open("sqlite", rdsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("logstore: open read pool: %w", err)
	}
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)
	s := &SQLiteStore{
		db:     db,
		rdb:    rdb,
		dbPath: dbPath,
		logger: logger,
		ch:     make(chan Event, sqliteQueueSize),
		done:   make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// readTimeoutCtx bounds every read query so a heavy console scan cannot hold
// a pooled connection (and its goroutine) indefinitely.
func (s *SQLiteStore) readTimeoutCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), sqliteReadTimeout)
}

// SetWriteHook registers a synchronous callback invoked for every accepted
// event at enqueue time (before the batch commit). Used by the penalty
// engine to count attack events with minimal latency; nil clears the hook.
func (s *SQLiteStore) SetWriteHook(fn func(Event)) {
	if fn == nil {
		s.writeHook.Store(func(Event) {})
		return
	}
	s.writeHook.Store(fn)
}

// Write enqueues an event without blocking; on queue overflow the event is
// dropped and counted (exposed via Dropped for metrics).
func (s *SQLiteStore) Write(ev *Event) {
	if ev == nil {
		return
	}
	if ev.TS == "" {
		ev.TS = time.Now().Format(time.RFC3339Nano)
	}
	if fn, ok := s.writeHook.Load().(func(Event)); ok {
		fn(*ev)
	}
	select {
	case s.ch <- *ev:
		s.pending.Add(1)
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped due to queue overflow.
func (s *SQLiteStore) Dropped() int64 { return s.dropped.Load() }

// Pending returns the number of queued-but-uncommitted events (queue depth
// gauge for observability).
func (s *SQLiteStore) Pending() int64 { return s.pending.Load() }

// Flush waits until every queued event is committed (bounded by timeout).
func (s *SQLiteStore) Flush(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for s.pending.Load() > 0 {
		if time.Now().After(deadline) {
			return fmt.Errorf("logstore: flush timeout with %d pending events", s.pending.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// Close flushes pending events and stops the writer.
func (s *SQLiteStore) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.ch)
		<-s.done
		_ = s.rdb.Close()
		err = s.db.Close()
	})
	return err
}

func (s *SQLiteStore) loop() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("audit writer panic recovered", "panic", r)
		}
	}()
	defer close(s.done)
	batch := make([]Event, 0, sqliteBatchSize)
	ticker := time.NewTicker(sqliteFlushEvery)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.insert(batch)
		batch = batch[:0]
	}
	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= sqliteBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *SQLiteStore) insert(batch []Event) {
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("audit log: begin tx failed", "err", err)
		s.pending.Add(-int64(len(batch)))
		s.dropped.Add(int64(len(batch)))
		return
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO events
		(ts_ms, trace_id, site, client_ip, method, path, url, action, rule, reason, status, body_bytes, ua, bot_class, raw)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		s.logger.Error("audit log: prepare failed", "err", err)
		s.pending.Add(-int64(len(batch)))
		s.dropped.Add(int64(len(batch)))
		return
	}
	for i := range batch {
		ev := &batch[i]
		raw, merr := json.Marshal(ev)
		if merr != nil {
			raw = []byte("{}")
		}
		if _, err := stmt.Exec(
			parseEventTS(ev.TS).UnixMilli(), ev.TraceID, ev.Site, ev.ClientIP, ev.Method,
			ev.Path, ev.URL, ev.Action, ev.Rule, ev.Reason, ev.Status, ev.BodyBytes,
			ev.UserAgent, ev.BotClass, string(raw)); err != nil {
			s.logger.Error("audit log: insert failed", "err", err)
		}
	}
	if err := stmt.Close(); err != nil {
		s.logger.Error("audit log: stmt close failed", "err", err)
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("audit log: commit failed", "err", err)
	}
	s.pending.Add(-int64(len(batch)))
}

func parseEventTS(ts string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	return time.Now()
}

// Recent returns up to n newest events (newest first) from the database.
// Events younger than the last batch commit (~0.5s) may not be visible yet.
func (s *SQLiteStore) Recent(n int) []Event {
	if n <= 0 {
		return nil
	}
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx, `SELECT raw FROM events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		s.logger.Error("audit log: recent query failed", "err", err)
		return nil
	}
	defer rows.Close()
	out := make([]Event, 0, n)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var ev Event
		if json.Unmarshal([]byte(raw), &ev) != nil {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// searchWhere builds the WHERE clause shared by Query and Count.
func searchWhere(q LogQuery) (string, []any) {
	where := []string{"1=1"}
	var args []any
	if !q.Since.IsZero() {
		where = append(where, "ts_ms >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if !q.Until.IsZero() {
		where = append(where, "ts_ms <= ?")
		args = append(args, q.Until.UnixMilli())
	}
	if q.Action != "" {
		where = append(where, "action = ?")
		args = append(args, q.Action)
	}
	if q.Site != "" {
		where = append(where, `site LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.Site)+"%")
	}
	if q.Rule != "" {
		where = append(where, `rule LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.Rule)+"%")
	}
	if q.SrcIP != "" {
		where = append(where, `client_ip LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(q.SrcIP)+"%")
	}
	if t := strings.TrimSpace(q.Text); t != "" {
		where = append(where, "id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
		args = append(args, ftsQuery(t))
	}
	if tid := strings.TrimSpace(q.TraceID); tid != "" {
		where = append(where, `trace_id LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(tid)+"%")
	}
	return strings.Join(where, " AND "), args
}

// Query returns events matching the filters, newest first. Site and rule
// filters are substring matches (LIKE '%v%'), the source IP is a prefix
// match and Text runs an FTS5 full-text query.
func (s *SQLiteStore) Query(q LogQuery) ([]Event, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	where, args := searchWhere(q)
	args = append(args, q.limit())
	sql := `SELECT raw FROM events WHERE ` + where + ` ORDER BY id DESC LIMIT ?`
	if q.Offset > 0 {
		sql += ` OFFSET ?`
		args = append(args, q.Offset)
	}
	rows, err := s.rdb.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("logstore: query: %w", err)
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var ev Event
		if json.Unmarshal([]byte(raw), &ev) != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Purge deletes events older than the given timestamp (retention job and
// disk-guard reclaim: the oldest-first policy is enforced by the callers).
func (s *SQLiteStore) Purge(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM events WHERE ts_ms < ?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("logstore: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Count returns how many events match the query filters, ignoring
// Limit/Offset — the pagination total for the console log view.
func (s *SQLiteStore) Count(q LogQuery) (int, error) {
	where, args := searchWhere(q)
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	var n int
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("logstore: count: %w", err)
	}
	return n, nil
}

// TypeDistribution groups the window's events by derived attack type
// (rule → AttackTypeOf) and returns the top hits, for the dashboard
// attack-type donut.
func (s *SQLiteStore) TypeDistribution(since, until time.Time, topN int) ([]TopHit, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT rule, COUNT(*) AS c FROM events
		  WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != ''
		  GROUP BY rule ORDER BY c DESC LIMIT ?`,
		append([]any{since.UnixMilli(), until.UnixMilli()}, topN)...)
	if err != nil {
		return nil, fmt.Errorf("logstore: type distribution: %w", err)
	}
	defer rows.Close()
	merged := map[string]int{}
	order := []string{}
	for rows.Next() {
		var rule string
		var c int
		if rows.Scan(&rule, &c) != nil {
			continue
		}
		t := AttackTypeOf(rule)
		if t == "" {
			t = rule
		}
		if _, seen := merged[t]; !seen {
			order = append(order, t)
		}
		merged[t] += c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(order, func(i, j int) bool { return merged[order[i]] > merged[order[j]] })
	out := make([]TopHit, 0, len(order))
	for _, t := range order {
		out = append(out, TopHit{Key: t, Count: merged[t]})
	}
	return out, nil
}

// TopSourceIPs groups the window's attack events by client_ip and returns
// the top addresses, feeding the GeoIP attack-origin aggregation. The
// criteria matches the attack-type donut (TypeDistribution): the event must
// carry both an action and a rule, so monitor-level noise without a rule
// and malformed rows are excluded.
func (s *SQLiteStore) TopSourceIPs(since, until time.Time, limit int) ([]TopHit, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT client_ip, COUNT(*) AS c FROM events
		  WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != '' AND client_ip != ''
		  GROUP BY client_ip ORDER BY c DESC, client_ip ASC LIMIT ?`,
		since.UnixMilli(), until.UnixMilli(), limit)
	if err != nil {
		return nil, fmt.Errorf("logstore: top source ips: %w", err)
	}
	defer rows.Close()
	out := []TopHit{}
	for rows.Next() {
		var h TopHit
		if rows.Scan(&h.Key, &h.Count) == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

// RuleTopHits ranks the window's most-hit rules and returns the total
// number of attack events in the same window (same criteria, unbounded by
// topN). The attack criteria matches TypeDistribution: the event must carry
// both an action and a rule, so empty-rule and action-less rows are
// excluded; feeds the policy page rule-hit statistics card.
func (s *SQLiteStore) RuleTopHits(since, until time.Time, limit int) ([]TopHit, int64, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	if limit <= 0 {
		limit = topN
	}
	args := []any{since.UnixMilli(), until.UnixMilli()}
	var total int64
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != ''`,
		args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("logstore: rule top hits total: %w", err)
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT rule AS k, COUNT(*) AS c FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != ''
		 GROUP BY k ORDER BY c DESC, k ASC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("logstore: rule top hits: %w", err)
	}
	defer rows.Close()
	out := []TopHit{}
	for rows.Next() {
		var h TopHit
		if rows.Scan(&h.Key, &h.Count) == nil {
			out = append(out, h)
		}
	}
	return out, total, rows.Err()
}

// SiteAttackCounts groups the window's attack events by site, feeding the
// per-site dashboard card. The criteria matches RuleTopHits (action != ''
// AND rule != ''); empty site labels are excluded.
func (s *SQLiteStore) SiteAttackCounts(since, until time.Time) ([]TopHit, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT site, COUNT(*) AS c FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != '' AND site != ''
		 GROUP BY site ORDER BY c DESC, site ASC`,
		since.UnixMilli(), until.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("logstore: site attack counts: %w", err)
	}
	defer rows.Close()
	out := []TopHit{}
	for rows.Next() {
		var h TopHit
		if rows.Scan(&h.Key, &h.Count) == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

// AttackTotal counts the attack events in the window under the same criteria
// as TopSourceIPs (action != '' AND rule != '' AND client_ip != '') — the
// denominator of the attack-origin view (unbounded by the IP limit).
func (s *SQLiteStore) AttackTotal(since, until time.Time) (int64, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	var n int64
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND action != '' AND rule != '' AND client_ip != ''`,
		since.UnixMilli(), until.UnixMilli()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("logstore: attack total: %w", err)
	}
	return n, nil
}

// Aggregate builds a Summary over [since, until) with SQL group-bys.
func (s *SQLiteStore) Aggregate(since, until time.Time) (*Summary, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	if since.After(until) {
		return nil, fmt.Errorf("logstore: aggregate window is inverted")
	}
	lo, hi := since.UnixMilli(), until.UnixMilli()
	base := []any{lo, hi}
	sum := &Summary{
		WindowStart: since.UTC().Format(time.RFC3339),
		WindowEnd:   until.UTC().Format(time.RFC3339),
		ByAction:    map[string]int{},
		TopBotClass: map[string]int{},
	}

	var minTSms, maxTSms int64
	if err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MIN(ts_ms),0), COALESCE(MAX(ts_ms),0)
		 FROM events WHERE ts_ms >= ? AND ts_ms <= ?`,
		base...,
	).Scan(&sum.Total, &minTSms, &maxTSms); err != nil {
		return nil, fmt.Errorf("logstore: aggregate: %w", err)
	}
	if sum.Total > 0 {
		sum.FirstTS = time.UnixMilli(minTSms).UTC().Format(time.RFC3339Nano)
		sum.LastTS = time.UnixMilli(maxTSms).UTC().Format(time.RFC3339Nano)
	}

	rows, err := s.rdb.QueryContext(ctx,
		`SELECT action, COUNT(*) FROM events WHERE ts_ms >= ? AND ts_ms <= ? GROUP BY action`,
		base...)
	if err != nil {
		return nil, fmt.Errorf("logstore: aggregate by action: %w", err)
	}
	for rows.Next() {
		var action string
		var n int
		if rows.Scan(&action, &n) == nil {
			sum.ByAction[action] = n
		}
	}
	rows.Close()

	rows, err = s.rdb.QueryContext(ctx,
		`SELECT bot_class, COUNT(*) FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND bot_class != '' GROUP BY bot_class`,
		base...)
	if err != nil {
		return nil, fmt.Errorf("logstore: aggregate by bot: %w", err)
	}
	for rows.Next() {
		var class string
		var n int
		if rows.Scan(&class, &n) == nil {
			sum.TopBotClass[class] = n
		}
	}
	rows.Close()

	if sum.TopRules, err = s.topHits(lo, hi, "rule", ""); err != nil {
		return nil, err
	}
	if sum.TopIPs, err = s.topHits(lo, hi, "client_ip", ""); err != nil {
		return nil, err
	}
	if sum.TopPaths, err = s.topHits(lo, hi, `method || ' ' || path`, "path != ''"); err != nil {
		return nil, err
	}
	if sum.TopSites, err = s.topHits(lo, hi, "site", ""); err != nil {
		return nil, err
	}

	if err := s.rdb.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(c),0) FROM (
			SELECT COUNT(*) AS c FROM events
			WHERE ts_ms >= ? AND ts_ms <= ? AND rule != '' AND client_ip != ''
			GROUP BY client_ip, rule HAVING COUNT(*) >= 20
		 )`, base...).Scan(&sum.SuspectedFP); err != nil {
		return nil, fmt.Errorf("logstore: aggregate fp: %w", err)
	}
	return sum, nil
}

// Trend buckets events over [since, until) into bucketSec-wide windows
// (epoch-aligned, floor division on ts_ms). Returns sparse buckets sorted by
// time; the API layer zero-fills for charting.
func (s *SQLiteStore) Trend(since, until time.Time, bucketSec int) ([]TrendBucket, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if until.IsZero() {
		until = time.Now()
	}
	if since.After(until) {
		return nil, fmt.Errorf("logstore: trend window is inverted")
	}
	if bucketSec <= 0 {
		bucketSec = 300
	}
	if bucketSec < 60 {
		bucketSec = 60
	}
	bs := int64(bucketSec) * 1000
	lo, hi := since.UnixMilli(), until.UnixMilli()
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT (ts_ms / ?) * ? AS bucket, action, COUNT(*) FROM events
		 WHERE ts_ms >= ? AND ts_ms < ? GROUP BY bucket, action`,
		bs, bs, lo, hi)
	if err != nil {
		return nil, fmt.Errorf("logstore: trend: %w", err)
	}
	defer rows.Close()
	byMs := map[int64]*TrendBucket{}
	order := []int64{}
	for rows.Next() {
		var (
			ms     int64
			action string
			n      int
		)
		if err := rows.Scan(&ms, &action, &n); err != nil {
			continue
		}
		b, seen := byMs[ms]
		if !seen {
			b = &TrendBucket{BucketMs: ms, ByAction: map[string]int{}}
			byMs[ms] = b
			order = append(order, ms)
		}
		b.ByAction[action] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logstore: trend rows: %w", err)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	out := make([]TrendBucket, 0, len(order))
	for _, ms := range order {
		out = append(out, *byMs[ms])
	}
	return out, nil
}

// topHits returns the top-N values of one column within the window. extraCond
// narrows the population (e.g. exclude empty keys) without touching the
// time bounds.
func (s *SQLiteStore) topHits(lo, hi int64, col, extraCond string) ([]TopHit, error) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	if extraCond == "" {
		extraCond = col + " != ''"
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT `+col+` AS k, COUNT(*) AS c FROM events
		 WHERE ts_ms >= ? AND ts_ms <= ? AND `+extraCond+`
		 GROUP BY k ORDER BY c DESC, k ASC LIMIT ?`,
		lo, hi, topN)
	if err != nil {
		return nil, fmt.Errorf("logstore: aggregate top: %w", err)
	}
	defer rows.Close()
	out := []TopHit{}
	for rows.Next() {
		var h TopHit
		if rows.Scan(&h.Key, &h.Count) == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// ftsQuery converts free text into a safe FTS5 MATCH expression: every
// whitespace-separated token is quoted (implicit AND); a trailing '*' turns
// the token into a prefix query.
func ftsQuery(text string) string {
	toks := strings.Fields(text)
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		prefix := strings.HasSuffix(t, "*")
		t = strings.TrimSuffix(t, "*")
		t = strings.ReplaceAll(t, `"`, `""`)
		if t == "" {
			continue
		}
		if prefix {
			out = append(out, `"`+t+`"*`)
		} else {
			out = append(out, `"`+t+`"`)
		}
	}
	return strings.Join(out, " ")
}

// OldestEventTime returns the timestamp of the oldest live event (disk guard
// FIFO reclaim). ok=false when the store is empty.
func (s *SQLiteStore) OldestEventTime() (time.Time, bool) {
	ctx, cancel := s.readTimeoutCtx()
	defer cancel()
	row := s.rdb.QueryRowContext(ctx, `SELECT MIN(ts_ms) FROM events`)
	var ms int64
	if err := row.Scan(&ms); err != nil || ms == 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(ms).UTC(), true
}

// DBPath returns the audit database file path (disk guard volume check).
func (s *SQLiteStore) DBPath() string { return s.dbPath }

// Backlogged reports ingest-side saturation: the write queue holds more
// than 80% of its capacity. Callers can shed load or back off while true
// instead of losing events to the queue.
func (s *SQLiteStore) Backlogged() bool {
	return s.pending.Load() > sqliteQueueSize*4/5
}
