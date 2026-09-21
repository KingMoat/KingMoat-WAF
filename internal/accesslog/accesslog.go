// Package accesslog implements the full access-log pipeline: one entry per
// forwarded (or blocked/challenged/redirected) request, batched and pushed
// asynchronously to ClickHouse, Elasticsearch or Loki. The request hot path
// only pays a bounded-queue send; drops under backpressure are counted.
package accesslog

import (
	"bufio"
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/s3sink"
	"github.com/kingmoat/kingmoat/internal/redact"
	"github.com/kingmoat/kingmoat/internal/syslogsink"
)

// Entry is one access-log record (JSON fields are the storage schema).
type Entry struct {
	TS        string `json:"ts"`
	TraceID   string `json:"trace_id,omitempty"`
	Site      string `json:"site,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Query     string `json:"query,omitempty"`
	Status    int    `json:"status,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Outcome   string `json:"outcome,omitempty"` // forwarded/blocked/challenged/monitor_forwarded/redirected
	Rule      string `json:"rule,omitempty"`    // last deny rule, when blocked
	AttackType string `json:"attack_type,omitempty"`
}

// Sink consumes access entries; implementations must be safe for concurrent
// use and never block the hot path.
type Sink interface {
	Write(e *Entry)
	Close() error
}

// Shipper batches entries and pushes them to the configured platform.
type Shipper struct {
	kind    string // clickhouse | elasticsearch | loki | s3 | syslog
	url     string
	index   string
	s3cfg   *config.S3Settings
	syslog  *syslogsink.Client
	client  *http.Client
	ch      chan Entry
	dropped atomic.Int64
	done    chan struct{}
	logger  *slog.Logger

	batchSize int
	flush     time.Duration
	samplePct int
	sampleCtr atomic.Uint64
	// basic-auth credentials for the HTTP sinks (ch / es / loki).
	username string
	password string
}

// New validates settings and starts the batcher.
func New(cfg config.AccessLogSettings, logger *slog.Logger) (*Shipper, error) {
	switch cfg.Type {
	case "clickhouse", "elasticsearch", "loki", "s3", "syslog":
	default:
		return nil, fmt.Errorf("accesslog: unsupported type %q", cfg.Type)
	}
	if cfg.Type == "s3" {
		if err := cfg.S3.Validate(); err != nil {
			return nil, err
		}
	} else if cfg.URL == "" {
		return nil, fmt.Errorf("accesslog: url is required")
	}
	if cfg.Type == "syslog" {
		if err := cfg.Syslog.Validate(); err != nil {
			return nil, fmt.Errorf("accesslog: syslog: %w", err)
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Shipper{
		kind:  cfg.Type,
		url:   cfg.URL,
		index: cfg.Index,
		s3cfg: cfg.S3,
		client: &http.Client{Timeout: durationSec(cfg.TimeoutSec, 5)},
		ch:    make(chan Entry, queueSize),
		done:  make(chan struct{}),
		logger: logger,
		username: cfg.Username,
		password: cfg.Password,

		batchSize: cfg.BatchSize,
		flush:     durationSec(cfg.FlushSec, 5),
		samplePct: cfg.SamplePctOrDefault(),
	}
	if cfg.Type == "syslog" {
		sys, serr := syslogsink.New(config.ShipperSettings{
			Type:  "syslog",
			URL:   cfg.URL,
			Index: cfg.Index,
			Syslog: cfg.Syslog,
		}, "kingmoat_access")
		if serr != nil {
			return nil, serr
		}
		s.syslog = sys
	}
	if s.index == "" {
		s.index = "kingmoat_access"
	}
	if s.batchSize <= 0 {
		s.batchSize = 200
	}
	go s.loop()
	return s, nil
}

const queueSize = 8192

// Write implements Sink (non-blocking; sampling applies here).
func (s *Shipper) Write(e *Entry) {
	if e == nil || s.samplePct < 100 {
		// deterministic 1..N sampling without a lock
		if s.samplePct < 100 {
			n := s.sampleCtr.Add(1)
			if int(n%100) >= s.samplePct {
				return
			}
		}
	}
	if e == nil {
		return
	}
	select {
	case s.ch <- *e:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of entries dropped under backpressure.
func (s *Shipper) Dropped() int64 { return s.dropped.Load() }

// Depth returns the current queue length (observability gauge).
func (s *Shipper) Depth() int { return len(s.ch) }

// Close flushes pending entries and stops the batcher.
func (s *Shipper) Close() error {
	close(s.ch)
	<-s.done
	return nil
}

func (s *Shipper) loop() {
	defer close(s.done)
	batch := make([]Entry, 0, s.batchSize)
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.push(batch)
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
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *Shipper) push(batch []Entry) {
	if s.kind == "syslog" {
		for i := range batch {
			e := &batch[i]
			ts := syslogsink.ParseEventTS(e.TS)
			msg := syslogsink.MarshalLine(e)
			sev := syslogsink.SeverityFor(e.Outcome)
			if err := s.syslog.Send(ts, e.Outcome, string(msg), sev); err != nil {
				s.logger.Warn("accesslog syslog send failed", "err", redact.String(err.Error()))
			}
		}
		return
	}
	var body []byte
	var contentType string
	var target string
	switch s.kind {
	case "s3":
		c, err := s3sink.New(s.s3cfg)
		if err != nil {
			s.logger.Warn("accesslog s3 client failed", "err", err)
			return
		}
		var buf bytes.Buffer
		for _, e := range batch {
			b, _ := json.Marshal(e)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		if err := c.PutJSONL(context.Background(), "access", buf.Bytes()); err != nil {
			s.logger.Warn("accesslog s3 put failed", "err", err)
		}
		return
	case "clickhouse":
		// JSONEachRow: one JSON object per line into a fixed table.
		var buf bytes.Buffer
		for _, e := range batch {
			b, _ := json.Marshal(e)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		body = buf.Bytes()
		contentType = "text/plain; charset=utf-8"
		q := "INSERT INTO " + s.index + " FORMAT JSONEachRow"
		target = joinURL(s.url, "/?query="+url.QueryEscape(q))
	case "elasticsearch":
		var buf bytes.Buffer
		day := time.Now().UTC().Format("2006.01.02")
		for _, e := range batch {
			buf.WriteString(fmt.Sprintf(`{"index":{"_index":"%s-%s"}}`+"\n", s.index, day))
			b, _ := json.Marshal(e)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		body = buf.Bytes()
		contentType = "application/x-ndjson"
		target = joinURL(s.url, "/_bulk")
	case "loki":
		vals := make([][]string, 0, len(batch))
		for _, e := range batch {
			b, _ := json.Marshal(e)
			ts := e.TS
			if t, err := time.Parse(time.RFC3339Nano, e.TS); err == nil {
				ts = fmt.Sprint(t.UnixNano())
			}
			vals = append(vals, []string{ts, string(b)})
		}
		payload, _ := json.Marshal(map[string]any{
			"streams": []map[string]any{
				{"stream": map[string]string{"app": s.index, "job": "kingmoat-access"}, "values": vals},
			},
		})
		body = payload
		contentType = "application/json"
		target = joinURL(s.url, "/loki/api/v1/push")
	default:
		return
	}

	req, rerr := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if rerr != nil {
		s.logger.Warn("accesslog push request build failed", "type", s.kind, "err", redact.String(rerr.Error()))
		return
	}
	req.Header.Set("Content-Type", contentType)
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn("accesslog push failed", "type", s.kind, "err", redact.String(err.Error()))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.logger.Warn("accesslog push rejected", "type", s.kind, "status", resp.StatusCode)
	}
}

// Recorder wraps a ResponseWriter to capture the outgoing status and byte
// count while transparently preserving Flush/Hijack for WebSocket and
// streaming responses.
type Recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

// NewRecorder wraps w.
func NewRecorder(w http.ResponseWriter) *Recorder { return &Recorder{ResponseWriter: w} }

// Status returns the captured status code (0 = none written yet).
func (r *Recorder) Status() int { return r.status }

// BytesWritten returns the captured body byte count.
func (r *Recorder) BytesWritten() int { return r.bytes }

// WriteHeader captures the status and delegates.
func (r *Recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write captures the byte count and delegates.
func (r *Recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush forwards to the underlying flusher when available.
func (r *Recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying hijacker when available so WebSocket
// upgrades keep working.
func (r *Recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func durationSec(n int, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}

// joinURL concatenates a base URL and a path/query.
func joinURL(base, suffix string) string {
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + suffix
}
