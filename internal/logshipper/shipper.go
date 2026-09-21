// Package logshipper streams audit events to external log platforms
// (ClickHouse JSONEachRow, Elasticsearch bulk API or Loki push API) with
// batching and drop counting.
package logshipper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/redact"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/syslogsink"
)

// Shipper is a logstore.Store that batches events and pushes them out.
type Shipper struct {
	kind    string // clickhouse | elasticsearch | loki | s3 | syslog | kafka
	url     string
	index   string
	client  *http.Client
	s3      *s3Target
	syslog  *syslogsink.Client
	kafka   *kafkaTarget
	ch      chan logstore.Event
	dropped atomic.Int64
	done    chan struct{}
	logger  *slog.Logger

	batchSize int
	flush     time.Duration
	// basic-auth credentials for the es / loki / clickhouse HTTP sinks.
	username string
	password string
}

const queueSize = 8192

// New validates settings and starts the batcher with the default queue.
func New(cfg config.ShipperSettings, logger *slog.Logger) (*Shipper, error) {
	return newShipper(cfg, queueSize, logger)
}

// newShipper allows tests to inject a small queue.
func newShipper(cfg config.ShipperSettings, size int, logger *slog.Logger) (*Shipper, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Type != "elasticsearch" && cfg.Type != "loki" && cfg.Type != "clickhouse" && cfg.Type != "s3" && cfg.Type != "syslog" && cfg.Type != "kafka" {
		return nil, fmt.Errorf("logshipper: unsupported type %q", cfg.Type)
	}
	s := &Shipper{
		kind:   cfg.Type,
		url:    cfg.URL,
		index:  cfg.Index,
		client: &http.Client{Timeout: durationSec(cfg.TimeoutSec, 5)},
		ch:     make(chan logstore.Event, size),
		done:   make(chan struct{}),
		logger: logger,

		batchSize: cfg.BatchSize,
		flush:     durationSec(cfg.FlushSec, 5),
		username:  cfg.Username,
		password:  cfg.Password,
	}
	if cfg.Type == "s3" {
		tgt, terr := newS3Target(cfg)
		if terr != nil {
			return nil, terr
		}
		s.s3 = tgt
		tgt.checkBucket(logger)
	}
	if cfg.Type == "syslog" {
		sys, serr := syslogsink.New(cfg, "kingmoat")
		if serr != nil {
			return nil, serr
		}
		s.syslog = sys
	}
	if cfg.Type == "kafka" {
		tgt, terr := newKafkaTarget(cfg)
		if terr != nil {
			return nil, terr
		}
		s.kafka = tgt
	}
	if s.batchSize <= 0 {
		s.batchSize = 100
	}
	if s.index == "" {
		s.index = "kingmoat"
	}
	go s.loop()
	return s, nil
}

// Write implements logstore.Store (non-blocking fan-in).
func (s *Shipper) Write(ev *logstore.Event) {
	if ev == nil {
		return
	}
	select {
	case s.ch <- *ev:
	default:
		s.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped under backpressure.
func (s *Shipper) Dropped() int64 { return s.dropped.Load() }

// Depth returns the current queue length (observability gauge).
func (s *Shipper) Depth() int { return len(s.ch) }

// Close flushes pending events and stops the batcher.
func (s *Shipper) Close() error {
	close(s.ch)
	<-s.done
	if s.kafka != nil {
		_ = s.kafka.close()
	}
	return nil
}

func (s *Shipper) loop() {
	defer close(s.done)
	batch := make([]logstore.Event, 0, s.batchSize)
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

func (s *Shipper) push(batch []logstore.Event) {
	if s.kind == "kafka" {
		if err := s.kafka.pushBatch(batch); err != nil {
			s.logger.Warn("logshipper kafka push failed", "err", redact.String(err.Error()))
		}
		return
	}
	if s.kind == "s3" {
		timeout := s.flush
		if timeout < 30*time.Second {
			timeout = 30 * time.Second
		}
		if err := s.s3.pushBatch(batch, timeout); err != nil {
			s.logger.Warn("logshipper s3 push failed", "err", redact.String(err.Error()))
		}
		return
	}
	if s.kind == "syslog" {
		for i := range batch {
			ev := &batch[i]
			ts := syslogsink.ParseEventTS(ev.TS)
			msg := syslogsink.MarshalLine(ev)
			sev := syslogsink.SeverityFor(ev.Action)
			if err := s.syslog.Send(ts, ev.Action, string(msg), sev); err != nil {
				s.logger.Warn("logshipper syslog send failed", "err", redact.String(err.Error()))
			}
		}
		return
	}
	var body []byte
	var contentType string
	var target string
	switch s.kind {
	case "clickhouse":
		// HTTP interface, JSONEachRow: one event per line into a fixed table.
		var buf bytes.Buffer
		for _, ev := range batch {
			b, _ := json.Marshal(ev)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		q := "INSERT INTO " + s.index + " FORMAT JSONEachRow"
		body, contentType = buf.Bytes(), "text/plain; charset=utf-8"
		target = strings.TrimSuffix(s.url, "/") + "/?query=" + url.QueryEscape(q)
	case "elasticsearch":
		var buf bytes.Buffer
		day := time.Now().UTC().Format("2006.01.02")
		for _, ev := range batch {
			buf.WriteString(fmt.Sprintf(`{"index":{"_index":"%s-%s"}}`+"\n", s.index, day))
			b, _ := json.Marshal(ev)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		body, contentType, target = buf.Bytes(), "application/x-ndjson", s.url+"/_bulk"
	case "loki":
		vals := make([][]string, 0, len(batch))
		for _, ev := range batch {
			b, _ := json.Marshal(ev)
			ts := ev.TS
			if t, err := time.Parse(time.RFC3339Nano, ev.TS); err == nil {
				ts = fmt.Sprint(t.UnixNano())
			}
			vals = append(vals, []string{ts, string(b)})
		}
		payload, _ := json.Marshal(map[string]any{
			"streams": []map[string]any{
				{"stream": map[string]string{"app": s.index, "job": "kingmoat"}, "values": vals},
			},
		})
		body, contentType, target = payload, "application/json", s.url+"/loki/api/v1/push"
	default:
		return
	}

	req, rerr := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if rerr != nil {
		s.logger.Warn("logshipper push request build failed", "type", s.kind, "err", redact.String(rerr.Error()))
		return
	}
	req.Header.Set("Content-Type", contentType)
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn("logshipper push failed", "type", s.kind, "err", redact.String(err.Error()))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.logger.Warn("logshipper push rejected", "type", s.kind, "status", resp.StatusCode)
	}
}

func durationSec(n int, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}

// UploadArchive uploads a local file (e.g. the daily audit DB snapshot) to
// the configured S3-compatible bucket. Only available for type "s3".
func (s *Shipper) UploadArchive(localPath, objectKey string) error {
	if s.s3 == nil {
		return fmt.Errorf("logshipper: archive upload requires log_shipper.type = \"s3\"")
	}
	return s.s3.uploadArchive(localPath, objectKey)
}
