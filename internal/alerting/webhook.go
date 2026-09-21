// Package alerting pushes audit events to an HTTP webhook endpoint.
// Delivery is asynchronous with a bounded queue: events are dropped (and
// counted) under backpressure so the request hot path is never blocked.
package alerting

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/redact"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// Webhook is a logstore.Store decorator that mirrors every event to the
// configured endpoint (POST JSON).
type Webhook struct {
	url     string
	secret  string
	keyword string
	client  *http.Client
	ch      chan logstore.Event
	size    int
	dropped atomic.Int64
	done    chan struct{}
	logger  *slog.Logger
}

const queueSize = 1024

// NewWebhook builds the mirror with the default queue size.
func NewWebhook(cfg config.WebhookSettings, logger *slog.Logger) *Webhook {
	return newWebhook(cfg, queueSize, logger)
}

// newWebhook allows tests to inject a small queue.
func newWebhook(cfg config.WebhookSettings, size int, logger *slog.Logger) *Webhook {
	if logger == nil {
		logger = slog.Default()
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	w := &Webhook{
		url:    cfg.URL,
		secret: cfg.Secret,
		keyword: cfg.Keyword,
		client: &http.Client{Timeout: timeout},
		ch:     make(chan logstore.Event, size),
		size:   size,
		done:   make(chan struct{}),
		logger: logger,
	}
	go w.loop()
	return w
}

// Write implements logstore.Store (non-blocking fan-in).
func (w *Webhook) Write(ev *logstore.Event) {
	if ev == nil {
		return
	}
	select {
	case w.ch <- *ev:
	default:
		w.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped under backpressure.
func (w *Webhook) Dropped() int64 { return w.dropped.Load() }

// Close flushes pending events and stops the sender.
func (w *Webhook) Close() error {
	close(w.ch)
	<-w.done
	return nil
}

func (w *Webhook) loop() {
	defer close(w.done)
	for ev := range w.ch {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		if w.keyword != "" {
			// 关键词认证:在事件 JSON 上补 keyword 字段(机器人校验用)
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				m["keyword"] = w.keyword
				b, err = json.Marshal(m)
				if err != nil {
					continue
				}
			}
		}
		req, rerr := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(b))
		if rerr != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if w.secret != "" {
			mac := hmac.New(sha256.New, []byte(w.secret))
			mac.Write(b)
			req.Header.Set("X-KingMoat-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := w.client.Do(req)
		if err != nil {
			w.logger.Warn("webhook deliver failed", "url", redact.URL(w.url), "err", redact.String(err.Error()))
			continue
		}
		if resp.StatusCode >= 300 {
			w.logger.Warn("webhook deliver rejected", "url", redact.URL(w.url), "status", resp.StatusCode)
		}
		resp.Body.Close()
	}
}
