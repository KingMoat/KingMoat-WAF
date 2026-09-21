package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// logsPageResponse is the paginated console log view payload.
type logsPageResponse struct {
	Items    []logstore.Event `json:"items"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// parseLogQuery extracts the shared filter parameters (action, site, rule,
// ip, q, since, until) from the request.
func parseLogQuery(qp url.Values) (logstore.LogQuery, bool) {
	var q logstore.LogQuery
	filtered := false
	if v := qp.Get("action"); v != "" {
		q.Action, filtered = v, true
	}
	if v := qp.Get("site"); v != "" {
		q.Site, filtered = v, true
	}
	if v := qp.Get("rule"); v != "" {
		q.Rule, filtered = v, true
	}
	if v := qp.Get("ip"); v != "" {
		q.SrcIP, filtered = v, true
	}
	if v := qp.Get("q"); v != "" {
		q.Text, filtered = v, true
	}
	if v := qp.Get("trace_id"); v != "" {
		q.TraceID, filtered = v, true
	}
	if v := qp.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since, filtered = t, true
		}
	}
	if v := qp.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Until, filtered = t, true
		}
	}
	return q, filtered
}

// logsGate wraps the audit-query gate shared by the export handler.
func (s *Server) logsGate(w http.ResponseWriter) (func(), time.Duration, bool) {
	_, cfg := s.opts.Center.Current()
	release, timeout, ok := s.auditQueryGate(cfg)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return nil, 0, false
	}
	return release, timeout, true
}

// handleLogsExport streams filtered audit events as NDJSON
// (GET /api/logs/export). Caps at 50k rows so a runaway export cannot pin
// the read pool.
func (s *Server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	release, timeout, ok := s.logsGate(w)
	if !ok {
		return
	}
	defer release()

	qp := r.URL.Query()
	q, _ := parseLogQuery(qp)
	q.Limit = 1000
	if v := qp.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50000 {
			q.Limit = n
		}
	}
	srch, _ := s.opts.Logs.(logstore.Searcher)
	if srch == nil {
		writeErr(w, http.StatusNotImplemented, fmt.Errorf("log export requires the sqlite audit store"))
		return
	}

	type result struct {
		evs []logstore.Event
		err error
	}
	done := make(chan result, 1)
	go func() {
		evs, err := srch.Query(q)
		done <- result{evs, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			writeErr(w, http.StatusInternalServerError, res.err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="kingmoat-attacks.ndjson"`)
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		for _, ev := range res.evs {
			_ = enc.Encode(ev)
		}
		_ = bw.Flush()
	case <-time.After(timeout):
		writeErr(w, http.StatusGatewayTimeout, fmt.Errorf("log export timed out"))
	}
}

// handleLogshipTest probes the configured log-shipper sink connectivity
// (POST /api/logship/test). Read-only: nothing is shipped.
func (s *Server) handleLogshipTest(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	sh := cfg.LogShipper
	if sh == nil || sh.Type == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "detail": "未配置日志外发通道"})
		return
	}
	start := time.Now()
	ok, detail := probeSink(r.Context(), sh)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         ok,
		"type":       sh.Type,
		"latency_ms": time.Since(start).Milliseconds(),
		"detail":     detail,
	})
}

// probeSink performs a lightweight read-only connectivity check per sink type.
func probeSink(ctx context.Context, sh *config.ShipperSettings) (bool, string) {
	timeout := 4 * time.Second
	switch sh.Type {
	case "elasticsearch":
		return probeHTTPSink(ctx, "elasticsearch", sh.URL, "/_cluster/health")
	case "loki":
		return probeHTTPSink(ctx, "loki", sh.URL, "/ready")
	case "clickhouse":
		return probeHTTPSink(ctx, "clickhouse", sh.URL, "/?query=SELECT%201")
	case "s3":
		host := sh.Endpoint
		if host == "" {
			return false, "s3 endpoint is empty"
		}
		if !strings.Contains(host, ":") {
			if useSSL(sh) {
				host += ":443"
			} else {
				host += ":80"
			}
		}
		return probeDial("tcp", host, timeout)
	case "kafka":
		if len(sh.Brokers) == 0 {
			return false, "kafka brokers is empty"
		}
		tr := &kafka.Transport{DialTimeout: timeout, MetadataTTL: timeout, IdleTimeout: timeout}
		if sh.UseTLS {
			tr.TLS = &tls.Config{InsecureSkipVerify: true} // mirrors the shipper transport
		}
		switch sh.SASL {
		case "plain":
			tr.SASL = plain.Mechanism{Username: sh.Username, Password: sh.Password}
		case "scram-sha256":
			m, merr := scram.Mechanism(scram.SHA256, sh.Username, sh.Password)
			if merr != nil {
				return false, "kafka sasl init failed: " + merr.Error()
			}
			tr.SASL = m
		}
		cl := &kafka.Client{Addr: kafka.TCP(sh.Brokers...), Timeout: timeout, Transport: tr}
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req := &kafka.MetadataRequest{}
		if t := strings.TrimSpace(sh.Topic); t != "" {
			req.Topics = []string{t}
		}
		resp, merr := cl.Metadata(ctx2, req)
		if merr != nil {
			return false, "kafka metadata fetch failed: " + merr.Error()
		}
		return true, fmt.Sprintf("kafka ok (brokers=%d)", len(resp.Brokers))
	case "syslog":
		proto := sh.Syslog.Protocol
		if proto == "" && sh.URL != "" {
			if i := strings.Index(sh.URL, "://"); i > 0 {
				proto = sh.URL[:i]
			}
		}
		switch proto {
		case "tcp":
			return probeDial("tcp", strings.TrimPrefix(strings.TrimPrefix(sh.URL, "tcp://"), "tls://"), timeout)
		case "tls":
			addr := strings.TrimPrefix(sh.URL, "tls://")
			d := &net.Dialer{Timeout: timeout}
			conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: false})
			if err != nil {
				return false, "tls dial failed: " + err.Error()
			}
			conn.Close()
			return true, "tls connect ok"
		default: // udp: connectionless, a bound socket is the best we can verify
			addr := strings.TrimPrefix(sh.URL, "udp://")
			if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
				return false, "udp resolve failed: " + err.Error()
			}
			return true, "udp target resolved (delivery is best-effort)"
		}
	default:
		return false, "unknown sink type " + sh.Type
	}
}

// useSSL mirrors s3sink.UseSSL semantics (scheme default true).
func useSSL(sh *config.ShipperSettings) bool {
	if sh.UseSSL != nil {
		return *sh.UseSSL
	}
	return true
}

// probeHTTPSink probes an ES/Loki/ClickHouse HTTP endpoint.
func probeHTTPSink(ctx context.Context, name, base, probe string) (bool, string) {
	if base == "" {
		return false, name + " url is empty"
	}
	client := &http.Client{Timeout: 4 * time.Second}
	target := strings.TrimRight(base, "/") + probe
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, name + " connect failed: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return false, fmt.Sprintf("%s responded %d", name, resp.StatusCode)
	}
	return true, fmt.Sprintf("%s responded %d", name, resp.StatusCode)
}

// probeDial probes a raw TCP endpoint.
func probeDial(network, addr string, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return false, network + " dial failed: " + err.Error()
	}
	conn.Close()
	return true, network + " connect ok"
}
