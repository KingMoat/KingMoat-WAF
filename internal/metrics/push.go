package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// StartPusher periodically POSTs the Prometheus text exposition to a remote
// receiver (e.g. a Pushgateway or any metrics collector endpoint). It runs
// until ctx is cancelled. Assembled at boot from the config snapshot —
// changing the target requires a restart (mirrors the archive job).
func StartPusher(ctx context.Context, url string, interval time.Duration, bearer, version string, logger *slog.Logger) {
	if url == "" || interval <= 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	client := &http.Client{Timeout: 10 * time.Second}
	body := PrometheusText(version)
	failures := 0
	logger.Info("metrics push target configured", "url", strings.Split(url, "?")[0], "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			logger.Warn("metrics push: bad url", "err", err)
			return
		}
		req.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			failures++
			logger.Warn("metrics push failed", "err", err, "failures", failures)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			failures++
			logger.Warn("metrics push rejected", "status", resp.StatusCode, "failures", failures)
			continue
		}
		if failures > 0 {
			logger.Info("metrics push recovered", "failures", failures)
			failures = 0
		}
	}
}
