package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// TestMetricsEndpointToggle covers the optional /metrics endpoint: disabled
// by default (404), hot-enabled via publish (200, exposition text), and
// never leaking metric data while disabled.
func TestMetricsEndpointToggle(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/metrics-test.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()

	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	audit.Write(&logstore.Event{Action: "blocked", Site: "a.local"})
	if err := audit.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, Version: "metrics-test"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled /metrics status = %d, want 404", resp.StatusCode)
	}
	if strings.Contains(string(body), "kingmoat_requests_total") {
		t.Fatalf("disabled /metrics leaked metric data")
	}

	newCfg := seedCfg()
	newCfg.Metrics = &config.MetricsSettings{Enabled: true}
	pubBody, _ := json.Marshal(map[string]any{"note": "enable metrics", "config": newCfg})
	pr, err := http.Post(ts.URL+"/api/config/publish", "application/json", bytes.NewReader(pubBody))
	if err != nil {
		t.Fatal(err)
	}
	if pr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pr.Body)
		pr.Body.Close()
		t.Fatalf("publish status = %d: %s", pr.StatusCode, string(b))
	}
	pr.Body.Close()

	resp2, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("enabled /metrics status = %d, want 200", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	out, _ := io.ReadAll(resp2.Body)
	for _, want := range []string{"kingmoat_requests_total", "kingmoat_build_info", "# TYPE kingmoat_audit_queue_depth gauge"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("metrics body missing %q", want)
		}
	}
}