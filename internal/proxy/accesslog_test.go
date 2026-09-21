package proxy

import (
	"sync"
	"testing"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/config"
)

// memSink collects access entries for assertions.
type memSink struct {
	mu      sync.Mutex
	entries []*accesslog.Entry
}

// compile-time interface check
var _ accesslog.Sink = (*memSink)(nil)

func (m *memSink) Close() error { return nil }

func (m *memSink) Write(e *accesslog.Entry) {
	m.mu.Lock()
	m.entries = append(m.entries, e)
	m.mu.Unlock()
}

func (m *memSink) snapshot() []*accesslog.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*accesslog.Entry(nil), m.entries...)
}

func TestAccessLogEmitsForwardedAndBlocked(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			WAF:      wafOff(),
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}

	sink := &memSink{}
	h, err := NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	h.SetAccessSink(sink)

	// forwarded: status + bytes captured through the recorder
	if rec := do(t, h, "GET", "http://t.local/a?x=1"); rec.Code != 200 {
		t.Fatalf("forward failed: %d", rec.Code)
	}
	// blocked: deny page status captured
	if rec := do(t, h, "GET", `http://t.local/p?id=1%27%20or%20%271%27=%271`); rec.Code != 403 {
		t.Fatalf("expected block, got %d", rec.Code)
	}

	entries := sink.snapshot()
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	fwd, blocked := entries[0], entries[1]
	if fwd.Outcome != "forwarded" || fwd.Status != 200 || fwd.Bytes == 0 || fwd.LatencyMS < 0 {
		t.Fatalf("forwarded entry wrong: %+v", fwd)
	}
	if fwd.Site != "t.local" || fwd.Path != "/a" || fwd.Query != "x=1" {
		t.Fatalf("forwarded fields wrong: %+v", fwd)
	}
	if blocked.Outcome != "blocked" || blocked.Status != 403 || blocked.Rule != "semantic/sqli" {
		t.Fatalf("blocked entry wrong: %+v", blocked)
	}
}

func TestAccessLogDisabledByDefault(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
		}},
	}
	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	do(t, h, "GET", "http://t.local/") // must not panic with a nil sink
}
