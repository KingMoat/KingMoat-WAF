package proxy

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// captureStore records audit events in memory for assertions.
type captureStore struct {
	mu     sync.Mutex
	events []logstore.Event
}

func (s *captureStore) Write(ev *logstore.Event) {
	if ev == nil {
		return
	}
	s.mu.Lock()
	s.events = append(s.events, *ev)
	s.mu.Unlock()
}

func (s *captureStore) Close() error { return nil }

func (s *captureStore) snapshot() []logstore.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]logstore.Event(nil), s.events...)
}

// TestTrustedFlow pins the trustedFlow decision contract: nil context, a
// missing flag, a non-bool flag and an explicit false are never trusted;
// only a strict bool true is.
func TestTrustedFlow(t *testing.T) {
	if trustedFlow(nil) {
		t.Fatal("nil request context must not be trusted")
	}
	bare := &pipeline.RequestContext{}
	if trustedFlow(bare) {
		t.Fatal("missing flag must not be trusted")
	}
	noValues := &pipeline.RequestContext{Values: map[string]any{}}
	if trustedFlow(noValues) {
		t.Fatal("empty values must not be trusted")
	}
	nonBool := &pipeline.RequestContext{Values: map[string]any{"trusted": "yes"}}
	if trustedFlow(nonBool) {
		t.Fatal("non-bool flag must not be trusted (strict bool assertion)")
	}
	falsy := &pipeline.RequestContext{Values: map[string]any{"trusted": false}}
	if trustedFlow(falsy) {
		t.Fatal("explicit false must not be trusted")
	}
	truthy := &pipeline.RequestContext{Values: map[string]any{"trusted": true}}
	if !trustedFlow(truthy) {
		t.Fatal("bool true must be trusted")
	}
}

// markStage marks the request trusted (like the ACL whitelist does) and
// returns the given verdict — a synthetic stand-in for a stage that would
// emit an audit event on a trusted flow.
type markStage struct {
	name    string
	trusted bool
	action  pipeline.Action
	slider  bool // challenge → take the slider branch instead of the bot one
}

func (s markStage) Name() string { return s.name }
func (s markStage) Inspect(_ context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if s.trusted {
		rc.Values["trusted"] = true
	}
	if s.slider {
		rc.Values["challenge_kind"] = "slider"
		rc.Values["challenge_html"] = "<html>slider</html>"
	}
	switch s.action {
	case pipeline.ActionDeny:
		return pipeline.Deny("test/leak", "synthetic deny")
	case pipeline.ActionChallenge:
		return pipeline.Verdict{Action: pipeline.ActionChallenge, Rule: "test/leak", Reason: "synthetic challenge"}
	default:
		return pipeline.Allow()
	}
}

	// TestTrustedFlowSkipsPipelineAuditEvents drives all five pipeline-derived
// audit write points (blocked / monitor deny / slider challenge / bot
// challenge / monitor challenge) through the full handler: a trusted flow
// must record nothing, while the identical untrusted flow still does —
// proving the write points themselves keep working.
func TestTrustedFlowSkipsPipelineAuditEvents(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	cases := []struct {
		name       string
		action     pipeline.Action
		slider     bool
		domain     string // example.com = intercept mode, monitor.example.com = monitor mode
		wantStatus int
	}{
		{"blocked-intercept", pipeline.ActionDeny, false, "example.com", 403},
		{"monitor-deny", pipeline.ActionDeny, false, "monitor.example.com", 200},
		{"slider-challenge", pipeline.ActionChallenge, true, "example.com", 200},
		{"bot-challenge", pipeline.ActionChallenge, false, "example.com", 200},
		{"monitor-challenge", pipeline.ActionChallenge, false, "monitor.example.com", 200},
	}

	for _, tc := range cases {
		for _, trusted := range []bool{false, true} {
			store := &captureStore{}
			cfg := proxyConfig(trimScheme(up.URL))
			h, err := New(cfg, pipeline.New(markStage{name: "synthetic", trusted: trusted, action: tc.action, slider: tc.slider}), store, testLogger())
			if err != nil {
				t.Fatalf("%s: New: %v", tc.name, err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "http://"+tc.domain+"/", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s trusted=%v: status = %d, want %d", tc.name, trusted, rec.Code, tc.wantStatus)
			}
			events := store.snapshot()
			if trusted && len(events) != 0 {
				t.Fatalf("%s: trusted flow must not write audit events, got %+v", tc.name, events)
			}
			if !trusted && len(events) != 1 {
				t.Fatalf("%s: untrusted flow must still write one audit event, got %d", tc.name, len(events))
			}
		}
	}
}

// TestACLWhitelistWritesNoAttackAudit is the end-to-end regression for the
// operator scenario: an IP on the ACL whitelist that fires a CRS-detected
// attack must be forwarded (trusted skips the WAF) and must produce NO
// audit event, while the same attack from a non-whitelisted client still
// blocks and records.
func TestACLWhitelistWritesNoAttackAudit(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	sqlTarget := `http://t.local/x?id=1%27%20or%20%271%27=%271`

	// Whitelisted client (httptest's default RemoteAddr 192.0.2.1):
	// trusted → no detection, no audit events.
	store := &captureStore{}
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
			Security: &config.SecuritySettings{
				ACL: &config.ACLSettings{Whitelist: []string{"192.0.2.1"}},
			},
		}},
	}
	h, err := NewReloadable(cfg, store, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqlTarget, nil))
	if rec.Code != 200 {
		t.Fatalf("whitelisted client blocked: %d", rec.Code)
	}
	if events := store.snapshot(); len(events) != 0 {
		t.Fatalf("whitelisted client must not produce attack logs, got %+v", events)
	}

	// Control: the same attack without the whitelist blocks and records.
	store2 := &captureStore{}
	cfgNoWL := *cfg
	cfgNoWL.Sites = []config.Site{{
		Domains:  []string{"t.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
	}}
	h2, err := NewReloadable(&cfgNoWL, store2, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable control: %v", err)
	}
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest("GET", sqlTarget, nil))
	if rec2.Code != 403 {
		t.Fatalf("control attack not blocked: %d", rec2.Code)
	}
	events := store2.snapshot()
	if len(events) != 1 || events[0].Action != "blocked" {
		t.Fatalf("control must record exactly one blocked event, got %+v", events)
	}
}
