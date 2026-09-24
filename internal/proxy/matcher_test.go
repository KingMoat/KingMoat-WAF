package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestMatcherRuntimeBlock proves the MicroEngine conditional rules actually
// intercept live requests through the full handler (runtime evidence for the
// matcher stage that was previously compile-verified only).
func TestMatcherRuntimeBlock(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
		}},
		Policy: &config.Policy{
			Matchers: []config.MatcherRule{
				{
					Name: "block-scanner", Enabled: true, Action: "deny", Logic: "and",
					Conditions: []config.MatcherCondition{
						{Field: "user_agent", Op: "contains", Value: "sqlmap"},
					},
				},
				{
					Name: "block-internal", Enabled: true, Action: "deny", Logic: "or",
					Conditions: []config.MatcherCondition{
						{Field: "path", Op: "prefix", Value: "/admin"},
						{Field: "client_ip", Op: "cidr", Value: "10.0.0.0/8"},
					},
				},
			},
		},
	}

	h := mustReloadable(t, cfg)

	// sqlmap UA → denied by rule 1
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://t.local/x", nil)
	req.Header.Set("User-Agent", "sqlmap/1.5")
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("sqlmap UA not blocked: %d", rec.Code)
	}

	// normal UA → forwarded
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "http://t.local/x", nil))
	if rec2.Code != 200 {
		t.Fatalf("normal UA blocked: %d", rec2.Code)
	}

	// /admin prefix → denied by rule 2
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest("GET", "http://t.local/admin/panel", nil))
	if rec3.Code != 403 {
		t.Fatalf("admin path not blocked: %d", rec3.Code)
	}
}

// TestMatcherRuntimeAllowTrusted proves the allow action skips later stages.
func TestMatcherRuntimeAllowTrusted(t *testing.T) {
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
		Policy: &config.Policy{
			Matchers: []config.MatcherRule{
				{
					Name: "trust-office", Enabled: true, Action: "allow", Logic: "and",
					Conditions: []config.MatcherCondition{
						{Field: "client_ip", Op: "cidr", Value: "192.0.2.0/24"},
					},
				},
			},
		},
	}

	h := mustReloadable(t, cfg)

	// office IP carries SQLi → trusted by matcher, skips semantic → 200
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", `http://t.local/x?id=1%27%20or%20%271%27=%271`, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("trusted client blocked: %d", rec.Code)
	}

	// NOTE: untrusted IP case is verified at stage level in stages tests;
	// httptest always uses the same RemoteAddr so per-IP CIDR testing
	// through the full handler is not feasible here.
}

// TestMatcherDisableHitFollowsLogToggle pins the disable-hit audit contract:
// a disable hit follows the rule's log_enabled toggle like every other
// matcher action — toggle off records nothing, toggle on records exactly one
// monitor event carrying the matcher/<name> identity and the disable reason.
func TestMatcherDisableHitFollowsLogToggle(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	for _, tc := range []struct {
		name       string
		logEnabled bool
		wantEvents int
	}{
		{"toggle-off", false, 0},
		{"toggle-on", true, 1},
	} {
		store := &captureStore{}
		cfg := &config.Config{
			ListenHTTP: ":0",
			Sites: []config.Site{{
				Domains:  []string{"t.local"},
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
				WAF:      wafOff(),
			}},
			Policy: &config.Policy{
				Matchers: []config.MatcherRule{{
					Name: "disable-botdetect", Enabled: true, Action: config.ActionDisable, Logic: "and",
					DisableStages: []string{"botdetect"},
					Conditions:    []config.MatcherCondition{{Field: "path", Op: "prefix", Value: "/x"}},
					LogEnabled:    tc.logEnabled,
				}},
			},
		}
		h, err := NewReloadable(cfg, store, testLogger())
		if err != nil {
			t.Fatalf("%s: NewReloadable: %v", tc.name, err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://t.local/x", nil))
		if rec.Code != 200 {
			t.Fatalf("%s: disable hit must forward, got status %d", tc.name, rec.Code)
		}
		events := store.snapshot()
		if len(events) != tc.wantEvents {
			t.Fatalf("%s: audit events = %d, want %d (got %+v)", tc.name, len(events), tc.wantEvents, events)
		}
		if tc.wantEvents == 1 {
			if events[0].Rule != "matcher/disable-botdetect" {
				t.Fatalf("%s: event rule = %q, want matcher/disable-botdetect", tc.name, events[0].Rule)
			}
			if events[0].Action != "monitor" {
				t.Fatalf("%s: event action = %q, want monitor", tc.name, events[0].Action)
			}
			if !strings.Contains(events[0].Reason, "switched off") {
				t.Fatalf("%s: event reason must carry the disabled scope, got %q", tc.name, events[0].Reason)
			}
		}
	}
}
