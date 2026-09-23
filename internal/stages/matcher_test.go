package stages

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestMatcherDisableScopedCoraza: a disable rule carrying the scoped
// coraza:<category> form registers the scoped key in the disable registry
// (without tripping the whole-stage "coraza" gate) and still bumps the
// rule's hit counter like every other matcher action.
func TestMatcherDisableScopedCoraza(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites:      []config.Site{{Domains: []string{"scoped.local"}}},
		Policy: &config.Policy{Matchers: []config.MatcherRule{{
			Name: "disable-sqli", Enabled: true, Action: config.ActionDisable,
			DisableStages: []string{"coraza:sqli", "botdetect"},
			Conditions:    []config.MatcherCondition{{Field: config.FieldClientIP, Op: config.OpContains, Value: "10."}},
		}}},
	}
	registry := NewStageDisableRegistry()
	m, err := NewMatcher(cfg, registry, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	r := httptest.NewRequest("GET", "http://scoped.local/", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: "scoped.local"},
		Values:  map[string]any{},
	}
	if v := m.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
		t.Fatalf("disable action must allow the request: %+v", v)
	}

	if !registry.Disabled("scoped.local", "coraza:sqli") {
		t.Fatal("scoped coraza:sqli key must be registered for the site")
	}
	if !registry.Disabled("scoped.local", "botdetect") {
		t.Fatal("plain module key must be registered for the site")
	}
	if registry.Disabled("scoped.local", "coraza") {
		t.Fatal("scoped coraza:<category> must NOT disable the whole coraza stage (pipeline gate)")
	}

	// Audit plumbing: the proxy force-audits disable hits (log_enabled has no
	// say); these values carry the rule identity and the disabled scope list.
	if got, _ := rc.Values["matcher_action"].(string); got != config.ActionDisable {
		t.Fatalf("matcher_action must carry disable, got %v", rc.Values["matcher_action"])
	}
	if got, _ := rc.Values["matcher_disable_stages"].(string); got != "coraza:sqli,botdetect" {
		t.Fatalf("matcher_disable_stages must carry the full scope list, got %q", got)
	}

	counts := MatcherHitCounts()
	if counts["disable-sqli"] != 1 {
		t.Fatalf("hit counter must record the disable-rule hit, got %v", counts)
	}

	// Other sites are unaffected (rule without site scoping was hit for this
	// request only; the registry state is per-site anyway).
	if registry.Disabled("other.local", "coraza:sqli") {
		t.Fatal("disable state must stay site-scoped")
	}
}
