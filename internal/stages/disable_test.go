package stages

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func TestMatcherDisableActionRegistersModules(t *testing.T) {
	reg := NewStageDisableRegistry()
	cfg := &config.Config{Policy: &config.Policy{Matchers: []config.MatcherRule{{
		Name:          "off-modules",
		Enabled:       true,
		Sites:         []string{"a.local"},
		Action:        config.ActionDisable,
		DisableStages: []string{"coraza", "semantic"},
		Conditions:    []config.MatcherCondition{{Field: config.FieldPath, Op: config.OpPrefix, Value: "/api/"}},
	}}}}
	m, err := NewMatcher(cfg, reg, nil)
	if err != nil {
		t.Fatal(err)
	}

	rc := &pipeline.RequestContext{
		Request: httptest.NewRequest("GET", "/api/users", nil),
		Site:    pipeline.SiteView{Domain: "a.local"},
		Values:  map[string]any{},
	}
	v := m.Inspect(context.Background(), rc)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("disable action must allow the current request, got %v", v.Action)
	}
	if !reg.Disabled("a.local", "coraza") || !reg.Disabled("a.local", "semantic") {
		t.Fatal("listed modules must be registered as disabled")
	}
	if reg.Disabled("a.local", "ratelimit") {
		t.Fatal("unlisted module must stay enabled")
	}
	if reg.Disabled("b.local", "coraza") {
		t.Fatal("other sites must not be affected")
	}

	// Non-matching path must not register anything.
	rc2 := &pipeline.RequestContext{
		Request: httptest.NewRequest("GET", "/other", nil),
		Site:    pipeline.SiteView{Domain: "a.local"},
		Values:  map[string]any{},
	}
	_ = m.Inspect(context.Background(), rc2)
}

func TestMatcherDisableActionValidation(t *testing.T) {
	rule := config.MatcherRule{Name: "bad", Enabled: true, Action: config.ActionDisable,
		Conditions: []config.MatcherCondition{{Field: config.FieldPath, Op: config.OpPrefix, Value: "/"}}}
	if err := rule.Validate(); err == nil {
		t.Fatal("disable without disable_stages must fail validation")
	}
	rule.DisableStages = []string{"acl"}
	if err := rule.Validate(); err == nil {
		t.Fatal("access-control stage must not be disableable")
	}
	rule.DisableStages = []string{"coraza"}
	if err := rule.Validate(); err != nil {
		t.Fatalf("valid disable rule rejected: %v", err)
	}
}