package stages

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
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

// TestDisableRegistrySnapshot pins the read-only view consumed by the
// /api/policy/disable-state endpoint: per-site keys, sorted entries, and a
// copy the caller cannot mutate the registry through.
func TestDisableRegistrySnapshot(t *testing.T) {
	reg := NewStageDisableRegistry()
	reg.Disable("a.local", "coraza:sqli")
	reg.Disable("a.local", "botdetect")
	reg.Disable("b.local", "ratelimit")

	snap := reg.Snapshot()
	if got := strings.Join(snap["a.local"], ","); got != "botdetect,coraza:sqli" {
		t.Fatalf("site A snapshot must be sorted, got %q", got)
	}
	if got := strings.Join(snap["b.local"], ","); got != "ratelimit" {
		t.Fatalf("site B snapshot mismatch, got %q", got)
	}

	snap["a.local"][0] = "MUTATED"
	snap2 := reg.Snapshot()
	if strings.Join(snap2["a.local"], ",") != "botdetect,coraza:sqli" {
		t.Fatal("snapshot must be a copy: mutating it must not affect the registry")
	}
}

// recordingStage is a minimal pipeline.Stage counting Inspect calls.
type recordingStage struct{ name string; calls int }

func (r *recordingStage) Name() string { return r.name }
func (r *recordingStage) Inspect(_ context.Context, _ *pipeline.RequestContext) pipeline.Verdict {
	r.calls++
	return pipeline.Allow()
}

// TestPipelineGateScopedVsWholeStage locks the gate responsibility boundary:
// a scoped coraza:<category> disable must NOT make the pipeline skip the
// whole coraza stage (variant switching happens inside the stage), while a
// plain coraza disable does skip it.
func TestPipelineGateScopedVsWholeStage(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites:      []config.Site{{Domains: []string{"gate.local"}}},
		Policy: &config.Policy{Matchers: []config.MatcherRule{{
			Name: "scoped-off", Enabled: true, Action: config.ActionDisable,
			DisableStages: []string{"coraza:sqli"},
			Conditions:    []config.MatcherCondition{{Field: config.FieldClientIP, Op: config.OpContains, Value: "10."}},
		}}},
	}
	reg := NewStageDisableRegistry()
	m, err := NewMatcher(cfg, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	corazaStage := &recordingStage{name: "coraza"}
	p := pipeline.New(m, corazaStage)
	p.SetGate(reg)

	r := httptest.NewRequest("GET", "http://gate.local/", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	p.Inspect(context.Background(), &pipeline.RequestContext{
		Request: r, Site: pipeline.SiteView{Domain: "gate.local"}, Values: map[string]any{},
	})
	if corazaStage.calls != 1 {
		t.Fatalf("scoped coraza:<category> must not skip the coraza stage in the pipeline, calls=%d", corazaStage.calls)
	}

	reg2 := NewStageDisableRegistry()
	reg2.Disable("gate.local", "coraza")
	m2, err := NewMatcher(cfg, reg2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	corazaStage2 := &recordingStage{name: "coraza"}
	p2 := pipeline.New(m2, corazaStage2)
	p2.SetGate(reg2)
	p2.Inspect(context.Background(), &pipeline.RequestContext{
		Request: r, Site: pipeline.SiteView{Domain: "gate.local"}, Values: map[string]any{},
	})
	if corazaStage2.calls != 0 {
		t.Fatalf("plain coraza disable must skip the coraza stage in the pipeline, calls=%d", corazaStage2.calls)
	}
}