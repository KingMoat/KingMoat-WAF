package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fixedStage struct {
	name string
	v    Verdict
}

func (s fixedStage) Name() string                                         { return s.name }
func (s fixedStage) Inspect(_ context.Context, _ *RequestContext) Verdict { return s.v }

type funcStage struct {
	name string
	fn   func(*RequestContext) Verdict
}

func (s funcStage) Name() string                                          { return s.name }
func (s funcStage) Inspect(_ context.Context, rc *RequestContext) Verdict { return s.fn(rc) }

func TestFirstNonAllowVerdictWins(t *testing.T) {
	p := New(
		fixedStage{name: "a", v: Allow()},
		fixedStage{name: "b", v: Deny("b/rule", "stop")},
		fixedStage{name: "c", v: Deny("c/rule", "never reached")},
	)
	rc := &RequestContext{Request: httptest.NewRequest(http.MethodGet, "http://t.local/", nil)}
	v := p.Inspect(context.Background(), rc)
	if v.Rule != "b/rule" {
		t.Fatalf("rule = %q, want b/rule", v.Rule)
	}
	if v.Status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", v.Status)
	}
}

func TestEmptyPipelineAllows(t *testing.T) {
	p := New()
	rc := &RequestContext{Request: httptest.NewRequest(http.MethodGet, "http://t.local/", nil)}
	v := p.Inspect(context.Background(), rc)
	if v.Action != ActionAllow {
		t.Fatalf("action = %v, want allow", v.Action)
	}
}

func TestValuesAutoInitialized(t *testing.T) {
	var got map[string]any
	p := New(funcStage{name: "probe", fn: func(rc *RequestContext) Verdict {
		got = rc.Values
		return Allow()
	}})
	rc := &RequestContext{Request: httptest.NewRequest(http.MethodGet, "http://t.local/", nil)}
	_ = p.Inspect(context.Background(), rc)
	if got == nil {
		t.Fatal("RequestContext.Values was not auto-initialized")
	}
}
