package pipeline

import (
	"context"
	"testing"
)

type gateStub struct{ disabled map[string]bool }

func (g gateStub) Disabled(site, stage string) bool {
	return g.disabled[site+"/"+stage]
}

type stubStage struct{ name string }

func (s *stubStage) Name() string { return s.name }

func (s *stubStage) Inspect(ctx context.Context, rc *RequestContext) Verdict {
	if s.name == "semantic" {
		return Deny("semantic/x", "hit")
	}
	return Allow()
}

func TestStageGateSkipsDisabledStages(t *testing.T) {
	p := New(&stubStage{name: "semantic"}, &stubStage{name: "coraza"})

	rc := &RequestContext{Site: SiteView{Domain: "a.local"}, Values: map[string]any{}}
	if v := p.Inspect(context.Background(), rc); v.Action != ActionDeny {
		t.Fatal("without gate the semantic stage must still deny")
	}

	p.SetGate(gateStub{disabled: map[string]bool{"a.local/semantic": true}})
	rc.Values = map[string]any{}
	if v := p.Inspect(context.Background(), rc); v.Action != ActionAllow {
		t.Fatal("disabled stage must be skipped for the matching site")
	}

	rc2 := &RequestContext{Site: SiteView{Domain: "b.local"}, Values: map[string]any{}}
	if v := p.Inspect(context.Background(), rc2); v.Action != ActionDeny {
		t.Fatal("other sites must not be affected by the disable entry")
	}
}