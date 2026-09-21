package coraza

import (
	"testing"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// TestBlocksBacktickCommandSubstitution pins the built-in hardening rule:
// paired backticks in query parameters must be denied like the $(...) shell
// syntax CRS already covers (anti-evasion, see CHANGELOG v0.6.2).
func TestBlocksBacktickCommandSubstitution(t *testing.T) {
	v := runReq(t, "test.local", "GET", "http://test.local/ping?x=%60id%60", nil, "")
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("backtick command substitution not denied: %+v", v)
	}
}

// TestAllowsBackticksOutsideQuery keeps the rule scoped to ARGS_GET: body
// content (markdown code spans etc.) must not trigger the hardening rule.
func TestAllowsBackticksInBody(t *testing.T) {
	v := runReq(t, "test.local", "POST", "http://test.local/comment",
		[]byte("body=use `%60code%60` spans in markdown"), "application/x-www-form-urlencoded")
	if v.Action == pipeline.ActionDeny && v.Rule == "coraza/rule-1000001" {
		t.Fatalf("built-in rule leaked into request body: %+v", v)
	}
}
