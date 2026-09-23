package config

import (
	"strings"
	"testing"
)

// Regression tests for the stored-XSS guard on custom block pages: the
// old five-name event-handler blacklist missed generic handlers, spaced
// attributes and entity-encoded schemes (security review R-3-1).
func TestBlockPageHTMLRejectsBypassVectors(t *testing.T) {
	bp := &BlockPage{}
	vectors := map[string]string{
		"unlisted event handler": `<details open ontoggle=alert(1)>X</details>`,
		"spaced event handler":   `<svg onload =alert(1)>X</svg>`,
		"entity-encoded scheme":  `<a href="java&#115;cript:alert(1)">x</a>`,
		"hex entity scheme":      `<a href="&#106;avascript:alert(1)">x</a>`,
		"data html url":          `<a href="data:text/html,<b>x</b>">x</a>`,
		"vbscript scheme":        `<a href="vbscript:msgbox(1)">x</a>`,
		"script tag":             `<script>alert(1)</script>`,
	}
	for name, htmlStr := range vectors {
		bp.HTML = htmlStr
		if err := bp.Validate(); err == nil {
			t.Fatalf("%s: malicious html accepted: %q", name, htmlStr)
		}
	}
}

func TestBlockPageHTMLAllowsBenignMarkup(t *testing.T) {
	bp := &BlockPage{HTML: `<p style="color:#c00">请求被拦截</p><div class="tip">data: 已记录本次事件</div>`}
	if err := bp.Validate(); err != nil {
		t.Fatalf("benign html rejected: %v", err)
	}
}


// TestPolicyRejectsDuplicateMatcherNames: matcher rules are located by name
// (console toggle/save/delete and audit tags matcher/<name>), so duplicate
// names must be rejected at the config validation layer (review rc2-N1).
func TestPolicyRejectsDuplicateMatcherNames(t *testing.T) {
	mk := func(name string) MatcherRule {
		return MatcherRule{Name: name, Action: "deny",
			Conditions: []MatcherCondition{{Field: "client_ip", Op: "contains", Value: "1.2.3.4"}}}
	}

	ok := &Policy{Matchers: []MatcherRule{mk("rule-a"), mk("rule-b")}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("distinct names must pass: %v", err)
	}

	dup := &Policy{Matchers: []MatcherRule{mk("same"), mk("other"), mk("same")}}
	err := dup.Validate()
	if err == nil {
		t.Fatalf("duplicate matcher names must be rejected")
	}
	if !strings.Contains(err.Error(), `duplicate rule name "same"`) {
		t.Fatalf("error must name the offending rule: %v", err)
	}
}
