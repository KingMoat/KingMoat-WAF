package config

import (
	"strings"
	"testing"
)

func disableRule(name string, stages ...string) *MatcherRule {
	return &MatcherRule{
		Name: name, Action: ActionDisable, DisableStages: stages,
		Conditions: []MatcherCondition{{Field: FieldClientIP, Op: OpContains, Value: "1.2.3.4"}},
	}
}

// TestMatcherValidateScopedCorazaAccepts covers the legal forms of the
// coraza:<category> disable scope: every detection category is accepted and
// normalized to lower case.
func TestMatcherValidateScopedCorazaAccepts(t *testing.T) {
	for _, cat := range WAFDetectionCategories {
		r := disableRule("scoped", StageCoraza+":"+cat)
		if err := r.Validate(); err != nil {
			t.Fatalf("category %q must be accepted: %v", cat, err)
		}
		if got := r.DisableStages[0]; got != StageCoraza+":"+strings.ToLower(cat) {
			t.Fatalf("category scope must be normalized to lower case, got %q", got)
		}
	}
	r := disableRule("mixed-modules", "botdetect", StageCoraza+":sqli", "ratelimit")
	if err := r.Validate(); err != nil {
		t.Fatalf("scoped coraza combined with plain modules must pass: %v", err)
	}
}

// TestMatcherValidateScopedCorazaRejectsUnknown covers invalid categories and
// malformed scopes: the error must list the ten valid categories.
func TestMatcherValidateScopedCorazaRejectsUnknown(t *testing.T) {
	cases := []struct {
		name  string
		stage string
	}{
		{"unknown category", "coraza:foo"},
		{"empty category", "coraza:"},
		{"whitespace category", "coraza:   "},
		{"typo category", "coraza:sql"},
	}
	for _, tc := range cases {
		err := disableRule("bad", tc.stage).Validate()
		if err == nil {
			t.Fatalf("%s: %q must be rejected", tc.name, tc.stage)
		}
		if !strings.Contains(err.Error(), strings.Join(WAFDetectionCategories, ", ")) {
			t.Fatalf("%s: error must list the valid categories: %v", tc.name, err)
		}
	}
}

// TestMatcherValidateScopedCorazaRejectsMixing: a rule cannot disable the
// whole coraza stage and a scoped category at the same time.
func TestMatcherValidateScopedCorazaRejectsMixing(t *testing.T) {
	err := disableRule("mix", StageCoraza, StageCoraza+":sqli").Validate()
	if err == nil {
		t.Fatalf("mixing coraza with coraza:<category> must be rejected")
	}
	err = disableRule("mix-order", StageCoraza+":sqli", StageCoraza).Validate()
	if err == nil {
		t.Fatalf("mixing order must not matter")
	}
}

// TestMatcherValidatePlainModulesRegression pins the pre-existing pure-module
// behaviour: every disableable stage passes, unknown stages are rejected.
func TestMatcherValidatePlainModulesRegression(t *testing.T) {
	for _, st := range DisableableStages {
		if err := disableRule("plain-"+st, st).Validate(); err != nil {
			t.Fatalf("plain stage %q must pass: %v", st, err)
		}
	}
	err := disableRule("unknown", "acl").Validate()
	if err == nil {
		t.Fatalf("non-disableable stage must be rejected")
	}
	if !strings.Contains(err.Error(), "not disableable") {
		t.Fatalf("unexpected error wording: %v", err)
	}
	if err := disableRule("empty").Validate(); err == nil {
		t.Fatalf("disable without stages must be rejected")
	}
}

// TestScopedCorazaExclusionSetsSiteScoping pins the matcher site-scoping
// semantics reused for variant collection: empty Sites = all sites,
// case-insensitive domain match, non-matching sites excluded.
func TestScopedCorazaExclusionSetsSiteScoping(t *testing.T) {
	p := &Policy{Matchers: []MatcherRule{
		*scopedRule("all", nil, "sqli"),
		*scopedRule("a-site", []string{"A.LOCAL"}, "xss"),
	}}

	sets, err := ScopedCorazaExclusionSets(p, []string{"a.local"})
	if err != nil {
		t.Fatalf("collect must pass: %v", err)
	}
	if len(sets) != 3 { // all-sites sqli + a-site xss + union
		t.Fatalf("site A must see both rules plus union, got %d sets", len(sets))
	}
	keys := map[string]bool{}
	for _, s := range sets {
		keys[ScopedCorazaSetKey(s)] = true
	}
	for _, want := range []string{"sqli", "xss", "sqli,xss"} {
		if !keys[want] {
			t.Fatalf("set %q missing, got %v", want, keys)
		}
	}

	sets, err = ScopedCorazaExclusionSets(p, []string{"b.local"})
	if err != nil {
		t.Fatalf("collect must pass: %v", err)
	}
	if len(sets) != 1 || ScopedCorazaSetKey(sets[0]) != "sqli" {
		t.Fatalf("site B must only see the all-sites rule, got %v", sets)
	}

	p = &Policy{Matchers: []MatcherRule{
		func() MatcherRule { r := *scopedRule("off", nil, "sqli"); r.Enabled = false; return r }(),
	}}
	if sets, _ := ScopedCorazaExclusionSets(p, []string{"a.local"}); len(sets) != 0 {
		t.Fatalf("disabled rules must be skipped, got %v", sets)
	}
}

func scopedRule(name string, sites []string, cats ...string) *MatcherRule {
	stages := make([]string, 0, len(cats))
	for _, c := range cats {
		stages = append(stages, StageCoraza+":"+c)
	}
	r := &MatcherRule{
		Name: name, Enabled: true, Action: ActionDisable, DisableStages: stages,
		Conditions: []MatcherCondition{{Field: FieldClientIP, Op: OpContains, Value: "10."}},
	}
	if sites != nil {
		r.Sites = sites
	}
	return r
}

// TestValidateScopedDisableLimitsPerSite: the per-site cap is enforced at
// config validation (publish entry) so a bad revision never reaches the
// store — previously the check only lived in the engine build and a breach
// landed as "published but engine load failed" + cold-start exit loop.
func TestValidateScopedDisableLimitsPerSite(t *testing.T) {
	cats := WAFDetectionCategories
	var rules []MatcherRule
	for i := 0; i <= MaxScopedCorazaRulesPerSite; i++ {
		rules = append(rules, *scopedRule("r"+string(rune('a'+i)), nil, cats[i]))
	}
	cfg := &Config{
		ListenHTTP: ":0",
		Sites:      []Site{{Domains: []string{"cap.local"}, WAF: &WAFSettings{}, Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:1"}}}}},
		Policy:     &Policy{Matchers: rules},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("per-site scoped-rule cap must be rejected at config validation")
	}
	if !strings.Contains(err.Error(), "max 4") {
		t.Fatalf("error must state the cap: %v", err)
	}
}

// TestValidateScopedDisableLimitsGlobal: the global variant budget (all
// sites' pre-compiled variants summed) is enforced at config validation.
func TestValidateScopedDisableLimitsGlobal(t *testing.T) {
	base := []string{"sqli", "xss", "rce", "lfi"} // 4 rules/site -> 5 variants/site
	build := func(nSites int) *Config {
		var sites []Site
		var rules []MatcherRule
		for i := 0; i < nSites; i++ {
			d := "g" + string(rune('a'+i)) + ".local"
			sites = append(sites, Site{Domains: []string{d}, WAF: &WAFSettings{},
				Upstream: Upstream{Nodes: []UpstreamNode{{Address: "127.0.0.1:1"}}}})
			for j, c := range base {
				rules = append(rules, *scopedRule("r"+string(rune('a'+i))+string(rune('a'+j)), []string{d}, c))
			}
		}
		return &Config{ListenHTTP: ":0", Sites: sites, Policy: &Policy{Matchers: rules}}
	}

	if err := build(12).Validate(); err != nil {
		t.Fatalf("12 sites x 5 variants = 60 must pass the global cap: %v", err)
	}
	err := build(13).Validate() // 65 > 64
	if err == nil {
		t.Fatal("global variant budget must be rejected at config validation")
	}
	if !strings.Contains(err.Error(), "max 64") {
		t.Fatalf("error must state the cap: %v", err)
	}
}
