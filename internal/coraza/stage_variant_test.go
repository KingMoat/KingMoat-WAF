package coraza

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	coraza "github.com/corazawaf/coraza/v3"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func scopedDisableRule(name, sites string, cats ...string) config.MatcherRule {
	stages := make([]string, 0, len(cats))
	for _, c := range cats {
		stages = append(stages, config.StageCoraza+":"+c)
	}
	r := config.MatcherRule{
		Name: name, Enabled: true, Action: config.ActionDisable,
		DisableStages: stages,
		Conditions:    []config.MatcherCondition{{Field: config.FieldClientIP, Op: config.OpContains, Value: "10."}},
	}
	if sites != "" {
		r.Sites = []string{sites}
	}
	return r
}

func variantTestCfg(domains string, rules ...config.MatcherRule) *config.Config {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites:      []config.Site{{Domains: []string{domains}, WAF: &config.WAFSettings{}}},
	}
	if len(rules) > 0 {
		cfg.Policy = &config.Policy{Matchers: rules}
	}
	return cfg
}

// fakeGate is a minimal DisableGate driven by a stage-name set (single-site
// tests: the site dimension is ignored).
type fakeGate struct{ disabled map[string]bool }

func (f *fakeGate) Disabled(site, stage string) bool { return f.disabled[stage] }

// TestNewBuildsVariantForScopedDisableRule: one coraza:<category> rule yields
// one variant engine (rule set == union, de-duplicated), compiled through the
// filtered-CRS path (dangling REQUEST-999 updates dropped).
func TestNewBuildsVariantForScopedDisableRule(t *testing.T) {
	cfg := variantTestCfg("variant1.local", scopedDisableRule("r1", "", "sqli"))
	st, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New with scoped disable rule must build: %v", err)
	}
	sw := st.byDomain["variant1.local"]
	if sw == nil {
		t.Fatal("site missing from stage map")
	}
	if len(sw.variants) != 1 {
		t.Fatalf("expected exactly 1 variant (rule set == union), got %d: %v", len(sw.variants), variantKeys(sw))
	}
	if _, ok := sw.variants["sqli"]; !ok {
		t.Fatalf("variant key \"sqli\" missing: %v", variantKeys(sw))
	}
}

// TestNewBuildsUnionVariant: two rules with different category sets get one
// variant each plus the union variant (multi-rule hits always find a match).
func TestNewBuildsUnionVariant(t *testing.T) {
	cfg := variantTestCfg("variant2.local",
		scopedDisableRule("r1", "", "sqli"),
		scopedDisableRule("r2", "", "xss"))
	st, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New must build: %v", err)
	}
	keys := variantKeys(st.byDomain["variant2.local"])
	for _, want := range []string{"sqli", "xss", "sqli,xss"} {
		if _, ok := st.byDomain["variant2.local"].variants[want]; !ok {
			t.Fatalf("variant key %q missing, got %v", want, keys)
		}
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 variants, got %v", keys)
	}
}

// TestNewRejectsTooManyScopedRules: more than MaxScopedCorazaRulesPerSite
// scoped disable rules for one site reject the build (publish error).
func TestNewRejectsTooManyScopedRules(t *testing.T) {
	cats := config.WAFDetectionCategories
	var rules []config.MatcherRule
	for i := 0; i <= config.MaxScopedCorazaRulesPerSite; i++ {
		rules = append(rules, scopedDisableRule("r"+string(rune('a'+i)), "", cats[i]))
	}
	_, err := New(variantTestCfg("variant3.local", rules...), testLogger())
	if err == nil {
		t.Fatal("exceeding the scoped-rule cap must reject the build")
	}
	if !strings.Contains(err.Error(), "max 4") {
		t.Fatalf("error must state the cap: %v", err)
	}
}

// TestNewNoVariantsWithoutScopedRules: no coraza:<category> rules = no
// variant engines (byte-for-byte zero behavioural change).
func TestNewNoVariantsWithoutScopedRules(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"nil policy":    variantTestCfg("variant4.local"),
		"plain disable": variantTestCfg("variant4.local", config.MatcherRule{
			Name: "r", Enabled: true, Action: config.ActionDisable, DisableStages: []string{"botdetect"},
			Conditions: []config.MatcherCondition{{Field: config.FieldClientIP, Op: config.OpContains, Value: "10."}},
		}),
		"disabled rule": variantTestCfg("variant4.local", func() config.MatcherRule {
			r := scopedDisableRule("r", "", "sqli")
			r.Enabled = false
			return r
		}()),
	} {
		st, err := New(cfg, testLogger())
		if err != nil {
			t.Fatalf("%s: New must build: %v", name, err)
		}
		if sw := st.byDomain["variant4.local"]; len(sw.variants) != 0 {
			t.Fatalf("%s: no variants expected, got %v", name, variantKeys(sw))
		}
	}
}

// TestVariantEnginesCompilePerCategory: excluding any single detection
// category as a variant must compile (guards the dangling-update fix across
// all ten categories on the variant path).
func TestVariantEnginesCompilePerCategory(t *testing.T) {
	s := &config.Site{Domains: []string{"variant5.local"}, WAF: &config.WAFSettings{}}
	policy := &config.Policy{}
	for _, cat := range config.WAFDetectionCategories {
		if _, err := buildVariantWAF(s, policy, map[string]bool{cat: true}); err != nil {
			t.Fatalf("variant excluding %q must compile: %v", cat, err)
		}
	}
}

// TestVariantCategoriesStacking pins the disable-only-narrows semantics: the
// variant set is the site's effective category set minus the exclusions —
// site list wins over the global default, and disabling never re-enables a
// category the site or policy already excluded.
func TestVariantCategoriesStacking(t *testing.T) {
	s := &config.Site{Domains: []string{"variant6.local"}, WAF: &config.WAFSettings{}}
	got := variantCategories(s, &config.Policy{}, map[string]bool{"sqli": true})
	if len(got) != len(config.WAFDetectionCategories)-1 || contains(got, "sqli") {
		t.Fatalf("all-but-sqli expected, got %v", got)
	}

	site := &config.Site{Domains: []string{"variant6.local"},
		WAF: &config.WAFSettings{Categories: []string{"sqli", "xss"}}}
	got = variantCategories(site, &config.Policy{}, map[string]bool{"sqli": true})
	if len(got) != 1 || got[0] != "xss" {
		t.Fatalf("site list minus exclusion must be [xss], got %v", got)
	}

	got = variantCategories(s, &config.Policy{WAFCategories: []string{"sqli", "xss"}}, map[string]bool{"xss": true})
	if len(got) != 1 || got[0] != "sqli" {
		t.Fatalf("global default minus exclusion must be [sqli], got %v", got)
	}

	got = variantCategories(site, &config.Policy{}, map[string]bool{"rce": true})
	if len(got) != 2 || !contains(got, "sqli") || !contains(got, "xss") {
		t.Fatalf("excluding a category the site never had must not widen the set, got %v", got)
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TestSiteVariantsDoNotCross: two sites with site-scoped rules keep disjoint
// variant maps (rule site scoping is honored per site).
func TestSiteVariantsDoNotCross(t *testing.T) {
	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{
			{Domains: []string{"variant-a.local"}, WAF: &config.WAFSettings{}},
			{Domains: []string{"variant-b.local"}, WAF: &config.WAFSettings{}},
		},
		Policy: &config.Policy{Matchers: []config.MatcherRule{
			scopedDisableRule("r-a", "variant-a.local", "sqli"),
			scopedDisableRule("r-b", "variant-b.local", "xss"),
		}},
	}
	st, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New must build: %v", err)
	}
	aKeys := variantKeys(st.byDomain["variant-a.local"])
	bKeys := variantKeys(st.byDomain["variant-b.local"])
	if _, ok := st.byDomain["variant-a.local"].variants["sqli"]; !ok {
		t.Fatalf("site A must have the sqli variant, got %v", aKeys)
	}
	if _, ok := st.byDomain["variant-a.local"].variants["xss"]; ok {
		t.Fatalf("site A must not have site B's xss variant, got %v", aKeys)
	}
	if _, ok := st.byDomain["variant-b.local"].variants["xss"]; !ok {
		t.Fatalf("site B must have the xss variant, got %v", bKeys)
	}
	if _, ok := st.byDomain["variant-b.local"].variants["sqli"]; ok {
		t.Fatalf("site B must not have site A's sqli variant, got %v", bKeys)
	}
}

// TestPickVariant covers the switching table: exact key match wins, unknown
// combinations fall back to the main engine with the unmatched set reported,
// and empty disable sets / nil gate / variant-less sites fall back silently.
func TestPickVariant(t *testing.T) {
	main := &siteWAF{waf: nil}
	variant := &siteWAF{waf: nil}
	main.variants = map[string]*siteWAF{"sqli": variant}

	rc := func() *pipeline.RequestContext {
		return &pipeline.RequestContext{Site: pipeline.SiteView{Domain: "s.local"}, Values: map[string]any{}}
	}
	v, why := main.pickVariant(rc(), nil)
	if v != nil || why != "" {
		t.Fatal("nil gate must fall back to the main engine silently")
	}
	v, why = main.pickVariant(rc(), &fakeGate{})
	if v != nil || why != "" {
		t.Fatal("no disabled categories must fall back to the main engine silently")
	}
	v, why = main.pickVariant(rc(), &fakeGate{disabled: map[string]bool{"coraza:xss": true}})
	if v != nil || why != "xss" {
		t.Fatalf("unknown exclusion combination must fall back reporting the set, got v=%v why=%q", v, why)
	}
	v, why = main.pickVariant(rc(), &fakeGate{disabled: map[string]bool{"coraza:sqli": true}})
	if v != variant || why != "" {
		t.Fatal("exact exclusion key must select the variant engine")
	}
	bare := &siteWAF{waf: nil}
	v, why = bare.pickVariant(rc(), &fakeGate{disabled: map[string]bool{"coraza:sqli": true}})
	if v != nil || why != "" {
		t.Fatal("variant-less siteWAF must fall back to the main engine silently")
	}
}

// TestInspectSwitchesToVariantEngine is the end-to-end semantic check: with
// sqli disabled for the site, SQLi payloads pass while XSS payloads are
// still blocked by the same variant engine; without the disable state the
// main engine blocks SQLi again.
func TestInspectSwitchesToVariantEngine(t *testing.T) {
	cfg := variantTestCfg("variant7.local", scopedDisableRule("r1", "", "sqli"))
	st, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New must build: %v", err)
	}
	sqliReq := func() *pipeline.RequestContext {
		r := httptest.NewRequest("GET", "http://variant7.local/products?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", nil)
		return &pipeline.RequestContext{Request: r, Site: pipeline.SiteView{Domain: "variant7.local"}, Values: map[string]any{}}
	}
	xssReq := func() *pipeline.RequestContext {
		r := httptest.NewRequest("POST", "http://variant7.local/comment", strings.NewReader("comment=<script>alert(1)</script>"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return &pipeline.RequestContext{Request: r, Site: pipeline.SiteView{Domain: "variant7.local"}, Values: map[string]any{}, Body: []byte("comment=<script>alert(1)</script>")}
	}

	if v := st.Inspect(context.Background(), sqliReq()); v.Action != pipeline.ActionDeny {
		t.Fatalf("main engine must block SQLi: %+v", v)
	}

	st.gate = &fakeGate{disabled: map[string]bool{"coraza:sqli": true}}
	if v := st.Inspect(context.Background(), sqliReq()); v.Action != pipeline.ActionAllow {
		t.Fatalf("variant engine must let SQLi pass while sqli is disabled: %+v", v)
	}
	if v := st.Inspect(context.Background(), xssReq()); v.Action != pipeline.ActionDeny {
		t.Fatalf("variant engine must still block XSS: %+v", v)
	}
}

func variantKeys(sw *siteWAF) []string {
	keys := make([]string, 0, len(sw.variants))
	for k := range sw.variants {
		keys = append(keys, k)
	}
	return keys
}

// TestNewDegradesWhenVariantBuildFails: a VARIANT compile failure must not
// abort the build (the scope falls back to the main engine, error logged);
// only a MAIN engine failure fails the build. Guards the cold-start
// resilience requirement (B-1): a bad variant must never loop the process
// into exit-on-startup.
func TestNewDegradesWhenVariantBuildFails(t *testing.T) {
	orig := buildVariantWAFFn
	buildVariantWAFFn = func(s *config.Site, p *config.Policy, ex map[string]bool) (coraza.WAF, error) {
		return nil, fmt.Errorf("simulated variant build failure")
	}
	defer func() { buildVariantWAFFn = orig }()

	cfg := variantTestCfg("variant8.local", scopedDisableRule("r1", "", "sqli"))
	st, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("variant build failure must degrade, not abort: %v", err)
	}
	if sw := st.byDomain["variant8.local"]; len(sw.variants) != 0 {
		t.Fatalf("failed variant must be absent, got %v", variantKeys(sw))
	}
}
