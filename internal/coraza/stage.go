// Package coraza hosts the KingMoat signature-detection stage built on
// Coraza (ModSecurity SecLang compatible) with the OWASP CRS 4.x embedded.
// One coraza.WAF instance is built per site; a single Stage dispatches
// by site domain (see docs/ARCHITECTURE.md §3.3).
package coraza

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// DisableGate lets the coraza stage observe the per-site module disable
// state (matcher "disable" rules) without importing the stages package: the
// proxy wires the live disable registry in via SetDisableGate. Only the
// scoped "coraza:<category>" keys are read here; disabling the plain
// "coraza" stage is handled by the pipeline gate, which skips the stage.
type DisableGate interface {
	Disabled(site, stage string) bool
}

// Stage implements pipeline.Stage with per-site Coraza WAF instances.
type Stage struct {
	byDomain map[string]*siteWAF
	gate     DisableGate
	logger   *slog.Logger
}

type siteWAF struct {
	waf coraza.WAF
	// variants pre-compiles category-trimmed engines, keyed by the excluded
	// category set in detection-category order ("sqli,xss"). Nil/empty when
	// the site has no coraza:<category> disable rules: the main engine
	// handles everything.
	variants map[string]*siteWAF
}

// SetDisableGate attaches the disable-state source used to switch to
// category-trimmed variant engines at request time. Optional: without a
// gate the stage always uses the main engine.
func (st *Stage) SetDisableGate(g DisableGate) { st.gate = g }

// buildVariantWAFFn is a package-level indirection so tests can simulate a
// variant-compile failure (cold-start degradation path).
var buildVariantWAFFn = buildVariantWAF

// New builds the multi-site Coraza stage. Sites with waf.enabled=false are
// skipped; every enabled site gets its own WAF instance compiled from the
// embedded CRS plus optional custom SecLang rules. Sites referenced by
// coraza:<category> disable rules additionally get variant engines
// pre-compiled for every rule's category set plus the union of all sets.
// A MAIN engine compile failure aborts the whole build (fail-static reload,
// cold start exit); a VARIANT compile failure only degrades that scope — the
// variant is skipped with an error log, requests for it fall back to the
// main engine and the process keeps running. Variant sets identical to the
// site's effective category set alias the main engine (no extra compile).
func New(cfg *config.Config, logger *slog.Logger) (*Stage, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var globalCats []string
	if cfg.Policy != nil {
		globalCats = cfg.Policy.WAFCategories
	}
	byDomain := make(map[string]*siteWAF)
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if !s.WAF.IsEnabled() {
			continue
		}
		waf, err := buildWAF(s, cfg.Policy)
		if err != nil {
			return nil, fmt.Errorf("coraza: site %d (%s): %w", i, strings.Join(s.Domains, ","), err)
		}
		sw := &siteWAF{waf: waf}
		exclusionSets, err := siteCategoryExclusions(cfg.Policy, s.Domains)
		if err != nil {
			return nil, fmt.Errorf("coraza: site %d (%s): %w", i, strings.Join(s.Domains, ","), err)
		}
		if len(exclusionSets) > 0 {
			variants := make(map[string]*siteWAF, len(exclusionSets))
			base := enabledCategorySet(s.WAF, globalCats)
			for _, ex := range exclusionSets {
				key := config.ScopedCorazaSetKey(ex)
				if cats := variantCategories(s, cfg.Policy, ex); len(cats) == len(base) {
					// The disabled categories were never in the effective
					// set: the main engine already IS this variant. Alias it
					// so runtime lookups hit the exact key without a
					// misleading fallback warning.
					variants[key] = sw
					continue
				}
				vw, err := buildVariantWAFFn(s, cfg.Policy, ex)
				if err != nil {
					logger.Error("coraza: variant engine build failed, scope falls back to the main engine",
						"site", strings.Join(s.Domains, ","), "excluded", key, "err", err)
					continue
				}
				variants[key] = &siteWAF{waf: vw}
			}
			sw.variants = variants
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = sw
		}
	}
	return &Stage{byDomain: byDomain, logger: logger}, nil
}

// buildWAF compiles one site's WAF: embedded CRS 4.x + optional custom rules.
// The site body limit is mirrored into Coraza's request body limits so the
// proxy buffer and the engine never disagree.
func buildWAF(s *config.Site, policy *config.Policy) (coraza.WAF, error) {
	// Build the CRS include list: always-on infrastructure files + per-site
	// category files. When s.WAF.Categories is nil, the global default
	// (policy.WAFCategories) applies when configured, otherwise all
	// categories are loaded (backward compat). A non-nil site list takes
	// precedence, reducing both rule count and per-request evaluation cost.
	var globalCats []string
	if policy != nil {
		globalCats = policy.WAFCategories
	}
	crsIncludes := buildCRSIncludes(s.WAF, globalCats)

	directives := strings.Join([]string{
		"Include @coraza.conf-recommended",
		"",
		"# --- KingMoat CRS setup (defaults derived from crs-setup.conf.example;",
		"#     the official example ships all thresholds commented out) ---",
		`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=`+strconv.Itoa(policy.InboundOrDefault())+`"`,
		`SecAction "id:900002,phase:1,pass,t:none,nolog,setvar:tx.outbound_anomaly_score_threshold=`+strconv.Itoa(policy.OutboundOrDefault())+`"`,
		`SecAction "id:900003,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=1"`,
		`SecAction "id:900004,phase:1,pass,t:none,nolog,setvar:tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE"`,
		`SecAction "id:900005,phase:1,pass,t:none,nolog,setvar:tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain|"`,
		`SecAction "id:900006,phase:1,pass,t:none,nolog,setvar:tx.allowed_http_versions=HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3"`,
		`SecAction "id:900007,phase:1,pass,t:none,nolog,setvar:tx.restricted_extensions=.asa/ .asax/ .ascx/ .axd/ .asx/ .asmx/ .config/ .cs/ .csproj/ .ccb/ .jsp/ .jspa/ .ldb/ .ldf/ .mdb/ .mdf/ .bak/ .java/ .class/ .ini/"`,
		`SecAction "id:900008,phase:1,pass,t:none,nolog,setvar:tx.restricted_headers=/proxy-connection/ /content-length/ /transfer-encoding/"`,
		`SecAction "id:900009,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0',setvar:tx.crs_setup_version=4250"`,
		"",
		crsIncludes,
		"# KingMoat: the recommended conf ships DetectionOnly; enforce blocking.",
		"SecRuleEngine On",
		"",
		"# --- KingMoat built-in hardening (always on) ---",
		"# Command substitution via paired backticks in query parameters: CRS",
		"# 932xxx covers shell syntax like $(...) but the bare backtick variant",
		"# (`id`) is not matched at paranoia level 1. Always deny, query only",
		"# (ARGS_GET) so markdown-style backticks in request bodies stay clean.",
		`SecRule ARGS_GET "@rx \x60[^\x60\n]{0,512}\x60" "id:1000001,phase:2,deny,log,t:none,msg:'KingMoat built-in: command substitution via backticks'"`,
	}, "\n")
	if s.WAF != nil && s.WAF.CustomRulesFile != "" {
		b, err := os.ReadFile(s.WAF.CustomRulesFile)
		if err != nil {
			return nil, fmt.Errorf("read custom rules: %w", err)
		}
		directives += "\n# --- site custom rules ---\n" + string(b)
	}
	if policy != nil && strings.TrimSpace(policy.CustomRules) != "" {
		directives += "\n# --- global custom rules (strategy console) ---\n" + policy.CustomRules
	}
	// False-positive exceptions: numeric rule IDs are removed per-site
	// ("一键加白" for CRS rules). Stage-level rules are handled dynamically
	// by the exceptions stage.
	if policy != nil {
		for _, e := range policy.Exceptions {
			if e.RuleID == "" || !isNumericRuleID(e.RuleID) {
				continue
			}
			if e.Site != "" && !siteMatches(s.Domains, e.Site) {
				continue
			}
			directives += "\nSecRuleRemoveById " + e.RuleID
		}
	}
	// CRS's always-on REQUEST-999 file carries SecRuleUpdateTargetById
	// directives referencing detection rules; excluding a category removes
	// those rules, so dangling update directives must be dropped or the
	// engine compile fails (hot reload would fail-static).
	directives = materializeCRSIncludes(directives, s.WAF, globalCats)
	limit := int(s.WAF.BodyLimit())
	conf := coraza.NewWAFConfig().
		WithRootFS(slashFS{inner: coreruleset.FS}).
		WithDirectives(directives).
		WithRequestBodyAccess().
		WithRequestBodyLimit(limit).
		WithRequestBodyInMemoryLimit(limit)
	return coraza.NewWAF(conf)
}

// Name implements pipeline.Stage.
func (st *Stage) Name() string { return "coraza" }

// Inspect implements pipeline.Stage: header phase first, then body phase
// when a buffered body is present (docs/ARCHITECTURE.md §3.1 steps ③⑤).
// Trusted requests (ACL whitelist) skip detection entirely.
func (st *Stage) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true {
		return pipeline.Allow()
	}
	sw := st.byDomain[strings.ToLower(rc.Site.Domain)]
	if sw == nil {
		return pipeline.Allow()
	}
	if v, why := sw.pickVariant(rc, st.gate); v != nil {
		sw = v
	} else if why != "" {
		// Disabled categories without a pre-compiled variant: a publish-time
		// set (or a degraded build) does not match the live disable state.
		st.logger.Warn("coraza: no pre-compiled variant for the disabled category set, using main engine",
			"site", rc.Site.Domain, "excluded", why)
	}
	return sw.inspect(rc, st.logger)
}

// pickVariant selects the variant engine matching the site's currently
// disabled CRS categories (set by matcher coraza:<category> rules via the
// disable registry). The disable state lives in a registry shared with the
// matcher stage, which runs earlier in the pipeline: a rule hit on the SAME
// request switches this request to the variant immediately, and the state
// persists site-wide until republish. The exclusion-set key must have been
// pre-compiled at publish time; unknown combinations fall back to the main
// engine (defensive). Returns nil (main engine) when there is no gate, no
// variants or no disabled category; the second return carries the unmatched
// exclusion set ("" when no fallback warning is warranted).
func (w *siteWAF) pickVariant(rc *pipeline.RequestContext, gate DisableGate) (*siteWAF, string) {
	if len(w.variants) == 0 || gate == nil {
		return nil, ""
	}
	var excluded []string
	for _, cat := range config.WAFDetectionCategories {
		if gate.Disabled(rc.Site.Domain, config.StageCoraza+":"+cat) {
			excluded = append(excluded, cat)
		}
	}
	if len(excluded) == 0 {
		return nil, ""
	}
	if v, ok := w.variants[strings.Join(excluded, ",")]; ok {
		return v, ""
	}
	return nil, strings.Join(excluded, ",")
}

func (w *siteWAF) inspect(rc *pipeline.RequestContext, logger *slog.Logger) pipeline.Verdict {
	r := rc.Request
	tx := w.waf.NewTransaction()
	defer tx.Close()

	clientHost, clientPort := addrParts(r.RemoteAddr)
	// Real-IP resolution (config.Site.RealIP): when the proxy resolved the
	// true client address, CRS REMOTE_ADDR sees it instead of the LB/CDN peer.
	if ip := pipeline.ClientIPFromContext(r.Context()); ip != nil {
		clientHost = ip.String()
	}
	serverHost, serverPort := addrParts(r.Host)
	tx.ProcessConnection(clientHost, clientPort, serverHost, serverPort)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	// Coraza does not parse the query string into ARGS_GET automatically;
	// inject it so CRS rules (942 SQLi, 930 LFI, ...) inspect query params.
	for k, vv := range r.URL.Query() {
		for _, v := range vv {
			tx.AddGetRequestArgument(k, v)
		}
	}
	tx.AddRequestHeader("Host", r.Host) // Go strips Host from the header map
	if r.ContentLength >= 0 && r.Header.Get("Content-Length") == "" {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}

	var it *types.Interruption
	if it = tx.ProcessRequestHeaders(); it != nil {
		tx.ProcessLogging()
		return verdictFrom(it, tx.MatchedRules())
	}

	if len(rc.Body) > 0 {
		var err error
		if it, _, err = tx.WriteRequestBody(rc.Body); err != nil {
			logger.Error("coraza: write request body failed",
				"err", err, "trace", rc.Values["trace_id"])
		}
		if it != nil {
			tx.ProcessLogging()
			return verdictFrom(it, tx.MatchedRules())
		}
	}

	// Phase 2 rules must run even for bodiless GETs (SQLi/LFI in ARGS_GET).
	if it, err := tx.ProcessRequestBody(); err != nil {
		logger.Error("coraza: process request body failed",
			"err", err, "trace", rc.Values["trace_id"])
	} else if it != nil {
		tx.ProcessLogging()
		return verdictFrom(it, tx.MatchedRules())
	}

	tx.ProcessLogging()
	return pipeline.Allow()
}

// verdictFrom converts a Coraza interruption into a pipeline Verdict.
// Internal rule messages are kept in Reason (logs/audit only, never the
// client-facing block page).
func verdictFrom(it *types.Interruption, matched []types.MatchedRule) pipeline.Verdict {
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	reason := it.Data
	var ids []string
	for _, mr := range matched {
		if msg := mr.Message(); msg != "" {
			ids = append(ids, fmt.Sprintf("%d %q", mr.Rule().ID(), msg))
		}
	}
	if len(ids) > 0 {
		reason = strings.Join(ids, "; ")
	}
	if reason == "" {
		reason = "blocked by WAF rule"
	}
	// Under the CRS anomaly-scoring model the interruption fires on the
	// threshold rules (949110 inbound / 959xxx outbound), which carry no
	// attack semantics of their own. Attribute the verdict to the first
	// concrete matched rule outside the scoring families — the one that
	// accumulated the score — so audit entries classify as the real attack
	// type (e.g. 942100 → SQL注入) instead of “综合评分”. Reason keeps
	// listing every matched rule.
	ruleID := it.RuleID
	if isScoringRuleID(ruleID) {
		if primary := primaryAttackRuleID(matched); primary > 0 {
			ruleID = primary
		}
	}
	return pipeline.Verdict{
		Action: pipeline.ActionDeny,
		Status: status,
		Rule:   fmt.Sprintf("coraza/rule-%d", ruleID),
		Reason: reason,
	}
}

// isScoringRuleID reports whether the rule is a CRS anomaly-scoring
// threshold rule: 949110 (inbound) and the 959xxx (outbound) family.
func isScoringRuleID(id int) bool {
	return id == 949110 || (id >= 959000 && id <= 959999)
}

// primaryAttackRuleID picks the matched rule that best represents the attack
// behind a scoring-rule interruption. Preference order:
//  1. the first rule tagged with a CRS "attack-*" tag — the concrete
//     detection rule that accumulated the anomaly score (e.g. 942100 → SQLi);
//  2. the first rule inside the CRS detection range (920xxx-959xxx) outside
//     the scoring families (949xxx/959xxx);
//  3. none (0) — the caller keeps the interruption's own rule id.
//
// Setup/init rules (900xxx-901xxx, e.g. 901340 "Enabling body inspection")
// and protocol-plumbing rules carry no attack-* tag and are skipped.
func primaryAttackRuleID(matched []types.MatchedRule) int {
	fallback := 0
	for _, mr := range matched {
		id := mr.Rule().ID()
		if id == 949110 || (id >= 949000 && id <= 949999) || (id >= 959000 && id <= 959999) {
			continue
		}
		for _, t := range mr.Rule().Tags() {
			if strings.HasPrefix(t, "attack-") {
				return id
			}
		}
		if fallback == 0 && id >= 920000 && id <= 959999 {
			fallback = id
		}
	}
	return fallback
}

func addrParts(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

// isNumericRuleID reports whether the ID is a numeric Coraza rule id.
func isNumericRuleID(id string) bool {
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(id) > 0
}

// siteMatches reports whether the domain matches any of the site's domains.
func siteMatches(domains []string, domain string) bool {
	for _, d := range domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// enabledCategorySet resolves the effective enabled detection categories:
// a non-nil site list wins, otherwise the global default (policy) applies
// when set, otherwise all categories are enabled (backward compat).
func enabledCategorySet(ws *config.WAFSettings, globalCats []string) map[string]bool {
	enabled := make(map[string]bool)
	if ws == nil || ws.Categories == nil {
		if globalCats != nil {
			for _, cat := range globalCats {
				cat = strings.TrimSpace(strings.ToLower(cat))
				if config.ValidWAFCategory(cat) {
					enabled[cat] = true
				}
			}
		} else {
			for _, cat := range config.WAFDetectionCategories {
				enabled[cat] = true
			}
		}
	} else {
		for _, cat := range ws.Categories {
			cat = strings.TrimSpace(strings.ToLower(cat))
			if config.ValidWAFCategory(cat) {
				enabled[cat] = true
			}
		}
	}
	return enabled
}

// crsFileNumber extracts the 3-digit CRS number from an include file name
// (e.g. REQUEST-932-APPLICATION-ATTACK-RCE.conf → 932).
func crsFileNumber(name string) int {
	i := strings.Index(name, "-")
	if i < 0 {
		return 0
	}
	rest := name[i+1:]
	j := strings.Index(rest, "-")
	if j < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return 0
	}
	return n
}

// filterUpdateTargetById drops SecRuleUpdateTargetById directives whose
// target rule lives in an excluded category file. CRS's always-on
// REQUEST-999 "after" file carries updates referencing rules inside the
// detection files (930/932/941/942…); excluding a category removes those
// rules and coraza fails to compile the dangling update ("rule … not
// found"), so such directives must be dropped for the filtered set.
func excludedCategoryPrefixes(ws *config.WAFSettings, globalCats []string) map[int]bool {
	enabled := enabledCategorySet(ws, globalCats)
	excluded := map[int]bool{}
	for cat, f := range config.WAFCategoryFiles() {
		if enabled[cat] {
			continue
		}
		if num := crsFileNumber(f); num > 0 {
			excluded[num] = true
		}
	}
	return excluded
}

// dropUpdateTargetLines filters one directives file body, dropping
// SecRuleUpdateTargetById lines whose target rule belongs to an excluded
// category file (3-digit CRS number prefix match).
func dropUpdateTargetLines(content string, excluded map[int]bool) string {
	if len(excluded) == 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToLower(t), "secruleupdatetargetbyid") {
			if fields := strings.Fields(t); len(fields) >= 2 {
				if id, err := strconv.Atoi(fields[1]); err == nil && excluded[id/1000] {
					continue
				}
			}
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// materializeCRSIncludes resolves the dangling SecRuleUpdateTargetById
// problem for filtered category sets. The update directives live INSIDE the
// included CRS files (the always-on REQUEST-999 "after" file references
// detection rules), so filtering the directive string alone is not enough:
// any included file whose body carries update directives targeting excluded
// categories is read from the embedded ruleset, filtered and INLINED in
// place of its Include directive; the directives string itself is filtered
// too (covers user custom rules referencing excluded rules).
func materializeCRSIncludes(directives string, ws *config.WAFSettings, globalCats []string) string {
	excluded := excludedCategoryPrefixes(ws, globalCats)
	if len(excluded) == 0 {
		return directives
	}
	lines := strings.Split(directives, "\n")
	out := make([]string, 0, len(lines)+64)
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if name, ok := strings.CutPrefix(t, "Include @owasp_crs/"); ok && !strings.Contains(name, "*") {
			if b, err := fs.ReadFile(coreruleset.FS, "@owasp_crs/"+name); err == nil {
				body := string(b)
				if strings.Contains(strings.ToLower(body), "secruleupdatetargetbyid") {
					out = append(out, dropUpdateTargetLines(body, excluded))
					continue
				}
			}
		}
		out = append(out, ln)
	}
	return dropUpdateTargetLines(strings.Join(out, "\n"), excluded)
}

// buildCRSIncludes generates the CRS include directive list based on the
// site's category configuration. When Categories is nil, the global default
// (policy.WAFCategories) applies when set, otherwise all detection
// categories are included (backward compat). A non-nil site list takes
// precedence over the global default. Only the listed category files and
// the always-on infrastructure files are included — disabled categories
// never load, reducing both rule count and per-request evaluation cost.
//
// Includes are emitted in CRS file-number order to preserve the original
// glob ordering, which matters because SecRuleUpdateTargetById in some CRS
// files references rules defined in earlier files.
func buildCRSIncludes(ws *config.WAFSettings, globalCats []string) string {
	enabled := enabledCategorySet(ws, globalCats)

	// Build the ordered include list: all CRS files sorted by number, with
	// disabled category files skipped. Always-on files are never skipped.
	type crsFile struct {
		name     string
		category string // "" = always-on, cannot be disabled
	}

	var allFiles []crsFile
	for _, f := range config.WAFAlwaysOnFiles() {
		allFiles = append(allFiles, crsFile{name: f, category: ""})
	}
	for cat, f := range config.WAFCategoryFiles() {
		allFiles = append(allFiles, crsFile{name: f, category: cat})
	}
	sort.Slice(allFiles, func(i, j int) bool { return allFiles[i].name < allFiles[j].name })

	var sb strings.Builder
	for _, f := range allFiles {
		if f.category != "" && !enabled[f.category] {
			continue
		}
		sb.WriteString("Include @owasp_crs/")
		sb.WriteString(f.name)
		sb.WriteString("\n")
	}
	return sb.String()
}

// siteCategoryExclusions delegates to the shared config-layer collector so
// publish-time validation and the runtime build derive identical variant
// sets (including the per-site scoped-rule cap error).
func siteCategoryExclusions(policy *config.Policy, domains []string) ([]map[string]bool, error) {
	return config.ScopedCorazaExclusionSets(policy, domains)
}

// buildVariantWAF compiles one variant engine: the site's effective category
// set minus the excluded categories, run through the regular buildWAF path
// (site waf.categories vs global default stacking and the REQUEST-999
// dangling-update filtering apply unchanged — disable scoping can only
// narrow the loaded set).
func buildVariantWAF(s *config.Site, policy *config.Policy, exclude map[string]bool) (coraza.WAF, error) {
	clone := *s
	ws := config.WAFSettings{}
	if s.WAF != nil {
		ws = *s.WAF
	}
	ws.Categories = variantCategories(s, policy, exclude)
	clone.WAF = &ws
	return buildWAF(&clone, policy)
}

// variantCategories computes the variant's effective detection categories:
// the site's enabled set (site waf.categories, else the global default, else
// all categories) minus the disabled categories. Disable scoping can only
// narrow the loaded set, never widen it.
func variantCategories(s *config.Site, policy *config.Policy, exclude map[string]bool) []string {
	var globalCats []string
	if policy != nil {
		globalCats = policy.WAFCategories
	}
	base := enabledCategorySet(s.WAF, globalCats)
	cats := make([]string, 0, len(base))
	for _, cat := range config.WAFDetectionCategories {
		if base[cat] && !exclude[cat] {
			cats = append(cats, cat)
		}
	}
	return cats
}
