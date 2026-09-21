package stages

import (
	"context"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/corazawaf/libinjection-go"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Semantic is a lightweight semantic detection layer built on libinjection.
// It detects SQL injection and XSS on the request target, referer headers
// and the buffered body, independent of the OWASP CRS rule set. It is not a
// full AST engine; it complements (not replaces) CRS.
type Semantic struct {
	byDomain map[string]semanticCfg
	logger   *slog.Logger
}

type semanticCfg struct {
	checkQuery bool
	checkBody  bool
}

// NewSemantic builds the stage; sites without semantic.enabled are skipped.
func NewSemantic(cfg *config.Config, logger *slog.Logger) *Semantic {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := map[string]semanticCfg{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.Semantic == nil || !s.Security.Semantic.Enabled {
			continue
		}
		sc := semanticCfg{checkQuery: true, checkBody: true}
		if s.Security.Semantic.CheckBody || s.Security.Semantic.CheckQuery {
			// explicit flags override defaults
			sc.checkQuery = s.Security.Semantic.CheckQuery
			sc.checkBody = s.Security.Semantic.CheckBody
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = sc
		}
	}
	return &Semantic{byDomain: byDomain, logger: logger}
}

// Name implements pipeline.Stage.
func (s *Semantic) Name() string { return "semantic" }

// Inspect implements pipeline.Stage.
func (s *Semantic) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if trusted, _ := rc.Values["trusted"].(bool); trusted {
		return pipeline.Allow()
	}
	sc, ok := s.byDomain[strings.ToLower(rc.Site.Domain)]
	if !ok {
		return pipeline.Allow()
	}
	r := rc.Request

	// False-positive exceptions ("一键加白") suppress stage-level rules.
	excepted := func(rule string) bool { return Excepted(rc, rule) }

	if sc.checkQuery {
		if v := s.scan(r.URL.Path); v != nil && !excepted(v.Rule) {
			return *v
		}
		q := r.URL.Query()
		for _, key := range sortedKeys(q) {
			for _, val := range q[key] {
				if v := s.scan(key + "=" + val); v != nil && !excepted(v.Rule) {
					return *v
				}
			}
		}
		if ref := r.Header.Get("Referer"); ref != "" {
			if v := s.scan(ref); v != nil && !excepted(v.Rule) {
				return *v
			}
		}
	}
	if sc.checkBody && len(rc.Body) > 0 {
		if v := s.scan(string(rc.Body)); v != nil && !excepted(v.Rule) {
			return *v
		}
	}
	return pipeline.Allow()
}

// scan returns a deny verdict for the first semantic hit in input.
func (s *Semantic) scan(input string) *pipeline.Verdict {
	if ok, fp := libinjection.IsSQLi(input); ok {
		s.logger.Warn("semantic: SQL injection pattern", "fingerprint", fp)
		v := pipeline.Deny("semantic/sqli", "SQL injection semantics detected (libinjection "+fp+")")
		return &v
	}
	if libinjection.IsXSS(input) {
		v := pipeline.Deny("semantic/xss", "XSS semantics detected (libinjection)")
		return &v
	}
	return nil
}

// sortedKeys keeps query parameter iteration deterministic.
func sortedKeys(q url.Values) []string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
