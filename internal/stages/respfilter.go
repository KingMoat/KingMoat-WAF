package stages

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
)

// RespFilter scans upstream response bodies for sensitive information and
// either masks matches or replaces the response with a block page. It runs
// in the proxy's ModifyResponse hook (docs/ARCHITECTURE.md 搂3.1 step 鈶? 鈥?
// it is not a request pipeline stage.
type RespFilter struct {
	byDomain map[string]*filterSite
	logger   *slog.Logger

	// hitHook is the optional observe-only callback fired with the pattern
	// name on every detection (used by the API-asset risk engine).
	hitHook func(siteDomain, path, pattern string)
}

type filterSite struct {
	action string // "mask" | "block"
	res    []*compiledPattern
	limit  int64
}

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

// builtinPresets are the built-in sensitive-data pattern sets (RE2 syntax 鈥?
// no lookbehind/lookahead).
var builtinPresets = map[string][]config.RespPattern{
	"phone": {{
		Name:  "cn_mobile_phone",
		Regex: `\b1[3-9]\d{9}\b`,
	}},
	"idcard": {{
		Name:  "cn_id_card",
		Regex: `\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b`,
	}},
	"secret": {
		{Name: "aws_access_key", Regex: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`},
		{Name: "openai_style_key", Regex: `\bsk-[A-Za-z0-9_-]{20,}\b`},
		{Name: "private_key_block", Regex: `-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`},
		{Name: "jwt", Regex: `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`},
	},
}

// NewRespFilter compiles per-site response filters.
func NewRespFilter(cfg *config.Config, logger *slog.Logger) (*RespFilter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := make(map[string]*filterSite)
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.RespFilter == nil || !s.Security.RespFilter.Enabled {
			continue
		}
		rf := s.Security.RespFilter
		fs := &filterSite{
			action: rf.Action,
			limit:  rf.BodyLimit,
		}
		if fs.action == "" {
			fs.action = "mask"
		}
		if fs.limit <= 0 {
			fs.limit = 8 << 20
		}
		patterns := make([]config.RespPattern, 0, len(rf.Presets)+len(rf.Patterns))
		for _, p := range rf.Presets {
			set, ok := builtinPresets[strings.ToLower(p)]
			if !ok {
				return nil, fmt.Errorf("respfilter: site %d: unknown preset %q (known: phone, idcard, secret)", i, p)
			}
			patterns = append(patterns, set...)
		}
		patterns = append(patterns, rf.Patterns...)
		for _, p := range patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("respfilter: site %d pattern %q: %w", i, p.Name, err)
			}
			fs.res = append(fs.res, &compiledPattern{name: p.Name, re: re})
		}
		if len(fs.res) == 0 {
			continue
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = fs
		}
	}
	return &RespFilter{byDomain: byDomain, logger: logger}, nil
}

// SetHitHook registers the observe-only detection callback (nil clears it).
func (rf *RespFilter) SetHitHook(fn func(siteDomain, path, pattern string)) {
	rf.hitHook = fn
}

// Apply inspects and rewrites an upstream response for the given site.
// Non-text bodies, oversized bodies and non-2xx/3xx responses pass through
// untouched. Returns true when the response was rewritten.
func (rf *RespFilter) Apply(siteDomain string, resp *http.Response) bool {
	if rf == nil || resp == nil || resp.Body == nil {
		return false
	}
	fs := rf.byDomain[strings.ToLower(siteDomain)]
	if fs == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if !isTextContentType(ct) {
		return false
	}
	if resp.ContentLength > fs.limit {
		return false // too large to scan safely: pass through
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, fs.limit+1))
	_ = resp.Body.Close()
	if err != nil {
		rf.logger.Error("respfilter: read response body failed", "err", err)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return false
	}
	if int64(len(body)) > fs.limit {
		// Oversized without Content-Length: forward the buffered stream intact.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return false
	}

	out := body
	hit := false
	for _, p := range fs.res {
		if p.re.Match(out) {
			hit = true
			rf.notifyHit(siteDomain, resp.Request, p.name)
			if fs.action == "mask" {
				out = p.re.ReplaceAll(out, []byte("[REDACTED:"+p.name+"]"))
			} else {
				break // block mode: stop at first hit
			}
		}
	}
	if !hit {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return false
	}

	rf.logger.Warn("respfilter: sensitive data detected",
		"site", siteDomain, "action", fs.action)

	if fs.action == "block" {
		resp.StatusCode = http.StatusForbidden
		resp.Status = ""
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Set("X-KingMoat-Action", "blocked")
		page := []byte(blockPageHTML)
		resp.Body = io.NopCloser(bytes.NewReader(page))
		resp.ContentLength = int64(len(page))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(page)))
		return true
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(out)))
	return true
}

func isTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	for _, marker := range []string{"text/", "json", "xml", "javascript"} {
		if strings.Contains(ct, marker) {
			return true
		}
	}
	return false
}

const blockPageHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Blocked by KingMoat</title></head>
<body style="font-family:system-ui,sans-serif;text-align:center;padding-top:15vh">
<h1>鍝嶅簲鍖呭惈鏁忔劅淇℃伅锛屽凡琚噾姹?WAF 鎷︽埅</h1>
<p>Response blocked by KingMoat WAF (sensitive data detected)</p>
</body></html>`

// notifyHit fires the observe-only hook when a pattern matches (best-effort;
// it must never affect the response pipeline).
func (rf *RespFilter) notifyHit(siteDomain string, req *http.Request, pattern string) {
	if rf.hitHook == nil || req == nil || req.URL == nil {
		return
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	rf.hitHook(siteDomain, path, pattern)
}
