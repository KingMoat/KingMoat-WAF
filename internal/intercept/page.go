// Package intercept renders the block page returned when the pipeline
// denies a request.
package intercept

import (
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Challenge writes the bot JS challenge page: the embedded script stores a
// signed cookie and reloads the page. Status 200 so browsers execute the JS.
func Challenge(w http.ResponseWriter, cookieName, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-KingMoat-Action", "challenge")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, challengePage,
		html.EscapeString(cookieName),
		html.EscapeString(token))
}

// SliderChallenge writes the slider-captcha page produced by the captcha
// stage (self-contained HTML with the SVG challenge).
func SliderChallenge(w http.ResponseWriter, pageHTML string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-KingMoat-Action", "challenge")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, pageHTML)
}

const challengePage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>安全验证 · KingMoat</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f6f7f9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:480px}
h1{font-size:20px;color:#1f2329;margin:0 0 12px}
p{color:#646a73;font-size:14px}
footer{margin-top:24px;font-size:12px;color:#8f959e}
</style>
</head>
<body>
<div class="card">
<h1>正在进行安全验证…</h1>
<p>请稍候，页面将自动刷新。</p>
<noscript><p>浏览器需要启用 JavaScript 才能完成验证。</p></noscript>
<footer>KingMoat WAF — 固若金汤，御攻于无形</footer>
</div>
<script>
(function(){
  var c = "%s";
  var t = "%s";
  document.cookie = c + "=" + t + "; path=/; max-age=3600; samesite=lax";
  setTimeout(function(){ location.reload(); }, 50);
})();
</script>
</body>
</html>
`

var blockPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>请求被拦截 · Blocked by KingMoat</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f6f7f9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:560px}
.code{font-size:44px;font-weight:700;color:#d4380d;margin:0 0 12px}
h1{font-size:20px;color:#1f2329;margin:0 0 8px}
p{color:#646a73;font-size:14px;margin:4px 0}
.rule{font-family:ui-monospace,SFMono-Regular,monospace;background:#f2f3f5;padding:2px 8px;border-radius:4px;font-size:12px;word-break:break-all}
footer{margin-top:24px;font-size:12px;color:#8f959e}
</style>
</head>
<body>
<div class="card">
<div class="code">%d</div>
<h1>%s</h1>
<p>%s</p>
<p>规则 <span class="rule">%s</span></p>
<p>请求地址 <span class="rule">%s</span></p>
<p>来源 IP <span class="rule">%s</span> ｜ Trace <span class="rule">%s</span></p>
<footer>%s</footer>
</div>
</body>
</html>
`

// badGatewayPage is the centered 502 page shown when a site's upstream is
// unreachable. Same visual language as the block page (fixed light palette,
// centered card, monospace detail row), no external resources; %s is the
// optional request/trace detail line (empty when no trace id is present).
const badGatewayPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>502 · 暂时无法访问该站点</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f6f7f9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:560px}
.code{font-size:44px;font-weight:700;color:#d46b08;margin:0 0 12px}
h1{font-size:20px;color:#1f2329;margin:0 0 8px}
p{color:#646a73;font-size:14px;margin:4px 0}
.rule{font-family:ui-monospace,SFMono-Regular,monospace;background:#f2f3f5;padding:2px 8px;border-radius:4px;font-size:12px;word-break:break-all}
footer{margin-top:24px;font-size:12px;color:#8f959e}
</style>
</head>
<body>
<div class="card">
<div class="code">502</div>
<h1>暂时无法访问该站点</h1>
<p>当前站点无法连接上游资源，请联系站点管理员处理</p>
%s
<footer>KingMoat WAF — 固若金汤，御攻于无形</footer>
</div>
</body>
</html>
`

// Render502 writes the centered 502 page for upstream failures. The trace id
// (attached to the request by the WAF handler) is rendered in the same
// monospace style as the block page when present. The response keeps status
// 502; callers own the X-KingMoat-Upstream-Error header and metrics.
func Render502(w http.ResponseWriter, r *http.Request) {
	trace := strings.TrimSpace(r.Header.Get("X-KingMoat-Trace-Id"))
	detail := ""
	if trace != "" {
		detail = `<p>请求地址 <span class="rule">` + html.EscapeString(r.URL.RequestURI()) +
			`</span> ｜ Trace <span class="rule">` + html.EscapeString(trace) + `</span></p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, badGatewayPage, detail)
}

// Deny writes the block page using the verdict's status (default 403).
// When a custom block page (block_page.html) is configured it replaces the
// built-in page entirely and gets request-context placeholders substituted
// (values are HTML-escaped before injection). For the built-in page the
// verdict reason is intentionally NOT rendered: detailed rule messages go to
// logs/audit only, never to the client.
var blockPageCopy atomic.Pointer[config.BlockPage]

// SetBlockPage wires the configured copy (nil = defaults).
func SetBlockPage(bp *config.BlockPage) { blockPageCopy.Store(bp) }

// blockVars builds the placeholder map for custom block pages.
func blockVars(r *http.Request, v pipeline.Verdict, traceID string, status int) map[string]string {
	now := time.Now().Format("2006-01-02 15:04:05 -0700")
	m := map[string]string{
		"request_id": traceID,
		"rule_id":    v.Rule,
		"reason":     v.Reason,
		"method":     r.Method,
		"host":       r.Host,
		"url":        r.URL.RequestURI(),
		"ua":         r.UserAgent(),
		"timestamp":  now,
		"status":     strconv.Itoa(status),
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		m["client_ip"] = ip
	} else {
		m["client_ip"] = r.RemoteAddr
	}
	return m
}

// expandBlockVars replaces {{key}} placeholders (HTML-escaped values).
func expandBlockVars(page string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(page, func(match string) string {
		key := strings.TrimSpace(match[2 : len(match)-2])
		if v, ok := vars[key]; ok {
			return html.EscapeString(v)
		}
		return ""
	})
}

var varRe = regexp.MustCompile(`\{\{\s*[a-z_]+\s*\}\}`)

func Deny(w http.ResponseWriter, r *http.Request, v pipeline.Verdict, traceID string) {
	status := v.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Script-free CSP: block pages carry no scripts, so this is a hard
	// backstop for the stored-XSS validation of custom HTML (defense in
	// depth, see config.validateBlockHTML).
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	w.Header().Set("X-KingMoat-Action", "blocked")
	w.Header().Set("X-KingMoat-Rule", v.Rule)
	w.Header().Set("X-KingMoat-Trace-Id", traceID)
	if bp := blockPageCopy.Load(); bp != nil && bp.HTML != "" {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, expandBlockVars(bp.HTML, blockVars(r, v, traceID, status)))
		return
	}
	title, message, footer := "请求被拦截 · Blocked by KingMoat",
		"该请求触发了安全防护规则，已被拒绝访问。", "KingMoat WAF — 固若金汤，御攻于无形"
	if bp := blockPageCopy.Load(); bp != nil {
		if bp.Title != "" {
			title = bp.Title
		}
		if bp.Message != "" {
			message = bp.Message
		}
		if bp.Footer != "" {
			footer = bp.Footer
		}
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, blockPage, status,
		html.EscapeString(title),
		html.EscapeString(message),
		html.EscapeString(v.Rule),
		html.EscapeString(r.URL.RequestURI()),
		html.EscapeString(blockVars(r, v, traceID, status)["client_ip"]),
		html.EscapeString(traceID),
		html.EscapeString(footer))
}
