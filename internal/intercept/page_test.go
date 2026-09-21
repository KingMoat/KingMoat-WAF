package intercept

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func TestDenyPageCustomCopy(t *testing.T) {
	SetBlockPage(&config.BlockPage{Title: "Custom Title", Message: "Custom Msg", Footer: "Custom Footer"})
	defer SetBlockPage(nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	Deny(rec, req, pipeline.Deny("test/rule", "reason"), "trace123")
	if rec.Code != 403 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, "Custom Title") || !contains(body, "Custom Msg") || !contains(body, "Custom Footer") {
		t.Fatal("custom copy not rendered")
	}
}

func TestDenyPageDefaults(t *testing.T) {
	SetBlockPage(nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	Deny(rec, req, pipeline.Deny("test/rule", "reason"), "t1")
	body := rec.Body.String()
	if !contains(body, "请求被拦截") {
		t.Fatal("default title not rendered")
	}
}

func TestDenyCustomHTMLVars(t *testing.T) {
	SetBlockPage(&config.BlockPage{HTML: `<html><title>blocked</title><p id="ip">{{client_ip}}</p><p id="rule">{{rule_id}}</p><p id="ua">{{ua}}</p></html>`})
	defer SetBlockPage(nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/pay?a=1", nil)
	req.Header.Set("User-Agent", `evil<script>`)
	Deny(rec, req, pipeline.Deny("crs/942100", "sqli"), "tr-9")
	if rec.Code != 403 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `crs/942100`) {
		t.Fatal("rule_id placeholder not substituted")
	}
	if !strings.Contains(body, `evil&lt;script&gt;`) {
		t.Fatal("placeholder values must be HTML-escaped")
	}
	if strings.Contains(body, "{{") {
		t.Fatal("unresolved placeholders leaked")
	}
}

func TestValidateBlockHTML(t *testing.T) {
	ok := &config.BlockPage{HTML: "<html><h1>blocked</h1></html>"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid html rejected: %v", err)
	}
	for _, bad := range []string{
		`<script>alert(1)</script>`,
		`<img onerror="x">`,
		`<a href="javascript:alert(1)">`,
		strings.Repeat("a", 256<<10+1),
	} {
		bp := &config.BlockPage{HTML: bad}
		if err := bp.Validate(); err == nil {
			t.Fatalf("expected rejection for %q", bad[:min(30, len(bad))])
		}
	}
}

func TestRender502Page(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://shop.local/app?q=1", nil)
	req.Header.Set("X-KingMoat-Trace-Id", "tr-502")
	Render502(rec, req)
	if rec.Code != 502 {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"502", "暂时无法访问该站点", "当前站点无法连接上游资源，请联系站点管理员处理", "tr-502", "/app?q=1"} {
		if !contains(body, want) {
			t.Fatalf("502 page missing %q", want)
		}
	}
	if strings.Contains(body, "<script") {
		t.Fatal("502 page must not embed scripts")
	}
}

func TestRender502PageNoTrace(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://shop.local/", nil)
	Render502(rec, req)
	if rec.Code != 502 {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Trace") {
		t.Fatal("trace line must be omitted when no trace id is present")
	}
}

func TestSliderChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	SliderChallenge(rec, "<html>slider</html>")
	if rec.Code != 200 || !contains(rec.Body.String(), "slider") {
		t.Fatal("slider challenge failed")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
