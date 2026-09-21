package dynamics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func secureResp(contentType string, body string) *httptest.ResponseRecorder {
	resp := httptest.NewRecorder()
	resp.Header().Set("Content-Type", contentType)
	resp.Body.WriteString(body)
	return resp
}

func TestApplyTransformsHTML(t *testing.T) {
	orig := "<html><body>" + strings.Repeat("secret ", 100) + "</body></html>"
	req := httptest.NewRequest("GET", "http://x.local/", nil)
	req = req.WithContext(WithClientSecure(req.Context(), true))

	rec := secureResp("text/html; charset=utf-8", orig)
	httpResp := rec.Result()
	httpResp.Request = req

	if !Apply(0, 0, httpResp) {
		t.Fatal("Apply returned false for an HTML body over HTTPS")
	}
	out := readAll(t, httpResp.Body)
	if !strings.Contains(out, "crypto.subtle") {
		t.Fatal("wrapper decoder missing")
	}
	if strings.Contains(out, "secret ") {
		t.Fatal("original body still visible")
	}
	if len(out) <= len(orig) {
		t.Fatal("wrapped body unexpectedly smaller")
	}
}

func TestApplySkipsNonHTML(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x.local/", nil)
	req = req.WithContext(WithClientSecure(req.Context(), true))
	rec := secureResp("application/json", `{"a":"`+strings.Repeat("x", 600)+`"}`)
	httpResp := rec.Result()
	httpResp.Request = req
	if Apply(0, 0, httpResp) {
		t.Fatal("non-HTML body must not be transformed")
	}
}

func TestApplySkipsInsecureContext(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x.local/", nil) // no WithClientSecure
	rec := secureResp("text/html", strings.Repeat("x", 700))
	httpResp := rec.Result()
	httpResp.Request = req
	if Apply(0, 0, httpResp) {
		t.Fatal("plain-http page must not be transformed")
	}
}

func TestApplySkipsCompressed(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x.local/", nil)
	req = req.WithContext(WithClientSecure(req.Context(), true))
	rec := secureResp("text/html", strings.Repeat("x", 700))
	rec.Header().Set("Content-Encoding", "gzip")
	httpResp := rec.Result()
	httpResp.Request = req
	if Apply(0, 0, httpResp) {
		t.Fatal("compressed body must not be transformed")
	}
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
