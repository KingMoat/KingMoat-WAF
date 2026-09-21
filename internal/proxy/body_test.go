package proxy

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestBufferBodySmall(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("hello world"))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 100}}

	data, over, pool, err := bufferBody(r, site)
	if pool != nil {
		defer recycle(pool)
	}
	if err != nil {
		t.Fatalf("bufferBody: %v", err)
	}
	if over {
		t.Fatal("small body must not be flagged over limit")
	}
	if string(data) != "hello world" {
		t.Fatalf("data = %q", data)
	}

	// Body must be rewound for forwarding / the pipeline.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "hello world" {
		t.Fatalf("rewound body = %q", rest)
	}
}

func TestBufferBodyOverLimitWithKnownLength(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("1234567890"))
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 5}}

	_, over, pool, err := bufferBody(r, site)
	if pool != nil {
		defer recycle(pool)
	}
	if err != nil || !over {
		t.Fatalf("over=%v err=%v, want over=true", over, err)
	}

	// The untouched body must still forward completely (bypass path).
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "1234567890" {
		t.Fatalf("bypassed body = %q, want intact", rest)
	}
}

func TestBufferBodyOverLimitChunkedRewinds(t *testing.T) {
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader("abcdefghij"))
	r.ContentLength = -1 // simulate chunked / unknown length
	r.TransferEncoding = []string{"chunked"}
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 5}}

	_, over, pool, err := bufferBody(r, site)
	if pool != nil {
		defer recycle(pool)
	}
	if err != nil || !over {
		t.Fatalf("over=%v err=%v, want over=true", over, err)
	}

	// Consumed bytes (limit+1) must be glued back to the remaining stream.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != "abcdefghij" {
		t.Fatalf("rewound chunked body = %q, want intact", rest)
	}
}

func TestBufferBodyStreamPolicyReturnsPrefix(t *testing.T) {
	body := strings.Repeat("a", 100)
	r := httptest.NewRequest("POST", "http://x.local/", strings.NewReader(body))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	site := &config.Site{WAF: &config.WAFSettings{BodyLimitBytes: 40, BodyOverLimit: "stream"}}

	data, over, pool, err := bufferBody(r, site)
	if pool != nil {
		defer recycle(pool)
	}
	if err != nil || !over {
		t.Fatalf("over=%v err=%v, want over=true", over, err)
	}
	if len(data) != 40 {
		t.Fatalf("stream prefix = %d bytes, want 40", len(data))
	}
	if string(data) != strings.Repeat("a", 40) {
		t.Fatal("stream prefix content mismatch")
	}

	// The full stream must still forward untouched.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != body {
		t.Fatalf("streamed body = %d bytes, want intact %d", len(rest), len(body))
	}
}
