package redact

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestURLStripsUserinfo(t *testing.T) {
	got := URL("http://elastic:Sup3rS3cret@logs.internal:9200/kingmoat/_bulk")
	if strings.Contains(got, "Sup3rS3cret") || strings.Contains(got, "elastic:") {
		t.Fatalf("credentials leaked: %s", got)
	}
	if got != "http://logs.internal:9200/kingmoat/_bulk" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestURLMasksTokenQuery(t *testing.T) {
	got := URL("https://oapi.dingtalk.com/robot/send?access_token=abc123def456&timestamp=1700000000")
	if strings.Contains(got, "abc123def456") {
		t.Fatalf("token leaked: %s", got)
	}
	if !strings.Contains(got, "timestamp=1700000000") {
		t.Fatalf("non-sensitive query must be preserved: %s", got)
	}
	if !strings.Contains(got, "access_token=%2A%2A%2A") {
		t.Fatalf("token not masked: %s", got)
	}
}

func TestURLKeepsPlainURLs(t *testing.T) {
	in := "http://loki:3100/loki/api/v1/push"
	if got := URL(in); got != in {
		t.Fatalf("plain url changed: %s", got)
	}
}

func TestStringRedactsEmbeddedURLs(t *testing.T) {
	_, _ = url.Parse("x")
	err := fmt.Errorf(`Post "http://user:secret@loki:3100/push?token=tkn123": dial tcp: i/o timeout`)
	got := String(err.Error())
	if strings.Contains(got, "secret") || strings.Contains(got, "tkn123") {
		t.Fatalf("credentials leaked: %s", got)
	}
	if !strings.Contains(got, "dial tcp: i/o timeout") {
		t.Fatalf("error context lost: %s", got)
	}
}

func TestStringLeavesPlainText(t *testing.T) {
	in := "connection refused after 5s"
	if got := String(in); got != in {
		t.Fatalf("plain text changed: %s", got)
	}
}
