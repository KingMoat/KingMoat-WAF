package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestResolveLegacyDataPath(t *testing.T) {
	origProbe := legacyDataFileExists
	defer func() { legacyDataFileExists = origProbe }()

	const configured = "/var/lib/kingmoat/uploads/certs/site-a/cert.pem"
	const remapped = "/var/lib/kingmoatwaf/uploads/certs/site-a/cert.pem"

	// Probe hit: remap and warn exactly once per path per process lifetime.
	legacyDataFileExists = func(string) bool { return true }
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if got := ResolveLegacyDataPath(configured, logger); got != remapped {
		t.Fatalf("resolve = %q, want remapped %q", got, remapped)
	}
	_ = ResolveLegacyDataPath(configured, logger)
	if n := strings.Count(buf.String(), "legacy data-dir path remapped"); n != 1 {
		t.Fatalf("warnings = %d, want 1 (once per path per process)\nlog:\n%s", n, buf.String())
	}

	// Probe miss: the original path is kept (the caller's normal error path
	// reports the configured path as-is) and no remap warning fires.
	legacyDataFileExists = func(string) bool { return false }
	other := "/var/lib/kingmoat/uploads/certs/site-b/cert.pem"
	if got := ResolveLegacyDataPath(other, logger); got != other {
		t.Fatalf("resolve = %q, want original %q (remapped target missing)", got, other)
	}
	if strings.Contains(buf.String(), "site-b") {
		t.Fatal("probe miss must not log a remap warning")
	}

	// Non-legacy paths pass through untouched regardless of the probe.
	legacyDataFileExists = func(string) bool { return true }
	if got := ResolveLegacyDataPath("/var/lib/kingmoatwaf/uploads/c.pem", nil); got != "/var/lib/kingmoatwaf/uploads/c.pem" {
		t.Fatalf("current-layout path must pass through, got %q", got)
	}
	if got := ResolveLegacyDataPath("uploads/c.pem", nil); got != "uploads/c.pem" {
		t.Fatalf("relative path must pass through, got %q", got)
	}
	if got := ResolveLegacyDataPath("", nil); got != "" {
		t.Fatalf("empty path must pass through, got %q", got)
	}
}

func TestLegacyPathHint(t *testing.T) {
	hint := LegacyPathHint("/var/lib/kingmoat/uploads/certs/a/cert.pem")
	for _, want := range []string{"疑似升级迁移", "/var/lib/kingmoat", "/var/lib/kingmoatwaf", "请更新配置或重新在控制台选择证书"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("hint %q missing %q", hint, want)
		}
	}
	if got := LegacyPathHint("/var/lib/kingmoatwaf/uploads/certs/a/cert.pem"); got != "" {
		t.Fatalf("current-layout path hint = %q, want empty", got)
	}
	if got := LegacyPathHint("uploads/a.pem"); got != "" {
		t.Fatalf("relative path hint = %q, want empty", got)
	}
	if got := LegacyPathHint(""); got != "" {
		t.Fatalf("empty path hint = %q, want empty", got)
	}
}
