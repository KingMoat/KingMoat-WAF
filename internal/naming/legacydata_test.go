package naming

import (
	"runtime"
	"testing"
)

func TestRemapLegacyDataPath(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"legacy file", "/var/lib/kingmoat/uploads/certs/site-a/cert.pem", "/var/lib/kingmoatwaf/uploads/certs/site-a/cert.pem", true},
		{"legacy non-uploads child", "/var/lib/kingmoat/geoip/db.mmdb", "/var/lib/kingmoatwaf/geoip/db.mmdb", true},
		{"already current layout", "/var/lib/kingmoatwaf/uploads/certs/x.pem", "", false},
		{"bare legacy dir (no separator)", "/var/lib/kingmoat", "", false},
		{"legacy sibling dir", "/var/lib/kingmoat-extra/uploads/x.pem", "", false},
		{"relative path", "uploads/certs/x.pem", "", false},
		{"empty", "", "", false},
		{"unrelated absolute", "/etc/kingmoatwaf/env", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RemapLegacyDataPath(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("RemapLegacyDataPath(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"trims space and remaps legacy", "  /var/lib/kingmoat/uploads/a.pem  ", "/var/lib/kingmoatwaf/uploads/a.pem"},
		{"keeps current layout", " /var/lib/kingmoatwaf/uploads/a.pem ", "/var/lib/kingmoatwaf/uploads/a.pem"},
		{"relative path only trimmed", " certs/a.pem ", "certs/a.pem"},
		{"empty", "   ", ""},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases, struct{ name, in, want string }{"unifies separators", `C:\data\certs\a.pem`, "C:/data/certs/a.pem"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePath(tc.in); got != tc.want {
				t.Fatalf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
