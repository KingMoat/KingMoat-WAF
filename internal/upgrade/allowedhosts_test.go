package upgrade

import (
	"net/url"
	"sort"
	"strings"
	"testing"
)

// allowlistKey renders a host list as an order-insensitive comparable key.
func allowlistKey(hosts []string) string {
	got := append([]string(nil), hosts...)
	sort.Strings(got)
	return strings.Join(got, ",")
}

// TestDefaultAllowedHostsPinned pins the exact contents of the default
// download allowlist: the Gitee release origin plus its official attachment
// CDN, nothing more. Any change here is a download-policy change and must be
// reviewed as such (a dropped host breaks online upgrades on the official
// channel; an added host widens the tamper surface).
func TestDefaultAllowedHostsPinned(t *testing.T) {
	want := []string{"gitee.com", "foruda.gitee.com"}
	if key := allowlistKey(defaultAllowedHosts); key != allowlistKey(want) {
		t.Fatalf("defaultAllowedHosts = %v, want exactly %v", defaultAllowedHosts, want)
	}
}

// TestServiceDefaultsToPinnedAllowlist ensures the pinned list is what a
// default-constructed service actually enforces, and that the refusal
// message names the enforced hosts.
func TestServiceDefaultsToPinnedAllowlist(t *testing.T) {
	s := NewService("v0.7.12-beta", t.TempDir())
	if key := allowlistKey(s.allowedHosts); key != allowlistKey(defaultAllowedHosts) {
		t.Fatalf("service allowlist = %v, want the pinned default %v", s.allowedHosts, defaultAllowedHosts)
	}
	u, err := url.Parse("https://evil.example.com/x.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.validateDownloadURL(u); err == nil || !strings.Contains(err.Error(), "来源域名") {
		t.Fatalf("foreign host = %v, want allowlist refusal", err)
	}
	for _, h := range defaultAllowedHosts {
		if !strings.Contains(err.Error(), h) {
			t.Fatalf("refusal %q must list enforced host %s", err, h)
		}
	}
}

// TestRefusalMessageListsConfiguredHosts pins C-7②: the refusal text is
// assembled from the service's actual allowlist, never a hardcoded pair —
// a deployment overriding WithAllowedHosts sees its own hosts in the error.
func TestRefusalMessageListsConfiguredHosts(t *testing.T) {
	s := NewService("v0.7.12-beta", t.TempDir(),
		WithAllowedHosts([]string{"mirror.example.com"}), WithPlatform("linux", "amd64"))
	u, err := url.Parse("https://foruda.gitee.com/pkg.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.validateDownloadURL(u); err == nil || !strings.Contains(err.Error(), "来源域名") {
		t.Fatalf("non-allowlisted host = %v, want allowlist refusal", err)
	}
	if !strings.Contains(err.Error(), "mirror.example.com") {
		t.Fatalf("refusal %q must list the configured allowlist host", err)
	}
	// The refused URL itself legitimately contains the offending host
	// ("下载地址 %q"); the allowlist must not - check only the list part.
	if i := strings.Index(err.Error(), "当前允许："); i >= 0 {
		tail := err.Error()[i:]
		if strings.Contains(tail, "foruda.gitee.com") {
			t.Fatalf("refusal allowlist %q must not hardcode a host outside the configured allowlist", tail)
		}
	}
}
