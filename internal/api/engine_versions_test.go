package api

import "testing"

// TestReleaseFor verifies the release-month lookup for the locked upstream
// versions. Regression: a lost write of this map left the version card
// showing "上游发布：-" in production.
func TestReleaseFor(t *testing.T) {
	cases := map[string]string{
		"github.com/corazawaf/coraza/v3@v3.7.0":              "2026-04",
		"github.com/corazawaf/coraza-coreruleset/v4@v4.25.0": "2026-03",
		"go1.27.0": "2026-08",
	}
	for key, want := range cases {
		if got := upstreamReleases[key]; got != want {
			t.Fatalf("%s: got %q want %q", key, got, want)
		}
	}
}
