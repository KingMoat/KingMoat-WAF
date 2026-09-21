package metrics

import (
	"strings"
	"testing"
)

func TestPrometheusText(t *testing.T) {
	RequestsTotal.Inc("site-a", "blocked")
	RequestsTotal.Inc("site-a", "blocked")
	RequestsTotal.Inc("site-b", "forwarded")
	AuditDropped.Set(3)
	out := PrometheusText("v-test")
	for _, want := range []string{
		"kingmoat_build_info{version=\"v-test\"} 1",
		"kingmoat_requests_total{site=\"site-a\",outcome=\"blocked\"} 2",
		"kingmoat_requests_total{site=\"site-b\",outcome=\"forwarded\"} 1",
		"kingmoat_audit_dropped_total 3",
		"# TYPE kingmoat_requests_total counter",
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("prometheus text missing %q\n%s", want, out)
		}
	}
}