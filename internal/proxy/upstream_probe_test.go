package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Regression: the active health probe used the default http.Client, which
// verifies upstream certificates — while the forward path skips verification
// unless the site opts in (verify_tls). A self-signed/internal-CA HTTPS
// upstream therefore served traffic fine while the probe kept marking the
// node unhealthy. The probe must mirror the site's TLS policy.
func TestProbeHonorsUpstreamTLSPolicy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	waitHealthy := func(p *Pool, want bool) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for {
			got := p.nodes[0].healthy.Load()
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("node healthy=%v, want %v (probe TLS policy mismatch)", got, want)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	hc := &config.HealthSettings{Enabled: true, IntervalSec: 1, TimeoutSec: 1, Path: "/"}

	// Default (verify_tls=false): probe must skip verification and succeed.
	poolInsecure, err := NewPool(config.Upstream{Nodes: []config.UpstreamNode{{Address: srv.URL}}}, hc, "t-insecure", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer poolInsecure.Close()
	waitHealthy(poolInsecure, true)

	// verify_tls=true against a self-signed upstream: probe fails (expected),
	// node must NOT be marked healthy.
	poolVerify, err := NewPool(config.Upstream{
		Nodes:     []config.UpstreamNode{{Address: srv.URL}},
		VerifyTLS: true,
	}, hc, "t-verify", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer poolVerify.Close()
	waitHealthy(poolVerify, false)
}
