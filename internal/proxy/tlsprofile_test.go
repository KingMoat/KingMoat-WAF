package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// startTLSProfileSite spins an HTTPS listener with the given site profile and
// returns its address. The upstream is irrelevant (handshake-only probes).
func startTLSProfileSite(t *testing.T, profile string) string {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	certPath, keyPath := genSelfSignedCert(t, dir, "profile.test")
	cfg := &config.Config{
		ListenHTTPS: ":0",
		Sites: []config.Site{{
			Domains:    []string{"profile.test"},
			Upstream:   config.Upstream{Nodes: []config.UpstreamNode{{Address: up.Listener.Addr().String()}}},
			TLSCert:    certPath,
			TLSKey:     keyPath,
			TLSProfile: profile,
		}},
	}
	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: tenSec,
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			CipherSuites:       config.TLSCipherSuitesModerate,
			GetCertificate:     h.GetCertificate,
			GetConfigForClient: h.TLSConfigFor,
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// handshakeWith tries a TLS handshake offering exactly one TLS 1.2 suite.
func handshakeWith(addr string, suite uint16) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         "profile.test",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12, // keep the suite list decisive
		CipherSuites:       []uint16{suite},
		InsecureSkipVerify: true, //nolint:gosec // test target
	})
	if err != nil {
		return err
	}
	return conn.Close()
}

func TestTLSCipherProfileHandshake(t *testing.T) {
	// Probe suites are the ECDSA variants (the test certificate is ECDSA
	// P-256): AEAD, CBC-SHA1 (Go secure list) and CBC-SHA256 (Go insecure
	// list, compatible profile only).
	aead := uint16(0xC02B)     // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	cbcSha1 := uint16(0xC009)  // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	cbcSha256 := uint16(0xC023) // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

	cases := []struct {
		profile string
		suite   uint16
		wantOK  bool
		note    string
	}{
		{"moderate", aead, true, "moderate serves AEAD"},
		{"moderate", cbcSha1, true, "moderate serves CBC-SHA1"},
		{"moderate", cbcSha256, false, "moderate rejects CBC-SHA256"},
		{"strong", aead, true, "strong serves AEAD"},
		{"strong", cbcSha1, false, "strong rejects CBC-SHA1"},
		{"strong", cbcSha256, false, "strong rejects CBC-SHA256"},
		{"compatible", aead, true, "compatible serves AEAD"},
		{"compatible", cbcSha1, true, "compatible serves CBC-SHA1"},
		{"compatible", cbcSha256, true, "compatible serves CBC-SHA256"},
		{"", aead, true, "default profile serves AEAD"},
		{"", cbcSha256, false, "default profile rejects CBC-SHA256"},
	}
	for _, tc := range cases {
		addr := startTLSProfileSite(t, tc.profile)
		err := handshakeWith(addr, tc.suite)
		if tc.wantOK && err != nil {
			t.Errorf("profile=%q suite=0x%04X (%s): expected success, got %v", tc.profile, tc.suite, tc.note, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("profile=%q suite=0x%04X (%s): expected rejection, handshake succeeded", tc.profile, tc.suite, tc.note)
		}
	}
}

// ensure the probe suites are actually supported by this Go runtime
func TestGoRuntimeHasProbeSuites(t *testing.T) {
	known := map[uint16]bool{}
	for _, cs := range tls.CipherSuites() {
		known[cs.ID] = true
	}
	for _, cs := range tls.InsecureCipherSuites() {
		known[cs.ID] = true
	}
	for _, id := range []uint16{0xC02B, 0xC009, 0xC023} {
		if !known[id] {
			t.Fatalf("probe suite 0x%04X unsupported by Go runtime", id)
		}
	}
}
