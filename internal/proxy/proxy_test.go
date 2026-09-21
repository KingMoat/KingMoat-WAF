package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fixedStage struct {
	name string
	v    pipeline.Verdict
}

func (s fixedStage) Name() string { return s.name }
func (s fixedStage) Inspect(_ context.Context, _ *pipeline.RequestContext) pipeline.Verdict {
	return s.v
}

func proxyConfig(upstreamAddr string) *config.Config {
	return &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{
			{
				Domains:  []string{"example.com"},
				Mode:     "intercept",
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: upstreamAddr}}},
			},
			{
				Domains:  []string{"monitor.example.com"},
				Mode:     "monitor",
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: upstreamAddr}}},
			},
		},
	}
}

func TestForwardPreservesHostAndSetsForwardedHeaders(t *testing.T) {
	var gotHost, gotXFF, gotTrace string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotTrace = r.Header.Get("X-KingMoat-Trace-Id")
		fmt.Fprintf(w, "up:%s", r.URL.Path)
	}))
	defer up.Close()

	h, err := New(proxyConfig(strings.TrimPrefix(up.URL, "http://")), nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/foo/bar", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "up:/foo/bar" {
		t.Fatalf("body = %q, want up:/foo/bar", got)
	}
	if gotHost != "example.com" {
		t.Fatalf("upstream Host = %q, want example.com", gotHost)
	}
	if gotXFF == "" {
		t.Fatal("X-Forwarded-For was not set")
	}
	if gotTrace == "" {
		t.Fatal("X-KingMoat-Trace-Id was not set")
	}
}

func TestUnknownSiteDenied(t *testing.T) {
	h, err := New(proxyConfig("127.0.0.1:1"), nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://other.example.org/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Header().Get("X-KingMoat-Action") != "blocked" {
		t.Fatalf("X-KingMoat-Action = %q, want blocked", rec.Header().Get("X-KingMoat-Action"))
	}
}

func TestDenyStageBlocksInterceptSite(t *testing.T) {
	h, err := New(proxyConfig("127.0.0.1:1"),
		pipeline.New(fixedStage{name: "acl/test", v: pipeline.Deny("acl/test", "denied for test")}),
		nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Header().Get("X-KingMoat-Rule") != "acl/test" {
		t.Fatalf("X-KingMoat-Rule = %q, want acl/test", rec.Header().Get("X-KingMoat-Rule"))
	}
	if rec.Header().Get("X-KingMoat-Trace-Id") == "" {
		t.Fatal("X-KingMoat-Trace-Id missing on block page")
	}
	// Reason is intentionally not rendered to the client (log/audit only).
	if strings.Contains(rec.Body.String(), "denied for test") {
		t.Fatal("block page must not leak the internal reason")
	}
	if !strings.Contains(rec.Body.String(), "请求被拦截") {
		t.Fatalf("block page marker missing, got %q", rec.Body.String())
	}
}

func TestMonitorModeForwardsOnDeny(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "up:/")
	}))
	defer up.Close()

	h, err := New(proxyConfig(strings.TrimPrefix(up.URL, "http://")),
		pipeline.New(fixedStage{name: "acl/test", v: pipeline.Deny("acl/test", "denied for test")}),
		nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://monitor.example.com/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 in monitor mode", rec.Code)
	}
	if got := rec.Body.String(); got != "up:/" {
		t.Fatalf("body = %q, want up:/", got)
	}
}

func TestUpstreamFailureReturns502(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(up.URL, "http://")
	up.Close() // guarantee connection refused

	h, err := New(proxyConfig(addr), nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if rec.Header().Get("X-KingMoat-Upstream-Error") != "true" {
		t.Fatal("X-KingMoat-Upstream-Error header missing")
	}
}

// TestUpstream502RendersCenteredPage verifies the handler-level contract of
// the friendly 502 page: status 502, HTML content type, the exact copy, the
// centered-page markers and the preserved upstream-error header.
func TestUpstream502RendersCenteredPage(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(up.URL, "http://")
	up.Close() // guarantee connection refused

	h, err := New(proxyConfig(addr), nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/app?q=1", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if rec.Header().Get("X-KingMoat-Upstream-Error") != "true" {
		t.Fatal("X-KingMoat-Upstream-Error header must be preserved")
	}
	body := rec.Body.String()
	for _, want := range []string{
		"暂时无法访问该站点",
		"当前站点无法连接上游资源，请联系站点管理员处理",
		"class=\"card\"",
		"KingMoat WAF",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("502 page missing %q in body: %s", want, body)
		}
	}
	// The WAF handler stamps a trace id on the request before forwarding;
	// the page renders it in the monospace detail row.
	if !strings.Contains(body, "Trace <span class=\"rule\">") || !strings.Contains(body, "/app?q=1") {
		t.Fatal("502 page must render the request/trace detail line")
	}
}

func TestSNICertificateSelection(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "secure.example.com")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := proxyConfig("127.0.0.1:1")
	cfg.Sites = append(cfg.Sites, config.Site{
		Domains:  []string{"secure.example.com"},
		TLSCert:  certPath,
		TLSKey:   keyPath,
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:1"}}},
	})
	h, err := New(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cert, err := h.state.Load().router.CertificateFor(&tls.ClientHelloInfo{ServerName: "secure.example.com"})
	if err != nil {
		t.Fatalf("CertificateFor(secure.example.com): %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "secure.example.com" {
		t.Fatalf("unexpected certificate CN: %+v", cert.Leaf)
	}
	if _, err := h.state.Load().router.CertificateFor(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("want error for unknown SNI, got nil")
	}
}

func TestRoundRobinPool(t *testing.T) {
	pool, err := NewPool(config.Upstream{Nodes: []config.UpstreamNode{
		{Address: "127.0.0.1:1"}, {Address: "127.0.0.1:2"},
	}}, nil, "t", nil)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		seen[pool.Next().Port()]++
	}
	if pool.Len() != 2 || seen["1"] != 2 || seen["2"] != 2 {
		t.Fatalf("round-robin distribution wrong: %v (len=%d)", seen, pool.Len())
	}
}

func genSelfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
