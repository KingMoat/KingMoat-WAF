package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// genSelfSignedCert writes an ECDSA self-signed cert/key pair for cn.
func genSelfSignedCert(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
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
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, cn+".crt")
	keyPath = filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func redirectTestCfg(listenHTTPS, cert, key string) *config.Config {
	return &config.Config{
		ListenHTTP:  ":0",
		ListenHTTPS: listenHTTPS,
		Sites: []config.Site{
			{
				Domains:         []string{"a.local"},
				Upstream:        config.Upstream{Nodes: []config.UpstreamNode{{Address: "up.local:9000"}}},
				TLSCert:         cert,
				TLSKey:          key,
				RedirectToHTTPS: true,
			},
			{
				Domains:  []string{"b.local"},
				Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "up.local:9000"}}},
			},
		},
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	dir := t.TempDir()
	cert, key := genSelfSignedCert(t, dir, "a.local")

	h, err := NewReloadable(redirectTestCfg(":8443", cert, key), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	// 1. plain HTTP request → 308 with the HTTPS target (port from listen_https).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://a.local/x?y=1", nil))
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://a.local:8443/x?y=1" {
		t.Fatalf("Location = %q, want https://a.local:8443/x?y=1", loc)
	}

	// 2. request Host carrying a port → stripped in the Location target.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://a.local/x", nil)
	req.Host = "a.local:8080"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://a.local:8443/x" {
		t.Fatalf("Location = %q, want https://a.local:8443/x", loc)
	}

	// 3. ACME HTTP-01 path is exempt and forwarded instead.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://a.local/.well-known/acme-challenge/token123", nil))
	if rec.Code == http.StatusPermanentRedirect {
		t.Fatalf("ACME path must not be redirected")
	}

	// 4. sites without the flag keep forwarding over HTTP.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://b.local/", nil))
	if rec.Code == http.StatusPermanentRedirect {
		t.Fatalf("b.local must not be redirected")
	}

	// 5. a request already on the HTTPS listener (r.TLS set) is not redirected.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "http://a.local/x", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusPermanentRedirect {
		t.Fatalf("HTTPS requests must not be redirected")
	}
}

func TestRedirectTargetDefaultPortOmitted(t *testing.T) {
	dir := t.TempDir()
	cert, key := genSelfSignedCert(t, dir, "a.local")

	// listen_https on :443 → Location without an explicit port.
	h, err := NewReloadable(redirectTestCfg(":443", cert, key), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://a.local/a/b?q=2", nil))
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://a.local/a/b?q=2" {
		t.Fatalf("Location = %q, want https://a.local/a/b?q=2", loc)
	}
}

func TestRedirectPOSTKeepsMethod308(t *testing.T) {
	// 308 preserves the method and body; verify via a real upstream round trip.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "method="+r.Method)
	}))
	defer up.Close()

	dir := t.TempDir()
	cert, key := genSelfSignedCert(t, dir, "a.local")
	cfg := redirectTestCfg(":443", cert, key)
	cfg.Sites[0].Upstream = config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}}

	h, err := NewReloadable(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "http://a.local/.well-known/acme-challenge/t", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ACME POST status = %d, want 200 forwarded", rec.Code)
	}
}

func trimScheme(u string) string {
	for _, p := range []string{"http://", "https://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}
