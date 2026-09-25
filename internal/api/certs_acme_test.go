package api

import (
	"context"
	crand "crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/certmgr"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
)

// longLivedCertPEM returns a self-signed certificate for domain valid for d
// (cache fixtures with controllable expiry).
func longLivedCertPEM(t *testing.T, domain string, d time.Duration) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(d),
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// acmeSeed returns a config with BOTH global listeners set (the ACME request
// prerequisite) and one non-ACME site.
func acmeSeed() *config.Config {
	return &config.Config{
		ListenHTTP:  ":8080",
		ListenHTTPS: ":8443",
		Sites: []config.Site{{
			Domains:  []string{"a.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9001"}}},
		}},
	}
}

// acmeServer builds a console API with the certificate-library ACME service
// wired to a fake issuer (no network). Returns the server and the service's
// cache base directory (for direct cache fixtures).
func acmeServer(t *testing.T, seed *config.Config, issue certmgr.IssueFunc) (*httptest.Server, string) {
	t.Helper()
	center, err := configcenter.Open(t.TempDir()+"/acme.db", seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	holder := certmgr.NewACMEHolder(t.TempDir())
	svc := certmgr.NewService(holder, nil, certmgr.WithIssuer(issue))
	srv := New(Options{SkipBootstrap: true, Center: center, ACME: svc})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, holder.BaseDir()
}

// fakeIssueOK returns a fake issuer succeeding with a real parsed certificate.
func fakeIssueOK(t *testing.T) certmgr.IssueFunc {
	return func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
		certPEM, _ := genTestPair(t)
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, errors.New("bad fixture")
		}
		return x509.ParseCertificate(block.Bytes)
	}
}

// waitStatus polls the status endpoint until the task reaches want.
func waitStatus(t *testing.T, ts *httptest.Server, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ts.URL + "/api/certs/acme/request?id=" + id)
		if err != nil {
			t.Fatal(err)
		}
		var task map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&task)
		resp.Body.Close()
		if task["status"] == want {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s in time", id, want)
	return nil
}

// TestACMERequestPrerequisites covers the two request-time rejections the
// card requires: missing global listeners and a malformed domain.
func TestACMERequestPrerequisites(t *testing.T) {
	noHTTPS := acmeSeed()
	noHTTPS.ListenHTTPS = ""
	ts, _ := acmeServer(t, noHTTPS, fakeIssueOK(t))
	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/certs/acme/request",
		map[string]any{"domain": "ok.local"})
	if code != http.StatusBadRequest {
		t.Fatalf("request without listen_https = %d, want 400", code)
	}
	if msg, _ := body["error"].(string); msg == "" || body["error"] == "listen_https" {
		t.Fatalf("prerequisite error = %v, want friendly guidance", body["error"])
	}

	ts2, _ := acmeServer(t, acmeSeed(), fakeIssueOK(t))
	code, body = doJSONBody(t, http.DefaultClient, "POST", ts2.URL+"/api/certs/acme/request",
		map[string]any{"domain": "*.wild.local"})
	if code != http.StatusBadRequest {
		t.Fatalf("wildcard request = %d, want 400", code)
	}
	if msg, _ := body["error"].(string); msg == "" {
		t.Fatalf("wildcard error body = %v", body)
	}

	code, _ = doJSONBody(t, http.DefaultClient, "POST", ts2.URL+"/api/certs/acme/request",
		map[string]any{"domain": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("empty domain = %d, want 400", code)
	}
}

// TestACMERequestLifecycle covers the happy path end to end over HTTP:
// 202 with a task id, status polling to success, unknown/missing ids.
func TestACMERequestLifecycle(t *testing.T) {
	ts, _ := acmeServer(t, acmeSeed(), fakeIssueOK(t))

	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/certs/acme/request",
		map[string]any{"domain": "km.example.com", "email": "ops@example.com", "staging": true})
	if code != http.StatusAccepted {
		t.Fatalf("submit = %d: %v", code, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("submit response missing id: %v", body)
	}
	if v, _ := body["staging"].(bool); !v {
		t.Fatalf("submit response staging flag = %v", body["staging"])
	}

	task := waitStatus(t, ts, id, "success")
	if task["not_after"] == "" {
		t.Fatalf("success task without not_after: %v", task)
	}

	// Single-flight over HTTP is covered in certmgr; here the unknown and
	// missing-id paths.
	resp, err := http.Get(ts.URL + "/api/certs/acme/request?id=does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", resp.StatusCode)
	}
	resp2, err := http.Get(ts.URL + "/api/certs/acme/request")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing id = %d, want 400", resp2.StatusCode)
	}
}

// TestACMERequestCooldownHTTP covers the 429 mapping after a failed attempt.
func TestACMERequestCooldownHTTP(t *testing.T) {
	ts, _ := acmeServer(t, acmeSeed(), func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
		return nil, errors.New("acme: network unreachable")
	})
	code, _ := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/certs/acme/request",
		map[string]any{"domain": "fail.local"})
	if code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202", code)
	}
	// The failure path is fast; poll until the cooldown is armed.
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/certs/acme/request",
			map[string]any{"domain": "fail.local"})
		if code == http.StatusTooManyRequests {
			if msg, _ := body["error"].(string); msg == "" {
				t.Fatalf("cooldown error body = %v", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("request never hit cooldown (last=%d)", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestACMEEntriesHTTP covers the cert-library listing endpoint: empty for a
// fresh cache, and populated from files written into the cache directories
// (production vs staging flag).
func TestACMEEntriesHTTP(t *testing.T) {
	ts, base := acmeServer(t, acmeSeed(), fakeIssueOK(t))

	resp, err := http.Get(ts.URL + "/api/certs/acme/entries")
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&entries)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(entries) != 0 {
		t.Fatalf("fresh entries = %d (%v), want 200 empty", resp.StatusCode, entries)
	}

	// Populate the production and staging caches with test certificates.
	certPEM := longLivedCertPEM(t, "prod.local", 90*24*time.Hour)
	if err := os.WriteFile(filepath.Join(base, "prod.local"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base+"-staging", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base+"-staging", "stag.local"), longLivedCertPEM(t, "stag.local", 90*24*time.Hour), 0o600); err != nil {
		t.Fatal(err)
	}

	resp2, err := http.Get(ts.URL + "/api/certs/acme/entries")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	entries = nil
	if err := json.NewDecoder(resp2.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %v, want 2", entries)
	}
	byDomain := map[string]map[string]any{}
	for _, e := range entries {
		byDomain[e["domain"].(string)] = e
	}
	p, ok := byDomain["prod.local"]
	if !ok || p["staging"] == true || p["status"] != "valid" {
		t.Fatalf("prod entry = %v", p)
	}
	st, ok := byDomain["stag.local"]
	if !ok || st["staging"] != true || st["status"] != "valid" {
		t.Fatalf("staging entry = %v", st)
	}
}
