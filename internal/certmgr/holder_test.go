// T-02 holder tests: dual-slot facades, the dynamic request-first whitelist
// and the challenge routing between the production and staging slots.
package certmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kingmoat/kingmoat/internal/config"
)

// ecdsaCapableHello builds a synthetic handshake the way an ECDSA-capable
// client would offer it (autocert keys the cache lookup by key type).
func ecdsaCapableHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       domain,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
}

// cacheFixture writes a DirCache entry (private key block first, then the
// certificate chain — autocert's cache layout) valid for domain under the
// given cache key name, and returns the leaf DER.
func cacheFixture(t *testing.T, dir, name, domain string) []byte {
	t.Helper()
	certPath, keyPath, err := EnsureSelfSigned(t.TempDir(), domain)
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(append([]byte{}, keyPEM...), certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("fixture without CERTIFICATE block")
	}
	return block.Bytes
}

// TestRequestFirstDynamicWhitelist covers the request-first flow end to end:
// a domain with no site and no cached certificate is registered by
// Service.Request, the default issueFn resolves the matching slot manager
// lazily (dynamic HostPolicy allows the pending domain), and after the
// issuance outcome lands in the cache a rebuild keeps serving it through the
// facade.
func TestRequestFirstDynamicWhitelist(t *testing.T) {
	base := t.TempDir()
	holder := NewACMEHolder(base)
	var mu sync.Mutex
	var flags []bool
	s := NewService(holder, nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			flags = append(flags, staging)
			mu.Unlock()
			return okLeaf(t, domain), nil
		}))

	task, err := s.Request("fresh.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, task.ID, TaskSuccess)
	mu.Lock()
	if len(flags) != 1 || flags[0] {
		mu.Unlock()
		t.Fatalf("issuer staging flags = %v, want [false]", flags)
	}
	mu.Unlock()

	// What defaultIssue resolves: the prod slot manager, built lazily around
	// the registration — the pending domain is allowed, everything else is
	// not, and the manager owns the production cache directory.
	m := holder.slotFor("fresh.local", false, "")
	if m == nil {
		t.Fatal("slotFor(fresh.local, prod) = nil, want lazily built manager")
	}
	if err := m.HostPolicy(context.Background(), "fresh.local"); err != nil {
		t.Fatalf("HostPolicy(fresh.local) = %v, want allowed while registered", err)
	}
	if err := m.HostPolicy(context.Background(), "other.local"); err == nil {
		t.Fatal("HostPolicy(other.local) = nil, want rejected")
	}
	if m.Cache.(autocert.DirCache) != autocert.DirCache(base) {
		t.Fatalf("prod slot cache = %v, want %s", m.Cache, base)
	}
	if m.Client != nil {
		t.Fatalf("prod manager client = %+v, want nil (production directory)", m.Client)
	}

	// Rebuild (restart / publish simulation): the still-uncovered
	// registration survives and the whitelist keeps allowing the domain.
	if prod, staging := holder.Rebuild(&config.Config{}, ""); prod == nil || staging != nil {
		t.Fatalf("Rebuild = (%v, %v), want prod manager only", prod, staging)
	}
	if err := holder.Prod().HostPolicy(context.Background(), "fresh.local"); err != nil {
		t.Fatalf("HostPolicy after rebuild = %v, want allowed via registration", err)
	}

	// The issuance outcome persists (what the real defaultIssue writes
	// through autocert): the cache entry covers the domain, the next rebuild
	// prunes the registration, and the facade serves the certificate.
	cacheFixture(t, base, "fresh.local", "fresh.local")
	if prod, _ := holder.Rebuild(&config.Config{}, ""); prod == nil {
		t.Fatal("Rebuild after cache landing = nil prod manager")
	}
	if err := holder.Prod().HostPolicy(context.Background(), "fresh.local"); err != nil {
		t.Fatalf("HostPolicy after cache landing = %v, want allowed via cached entry", err)
	}
	cert, err := holder.GetCertificate(ecdsaCapableHello("fresh.local"))
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate after rebuild = (%v, %v), want cached certificate", cert, err)
	}
}

// TestStagingIsolation pins the slot split: the issueFn receives the exact
// staging flag per request, each mode's manager owns its own cache directory
// and CA endpoint, and after a rebuild neither whitelist covers the other
// slot's domains.
func TestStagingIsolation(t *testing.T) {
	base := t.TempDir()
	holder := NewACMEHolder(base)
	type issueCall struct {
		domain  string
		email   string
		staging bool
	}
	var mu sync.Mutex
	var calls []issueCall
	s := NewService(holder, nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			mu.Lock()
			calls = append(calls, issueCall{domain: domain, email: email, staging: staging})
			mu.Unlock()
			return okLeaf(t, domain), nil
		}))

	t1, err := s.Request("iso-stag.local", "team@x.io", true)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, t1.ID, TaskSuccess)
	t2, err := s.Request("iso-prod.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, t2.ID, TaskSuccess)

	mu.Lock()
	if len(calls) != 2 || calls[0].domain != "iso-stag.local" || !calls[0].staging || calls[0].email != "team@x.io" ||
		calls[1].domain != "iso-prod.local" || calls[1].staging {
		mu.Unlock()
		t.Fatalf("issueFn calls = %+v, want staging/prod flags and emails routed as requested", calls)
	}
	mu.Unlock()

	// Slot routing by the staging parameter: staging owns the -staging
	// directory and the staging CA, production owns the base directory.
	stag := holder.slotFor("iso-stag.local", true, "team@x.io")
	if stag == nil {
		t.Fatal("slotFor(staging) = nil")
	}
	if stag.Cache.(autocert.DirCache) != autocert.DirCache(cacheDirFor(base, true)) {
		t.Fatalf("staging slot cache = %v, want %s", stag.Cache, cacheDirFor(base, true))
	}
	if stag.Client == nil || stag.Client.DirectoryURL != stagingDirectoryURL {
		t.Fatalf("staging client = %+v, want staging directory URL", stag.Client)
	}
	prodm := holder.slotFor("iso-prod.local", false, "")
	if prodm.Cache.(autocert.DirCache) != autocert.DirCache(base) {
		t.Fatalf("prod slot cache = %v, want %s", prodm.Cache, base)
	}
	if prodm.Client != nil {
		t.Fatalf("prod client = %+v, want nil", prodm.Client)
	}

	// Rebuild: each whitelist covers only its own slot's domains.
	holder.Rebuild(&config.Config{}, "")
	ctx := context.Background()
	if err := holder.Staging().HostPolicy(ctx, "iso-stag.local"); err != nil {
		t.Fatalf("staging HostPolicy(iso-stag.local) = %v, want allowed", err)
	}
	if err := holder.Staging().HostPolicy(ctx, "iso-prod.local"); err == nil {
		t.Fatal("staging whitelist must not cover the prod-issued domain")
	}
	if err := holder.Prod().HostPolicy(ctx, "iso-prod.local"); err != nil {
		t.Fatalf("prod HostPolicy(iso-prod.local) = %v, want allowed", err)
	}
	if err := holder.Prod().HostPolicy(ctx, "iso-stag.local"); err == nil {
		t.Fatal("prod whitelist must not cover the staging-issued domain")
	}
}

// TestChallengeTokenRoutingOrder pins the TLS-ALPN-01 dispatch across both
// slots: token lookups are memory + DirCache reads only (autocert also
// consults its cache directory for token certs, key "<domain>+token"), so
// fixtures exercise the real lookup path. Production answers first when both
// slots hold a token for the domain; a production miss falls through to the
// staging token.
func TestChallengeTokenRoutingOrder(t *testing.T) {
	base := t.TempDir()
	holder := NewACMEHolder(base)
	cfg := &config.Config{Sites: []config.Site{
		{Domains: []string{"prod.local"}, ACME: &config.ACMESettings{}},
		{Domains: []string{"stag.local"}, ACME: &config.ACMESettings{Staging: true}},
	}}
	holder.Rebuild(cfg, "")

	prodDER := cacheFixture(t, base, "dual.local+token", "dual.local")
	stagingDir := cacheDirFor(base, true)
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stagDER := cacheFixture(t, stagingDir, "dual.local+token", "dual.local")

	hello := &tls.ClientHelloInfo{ServerName: "dual.local", SupportedProtos: []string{acme.ALPNProto}}

	// Both slots hold a token: production answers (routing order).
	cert, err := holder.GetCertificate(hello)
	if err != nil || cert == nil {
		t.Fatalf("challenge with both tokens = (%v, %v), want the production token cert", cert, err)
	}
	if !bytes.Equal(cert.Certificate[0], prodDER) {
		t.Fatal("challenge answered by the staging token, want production first")
	}

	// Production miss: the staging token takes over.
	if err := os.Remove(filepath.Join(base, "dual.local+token")); err != nil {
		t.Fatal(err)
	}
	cert, err = holder.GetCertificate(hello)
	if err != nil || cert == nil {
		t.Fatalf("challenge after prod miss = (%v, %v), want the staging token cert", cert, err)
	}
	if !bytes.Equal(cert.Certificate[0], stagDER) {
		t.Fatal("challenge after prod miss answered with the wrong token cert")
	}

	// Both miss: the autocert token-miss error surfaces.
	if err := os.Remove(filepath.Join(stagingDir, "dual.local+token")); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.GetCertificate(hello); err == nil || !bytes.Contains([]byte(err.Error()), []byte("no token cert")) {
		t.Fatalf("challenge with no token = %v, want autocert token-cert miss", err)
	}
}

// TestHTTPChallengeDualSlotRouting pins the port-80 dispatch: the challenge
// path is served by the manager knowledge routes it to (autocert's
// HTTPHandler 403s hosts outside its own policy BEFORE the token lookup, so
// the routing must pick the right slot up front), and every other path falls
// through to the data plane.
func TestHTTPChallengeDualSlotRouting(t *testing.T) {
	base := t.TempDir()
	holder := NewACMEHolder(base)
	cfg := &config.Config{Sites: []config.Site{
		{Domains: []string{"prod.local"}, ACME: &config.ACMESettings{}},
		{Domains: []string{"stag.local"}, ACME: &config.ACMESettings{Staging: true}},
	}}
	holder.Rebuild(cfg, "")

	// http-01 token fixture in the staging slot's cache directory
	// (autocert stores tokens under "<token>+http-01").
	stagingDir := cacheDirFor(base, true)
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "tok123+http-01"), []byte("tok-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "DATA") })
	h := holder.HTTPHandler(data)

	// Staging site host: routed to the staging manager, which holds the token.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://stag.local/.well-known/acme-challenge/tok123", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "tok-value" {
		t.Fatalf("staging challenge = (%d, %q), want 200 with the token value", rec.Code, rec.Body.String())
	}

	// Production site host: routed to the production manager — its own token
	// store misses (404); the staging token is never consulted cross-slot.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://prod.local/.well-known/acme-challenge/tok123", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("prod challenge = %d, want 404 token miss from the production slot", rec.Code)
	}

	// Unknown host: routed to the production manager → HostPolicy 403.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://other.local/.well-known/acme-challenge/tok123", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown-host challenge = %d, want 403 HostPolicy rejection", rec.Code)
	}

	// Plain path: data plane, untouched.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://stag.local/", nil))
	if rec.Body.String() != "DATA" {
		t.Fatalf("plain path body = %q, want data plane response", rec.Body.String())
	}
}

// TestCooldownKeepsWhitelist pins the card decision: a failed issuance keeps
// its domain whitelisted until the failure cooldown ends (bounded), and the
// slot disables cleanly once the cooldown expires with nothing else left.
func TestCooldownKeepsWhitelist(t *testing.T) {
	base := t.TempDir()
	holder := NewACMEHolder(base)
	s := NewService(holder, nil, WithIssuer(
		func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
			return nil, errors.New("acme: boom")
		}))
	task, err := s.Request("cd.local", "", false)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, task.ID, TaskFailed)

	if !holder.registered(false, "cd.local") {
		t.Fatal("failed domain must stay registered during the cooldown")
	}
	// A rebuild during the cooldown keeps the manager alive and the domain
	// issuable (a retry after the cooldown re-registers and passes).
	if prod, _ := holder.Rebuild(&config.Config{}, ""); prod == nil {
		t.Fatal("rebuild during cooldown must keep a manager (active registration)")
	}
	if err := holder.Prod().HostPolicy(context.Background(), "cd.local"); err != nil {
		t.Fatalf("HostPolicy during cooldown = %v, want allowed", err)
	}

	// After the cooldown the entry goes inert and the next rebuild drops it;
	// with nothing else in the slot the manager disables cleanly.
	holder.mu.Lock()
	holder.registry[0]["cd.local"] = time.Now().Add(-time.Second)
	holder.mu.Unlock()
	if holder.registered(false, "cd.local") {
		t.Fatal("expired cooldown entry must not whitelist")
	}
	if prod, _ := holder.Rebuild(&config.Config{}, ""); prod != nil {
		t.Fatal("slot with nothing left must disable after the cooldown")
	}
}
