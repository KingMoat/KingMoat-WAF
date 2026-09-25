package certmgr

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// genTestCertPEM returns a self-signed certificate PEM for the given DNS
// names with the requested expiry (cache fixtures).
func genTestCertPEM(t *testing.T, domains []string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     domains,
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCacheDirFor(t *testing.T) {
	if got := cacheDirFor("acme-cache", false); got != "acme-cache" {
		t.Fatalf("cacheDirFor(prod) = %q, want acme-cache", got)
	}
	if got := cacheDirFor("acme-cache", true); got != "acme-cache-staging" {
		t.Fatalf("cacheDirFor(staging) = %q, want acme-cache-staging", got)
	}
}

// TestCachedHosts covers the directory scan: valid certificate entries
// surface as domains, the autocert account key and unparseable files never
// do, and an absent directory yields an empty list.
func TestCachedHosts(t *testing.T) {
	dir := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "b.local"), genTestCertPEM(t, []string{"b.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.local"), genTestCertPEM(t, []string{"a.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acmeAccountKeyFile), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.local"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}

	got := CachedHosts(dir)
	if !reflect.DeepEqual(got, []string{"a.local", "b.local"}) {
		t.Fatalf("CachedHosts = %v, want [a.local b.local] (sorted, garbage skipped)", got)
	}
	if got := CachedHosts(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("CachedHosts(missing dir) = %v, want nil", got)
	}
}

// TestCacheEntries covers the cert-library listing: production entries read
// from the base directory, staging entries from the sibling directory, the
// validity split at the 30-day renewal window, and metadata parsing.
func TestCacheEntries(t *testing.T) {
	base := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	soon := time.Now().Add(10 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(base, "prod.local"), genTestCertPEM(t, []string{"prod.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	stagingDir := cacheDirFor(base, true)
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "stag.local"), genTestCertPEM(t, []string{"stag.local"}, soon), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := CacheEntries(base)
	if len(entries) != 2 {
		t.Fatalf("CacheEntries = %d entries (%v), want 2", len(entries), entries)
	}
	prod := entries[0]
	if prod.Domain != "prod.local" || prod.Staging {
		t.Fatalf("first entry = %+v, want prod.local (production)", prod)
	}
	if prod.Status != "valid" || prod.NotAfter == "" || prod.NotBefore == "" {
		t.Fatalf("prod entry = %+v, want valid with parsed dates", prod)
	}
	stag := entries[1]
	if stag.Domain != "stag.local" || !stag.Staging {
		t.Fatalf("second entry = %+v, want stag.local (staging)", stag)
	}
	if stag.Status != "expiring" {
		t.Fatalf("staging entry status = %q, want expiring (10 days left)", stag.Status)
	}

	// An empty base (no directories at all) lists nothing.
	if got := CacheEntries(t.TempDir()); len(got) != 0 {
		t.Fatalf("CacheEntries(empty) = %v, want none", got)
	}
}
