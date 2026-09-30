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
	"strings"
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
// do, and an absent directory yields an empty list. The internal RSA
// handshake slot (`<name>+rsa`) stays listed as-is - that is a locked
// decision: the whitelist consumer treats it as a never-matching redundant
// member, and it is the renewal target collection that filters it.
func TestCachedHosts(t *testing.T) {
	dir := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "b.local"), genTestCertPEM(t, []string{"b.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.local"), genTestCertPEM(t, []string{"a.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.local"+rsaCacheKeySuffix), genTestCertPEM(t, []string{"a.local"}, far), 0o600); err != nil {
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
	if !reflect.DeepEqual(got, []string{"a.local", "a.local" + rsaCacheKeySuffix, "b.local"}) {
		t.Fatalf("CachedHosts = %v, want [a.local a.local+rsa b.local] (sorted, garbage skipped, +rsa kept as-is)", got)
	}
	if got := CachedHosts(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("CachedHosts(missing dir) = %v, want nil", got)
	}
}

// TestCacheEntries covers the cert-library listing: production entries read
// from the base directory, staging entries from the sibling directory, the
// validity split at the 30-day renewal window, metadata parsing, and the
// RSA-variant slot shown under its plain domain with variant=rsa next to
// the ecdsa entry of the same domain.
func TestCacheEntries(t *testing.T) {
	base := t.TempDir()
	far := time.Now().Add(90 * 24 * time.Hour)
	soon := time.Now().Add(10 * 24 * time.Hour)
	if err := os.WriteFile(filepath.Join(base, "prod.local"), genTestCertPEM(t, []string{"prod.local"}, far), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "prod.local"+rsaCacheKeySuffix), genTestCertPEM(t, []string{"prod.local"}, far), 0o600); err != nil {
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
	if len(entries) != 3 {
		t.Fatalf("CacheEntries = %d entries (%v), want 3", len(entries), entries)
	}
	prod := entries[0]
	if prod.Domain != "prod.local" || prod.Staging || prod.Variant != "ecdsa" {
		t.Fatalf("first entry = %+v, want prod.local (production, ecdsa)", prod)
	}
	if prod.Status != "valid" || prod.NotAfter == "" || prod.NotBefore == "" {
		t.Fatalf("prod entry = %+v, want valid with parsed dates", prod)
	}
	rsaSlot := entries[1]
	if rsaSlot.Domain != "prod.local" || rsaSlot.Variant != "rsa" || rsaSlot.Staging {
		t.Fatalf("second entry = %+v, want prod.local (production, rsa variant, no + in domain)", rsaSlot)
	}
	if rsaSlot.NotAfter == "" || rsaSlot.Subject == "" || rsaSlot.Issuer == "" {
		t.Fatalf("rsa entry metadata not parsed: %+v", rsaSlot)
	}
	if strings.Contains(rsaSlot.Domain, "+") {
		t.Fatalf("internal cache key leaked into Domain: %q", rsaSlot.Domain)
	}
	stag := entries[2]
	if stag.Domain != "stag.local" || !stag.Staging || stag.Variant != "ecdsa" {
		t.Fatalf("third entry = %+v, want stag.local (staging, ecdsa)", stag)
	}
	if stag.Status != "expiring" {
		t.Fatalf("staging entry status = %q, want expiring (10 days left)", stag.Status)
	}

	// An empty base (no directories at all) lists nothing.
	if got := CacheEntries(t.TempDir()); len(got) != 0 {
		t.Fatalf("CacheEntries(empty) = %v, want none", got)
	}
}
