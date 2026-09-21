package consoletls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmpLibrary(t *testing.T) (root, state string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "uploads", "certs")
	state = base
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	return root, state
}

// genLibPair writes an additional library entry with the given CN.
func genLibPair(t *testing.T, root, name, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapSelfSignedIntoLibrary(t *testing.T) {
	root, state := tmpLibrary(t)
	m, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1"})
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed entry lives inside the library → certificate page sees it.
	if _, err := os.Stat(filepath.Join(root, selfSignedName, "cert.pem")); err != nil {
		t.Fatalf("self-signed entry missing from library: %v", err)
	}
	in := m.Current()
	if !in.TLSEnabled || in.CertName != selfSignedName || in.Source != "self-signed" {
		t.Fatalf("current = %+v", in)
	}
	if in.Subject == "" || in.Fingerprint == "" || in.NotAfter == "" {
		t.Fatalf("info incomplete: %+v", in)
	}
	if m.Certificate() == nil {
		t.Fatal("no tls.Certificate published")
	}
	// Second boot: reused, not regenerated (same fingerprint).
	in1 := m.Current()
	m2, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Current().Fingerprint != in1.Fingerprint {
		t.Fatal("self-signed regenerated on second boot")
	}
}

func TestApplyFromLibraryHotSwapAndPersist(t *testing.T) {
	root, state := tmpLibrary(t)
	genLibPair(t, root, "official-cert", "console.example.com")
	m, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyFromLibrary("official-cert"); err != nil {
		t.Fatal(err)
	}
	in := m.Current()
	if in.CertName != "official-cert" || in.Source != "library" || in.Subject != "console.example.com" {
		t.Fatalf("after apply = %+v", in)
	}
	if !strings.Contains(m.Certificate().Leaf.Subject.CommonName, "console.example.com") {
		t.Fatal("tls.Certificate not swapped")
	}
	// Selection persists: a fresh manager boots straight onto the library cert.
	m2, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Current().CertName != "official-cert" {
		t.Fatalf("persisted selection lost: %+v", m2.Current())
	}
}

func TestApplyRejectsUnknownAndInvalidNames(t *testing.T) {
	root, state := tmpLibrary(t)
	m, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyFromLibrary("does-not-exist"); err == nil {
		t.Fatal("unknown entry accepted")
	}
	if err := m.ApplyFromLibrary("../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
	// Fallback intact: still serving the self-signed default.
	if m.Current().CertName != selfSignedName {
		t.Fatalf("current changed after failed apply: %+v", m.Current())
	}
}

func TestPinnedFlagAndUnavailableFallback(t *testing.T) {
	root, state := tmpLibrary(t)
	genLibPair(t, root, "pinned", "pinned.local")
	m, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1", PinnedName: "pinned"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Current().CertName != "pinned" {
		t.Fatalf("pinned not honored: %+v", m.Current())
	}
	// Pinned entry disappears later → boot falls back to self-signed.
	if err := os.RemoveAll(filepath.Join(root, "pinned")); err != nil {
		t.Fatal(err)
	}
	m2, err := New(Options{LibraryRoot: root, StateDir: state, Listen: ":8443", Host: "mp-1", PinnedName: "pinned"})
	if err != nil {
		t.Fatalf("fallback boot failed: %v", err)
	}
	if m2.Current().CertName != selfSignedName || m2.Current().Source != "self-signed" {
		t.Fatalf("fallback = %+v", m2.Current())
	}
}
