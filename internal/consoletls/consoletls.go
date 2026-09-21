// Package consoletls manages the management-plane console TLS certificate:
// a self-signed certificate is generated into the certificate library on
// first boot (so it shows up on the console certificate page), the active
// console certificate can be switched to any library entry at runtime
// (hot swap via tls.Config.GetCertificate, no listener restart), and the
// selection persists across restarts in a small state file.
package consoletls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/certmgr"
)

// selfSignedName is the certificate-library entry holding the bootstrap
// self-signed console certificate (same convention as the all-in-one
// bootstrap certificate).
const selfSignedName = "self-signed-default"

// stateFileName persists the active console certificate selection.
const stateFileName = "console-tls.json"

// Info is the current console TLS posture (GET /api/console/tls).
type Info struct {
	TLSEnabled  bool   `json:"tls_enabled"`
	Listen      string `json:"listen"`
	CertName    string `json:"cert_name"`
	Source      string `json:"source"` // "self-signed" | "library"
	Subject     string `json:"subject,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // sha256(leaf DER), hex
}

// Options configures the manager.
type Options struct {
	// LibraryRoot is the certificate library (<console db dir>/uploads/certs):
	// the self-signed bootstrap entry is created here so the console
	// certificate is visible on the certificate page next to user uploads.
	LibraryRoot string
	// StateDir persists the active selection (console-tls.json); typically
	// the console db dir.
	StateDir string
	// Listen is the HTTPS listen address (informational, surfaced in Info).
	Listen string
	// Host seeds the self-signed certificate CN/SAN.
	Host string
	// PinnedName optionally pins a library certificate at boot (flag value);
	// empty = persisted selection, else the self-signed default.
	PinnedName string
	Logger     *slog.Logger
}

// Manager owns the console TLS certificate (hot-swappable).
type Manager struct {
	mu          sync.Mutex
	libraryRoot string
	statePath   string
	listen      string
	pinned      string
	logger      *slog.Logger

	cert     atomic.Pointer[tls.Certificate]
	info     atomic.Pointer[Info]
	activeName string
}

// New bootstraps the self-signed library entry (when absent), resolves the
// initial certificate (pinned flag > persisted selection > self-signed) and
// returns the ready manager. A load failure of a pinned/persisted entry falls
// back to the self-signed certificate with a warning — the console must come
// up HTTPS.
func New(o Options) (*Manager, error) {
	logger := o.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if o.LibraryRoot == "" || o.StateDir == "" {
		return nil, fmt.Errorf("consoletls: library root and state dir are required")
	}
	// Bootstrap: self-signed entry inside the certificate library (visible on
	// the certificate page; reused when already present).
	if _, _, err := certmgr.EnsureSelfSigned(o.LibraryRoot, o.Host); err != nil {
		return nil, fmt.Errorf("consoletls: bootstrap self-signed: %w", err)
	}
	m := &Manager{
		libraryRoot: o.LibraryRoot,
		statePath:   filepath.Join(o.StateDir, stateFileName),
		listen:      o.Listen,
		pinned:      o.PinnedName,
		logger:      logger,
	}
	// Resolution order: pinned flag > persisted selection > self-signed.
	name := selfSignedName
	source := "self-signed"
	if o.PinnedName != "" {
		name, source = o.PinnedName, "library"
	} else if persisted, ok := m.loadState(); ok && persisted != "" {
		name, source = persisted, "library"
	}
	cert, leaf, err := m.loadLibraryCert(name)
	if err != nil && name != selfSignedName {
		logger.Warn("consoletls: configured console certificate unavailable; falling back to self-signed",
			"cert_name", name, "err", err)
		name, source = selfSignedName, "self-signed"
		cert, leaf, err = m.loadLibraryCert(name)
	}
	if err != nil {
		return nil, fmt.Errorf("consoletls: load console certificate: %w", err)
	}
	m.apply(cert, leaf, name, source)
	return m, nil
}

// Certificate satisfies tls.Config.GetCertificate (per-handshake lookup, so
// ApplyFromLibrary hot-swaps without touching the listener).
func (m *Manager) Certificate() *tls.Certificate {
	return m.cert.Load()
}

// Current returns the console TLS posture for the console UI.
func (m *Manager) Current() Info {
	if in := m.info.Load(); in != nil {
		return *in
	}
	return Info{Listen: m.listen}
}

// ApplyFromLibrary switches the console certificate to a certificate-library
// entry (hot swap; the selection persists for restarts).
func (m *Manager) ApplyFromLibrary(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || !validEntryName(name) {
		return fmt.Errorf("consoletls: invalid certificate name")
	}
	cert, leaf, err := m.loadLibraryCert(name)
	if err != nil {
		return err
	}
	m.apply(cert, leaf, name, "library")
	if err := m.saveState(name); err != nil {
		// Hot swap already applied; persistence failure only affects restarts.
		m.logger.Warn("consoletls: persist selection failed", "cert_name", name, "err", err)
	}
	m.logger.Info("console certificate switched", "cert_name", name, "source", "library")
	return nil
}

// apply publishes the certificate and its Info snapshot atomically.
func (m *Manager) apply(cert *tls.Certificate, leaf *x509.Certificate, name, source string) {
	sum := sha256.Sum256(leaf.Raw)
	in := &Info{
		TLSEnabled:  true,
		Listen:      m.listen,
		CertName:    name,
		Source:      source,
		Subject:     leaf.Subject.CommonName,
		NotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: hex.EncodeToString(sum[:])[:16],
	}
	m.cert.Store(cert)
	m.info.Store(in)
	m.mu.Lock()
	m.activeName = name
	m.mu.Unlock()
}

// loadLibraryCert reads a library entry and builds the tls.Certificate.
func (m *Manager) loadLibraryCert(name string) (*tls.Certificate, *x509.Certificate, error) {
	if name == "" || !validEntryName(name) {
		return nil, nil, fmt.Errorf("consoletls: invalid certificate name")
	}
	dir := filepath.Join(m.libraryRoot, name)
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("consoletls: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("consoletls: read key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("consoletls: parse pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("consoletls: empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("consoletls: parse leaf: %w", err)
	}
	return &cert, leaf, nil
}

// loadState / saveState persist the selection across restarts.
func (m *Manager) loadState() (string, bool) {
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return "", false
	}
	var st struct {
		CertName string `json:"cert_name"`
	}
	if json.Unmarshal(b, &st) != nil || st.CertName == "" {
		return "", false
	}
	return st.CertName, true
}

func (m *Manager) saveState(name string) error {
	b, _ := json.MarshalIndent(map[string]string{"cert_name": name}, "", "  ")
	return os.WriteFile(m.statePath, b, 0o640)
}

func validEntryName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
