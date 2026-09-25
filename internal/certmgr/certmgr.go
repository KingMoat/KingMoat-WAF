// Package certmgr inspects site TLS certificates and integrates ACME
// (Let's Encrypt) automatic issuance via x/crypto/acme/autocert.
package certmgr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Info describes one site's certificate state (for /api/certificates).
type Info struct {
	Site      string   `json:"site"`
	Source    string   `json:"source"` // "file" | "acme"
	Domains   []string `json:"domains,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Error     string   `json:"error,omitempty"`
	// Sites lists the primary domains of every site whose tls_cert/tls_key
	// resolves to the same certificate material (site itself included).
	Sites []string `json:"sites,omitempty"`
}

// InspectFile parses a PEM certificate file and returns its metadata.
func InspectFile(site, domain, certPath string) Info {
	info := Info{Site: site, Source: "file", Domains: []string{domain}}
	b, err := os.ReadFile(certPath)
	if err != nil {
		info.Error = fmt.Sprintf("read: %v", err)
		return info
	}
	var lastErr string
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			lastErr = fmt.Sprintf("parse: %v", err)
			continue
		}
		// Report the leaf (first certificate that is not a CA, else first).
		if cert.IsCA && rest != nil {
			if info.Subject == "" {
				info.Subject = cert.Subject.CommonName
				info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
				info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
			}
			continue
		}
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		info.Domains = cert.DNSNames
		if info.Error != "" {
			info.Error = ""
		}
		return info
	}
	if info.Subject == "" {
		if lastErr != "" {
			info.Error = lastErr
		} else {
			info.Error = "no CERTIFICATE block found"
		}
	}
	return info
}

// InspectSites builds the certificate inventory for a configuration. Each
// entry carries the list of sites sharing the same certificate material.
func InspectSites(cfg *config.Config) []Info {
	out := []Info{}
	// Group sites by tls_cert / tls_key path so shared certificates surface
	// every referencing site (site primary domains, deduplicated).
	refs := map[string][]string{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		domain := s.Domains[0]
		for _, p := range []string{s.TLSCert, s.TLSKey} {
			if p == "" {
				continue
			}
			if !containsStr(refs[p], domain) {
				refs[p] = append(refs[p], domain)
			}
		}
	}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		domain := s.Domains[0]
		switch {
		case s.TLSCert != "":
			info := InspectFile(domain, domain, s.TLSCert)
			info.Sites = sharedSites(refs, s.TLSCert, s.TLSKey)
			out = append(out, info)
		case s.ACME != nil:
			out = append(out, Info{
				Site:    domain,
				Source:  "acme",
				Domains: append([]string{}, s.Domains...),
				Subject: "managed by ACME (auto-renew)",
				Sites:   []string{domain},
			})
		}
	}
	return out
}

// sharedSites merges the site lists for the cert and key paths.
func sharedSites(refs map[string][]string, certPath, keyPath string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range []string{certPath, keyPath} {
		for _, d := range refs[p] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ACMEHosts returns the deduplicated domain list of every site with ACME
// enabled, in first-appearance order.
func ACMEHosts(cfg *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.ACME == nil {
			continue
		}
		for _, d := range s.Domains {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// ACMEManager builds an autocert.Manager for all sites with acme enabled,
// or nil when no site uses ACME. cacheDir persists issued certificates and
// account keys across restarts.
func ACMEManager(cfg *config.Config, cacheDir string, globalEmail string) *autocert.Manager {
	hosts := ACMEHosts(cfg)
	email := ""
	staging := false
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.ACME == nil {
			continue
		}
		if email == "" {
			email = s.ACME.Email
		}
		if email == "" {
			email = globalEmail // settings-page global ACME contact
		}
		staging = staging || s.ACME.Staging
	}
	if len(hosts) == 0 {
		return nil
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      email,
		Prompt:     autocert.AcceptTOS,
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	return m
}

// ACMEHolder dynamically holds the ACME manager for the ACTIVE configuration.
// The console publishes new revisions without a restart, so data-plane wiring
// (the TLS getCertificate chain and the HTTP-01 challenge handler) must
// re-resolve the current manager on every use instead of holding the one built
// at boot. Rebuild swaps the manager atomically; nil is stored when no site
// uses ACME, which disables ACME cleanly (challenge requests fall through to
// the data plane). ACMEManager construction is a pure in-memory operation, so
// a rebuild itself cannot fail: the swap always lands.
type ACMEHolder struct {
	mgr      atomic.Pointer[autocert.Manager]
	cacheDir string
}

// NewACMEHolder returns an empty holder persisting issued certificates in
// cacheDir.
func NewACMEHolder(cacheDir string) *ACMEHolder {
	return &ACMEHolder{cacheDir: cacheDir}
}

// Rebuild builds the manager from cfg (the configuration just applied to the
// data plane) and stores it; nil is stored when no site uses ACME. Returns
// the new manager.
func (h *ACMEHolder) Rebuild(cfg *config.Config, globalEmail string) *autocert.Manager {
	m := ACMEManager(cfg, h.cacheDir, globalEmail)
	h.mgr.Store(m)
	return m
}

// Load returns the current manager, or nil when ACME is disabled.
func (h *ACMEHolder) Load() *autocert.Manager { return h.mgr.Load() }
