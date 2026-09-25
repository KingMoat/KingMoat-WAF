// ACME certificate cache inspection: the cert library lists logical ACME
// entries straight from the autocert DirCache directories (no copies, no
// sync jobs), and the manager whitelist merges every domain already present
// in a cache so certificates requested before their site exists keep being
// served and renewed ("request first, attach site later").
package certmgr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// stagingCacheSuffix separates staging-issued certificates from production
// ones (gate item S-2): the production manager must never pick up a staging
// certificate and vice versa. Existing deployments keep their production
// cache directory unchanged ("acme-cache"); only staging writes move to the
// new sibling directory.
const stagingCacheSuffix = "-staging"

// acmeAccountKeyFile is the ACME account key autocert stores inside the
// cache directory; it is not a certificate and must not surface as one.
const acmeAccountKeyFile = "acme_account+key"

// renewBefore mirrors the autocert renewal window: certificates with less
// than 30 days left count as "expiring" in the cert library, and the
// certificate-library request flow only treats certificates with more than
// that margin as cache hits (nearly-expired entries re-issue instead).
const renewBefore = 30 * 24 * time.Hour

// cacheDirFor returns the autocert cache directory for the staging mode.
func cacheDirFor(base string, staging bool) string {
	if staging {
		return base + stagingCacheSuffix
	}
	return base
}

// cachedLeaf parses the leaf certificate of one DirCache entry. The file
// holds PEM certificate blocks (leaf first, then the chain) followed by the
// private key block; the first non-CA certificate wins, falling back to the
// first certificate when the chain layout differs.
func cachedLeaf(dir, name string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return leafFromPEM(b)
}

// leafFromPEM parses the leaf certificate out of raw PEM bytes.
func leafFromPEM(b []byte) (*x509.Certificate, error) {
	var first, leaf *x509.Certificate
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
			continue
		}
		if first == nil {
			first = cert
		}
		if !cert.IsCA {
			leaf = cert
			break
		}
	}
	if leaf == nil {
		leaf = first
	}
	if leaf == nil {
		return nil, fmt.Errorf("no certificate found in PEM")
	}
	return leaf, nil
}

// CachedHosts lists the domains that already have a certificate cached in
// dir, sorted. Entries that do not parse as certificates (account key,
// partial writes) are skipped.
func CachedHosts(dir string) []string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range files {
		if f.IsDir() || f.Name() == acmeAccountKeyFile {
			continue
		}
		if _, err := cachedLeaf(dir, f.Name()); err != nil {
			continue
		}
		out = append(out, f.Name())
	}
	slices.Sort(out)
	return out
}

// CertEntry is one logical ACME certificate as shown in the cert library.
type CertEntry struct {
	Domain    string `json:"domain"`
	Staging   bool   `json:"staging"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	// Status is "valid" (more than 30 days left) or "expiring" (inside the
	// 30-day renewal window, including already expired). Cache entries that
	// do not parse never surface (skipped at read time).
	Status string `json:"status"`
}

// CacheEntries lists the ACME-managed certificates of both cache directories
// (production first, then staging), sorted by domain within each.
func CacheEntries(base string) []CertEntry {
	var out []CertEntry
	now := time.Now()
	for _, staging := range []bool{false, true} {
		dir := cacheDirFor(base, staging)
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, f := range files {
			if f.IsDir() || f.Name() == acmeAccountKeyFile {
				continue
			}
			names = append(names, f.Name())
		}
		slices.Sort(names)
		for _, name := range names {
			leaf, err := cachedLeaf(dir, name)
			if err != nil {
				continue // partial write / not a certificate
			}
			status := "valid"
			if leaf.NotAfter.Before(now.Add(renewBefore)) {
				status = "expiring"
			}
			out = append(out, CertEntry{
				Domain:    name,
				Staging:   staging,
				NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
				Subject:   leaf.Subject.CommonName,
				Issuer:    leaf.Issuer.CommonName,
				Status:    status,
			})
		}
	}
	return out
}
