// Certificate upload: individual PEM cert/key pairs or an archive (zip /
// tar / tar.gz / gz, max 5 nesting layers) with automatic extraction,
// content-based cert/key detection (PEM and DER, any file extension) and
// public-key pairing when an archive holds multiple candidates. Uploaded
// certificates are stored under <console db dir>/uploads/certs/<name>/ and
// referenced from site config as file paths (all-in-one: same host).
package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/store"
)

// uploadsRoot resolves the certificate library directory.
func (s *Server) uploadsRoot() string {
	dbPath := "kingmoat.db"
	if s.opts.Center != nil {
		if p := s.opts.Center.DBPath(); p != "" {
			dbPath = p
		}
	}
	return filepath.Join(filepath.Dir(dbPath), "uploads", "certs")
}

// handleCertUpload POSTs multipart form:
//   - name  logical certificate name (required, [A-Za-z0-9_-], <=64 chars)
//   - cert  PEM certificate file (with key; optional when zip provided)
//   - key   PEM private key file
//   - zip   archive containing cert+key (zip/tar/tar.gz/gz, max 5 nesting
//           layers, <=10MiB compressed); every file is searched by CONTENT
//           for the certificate and the private key (any extension, PEM or
//           DER), and a matching pair is selected by public-key comparison
func (s *Server) handleCertUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	const maxUpload = 16 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("multipart parse failed: "+err.Error()))
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || !validName(name) {
		writeErr(w, http.StatusBadRequest, simpleError("name is required (letters, digits, dash, underscore)"))
		return
	}

	var certPEM, keyPEM []byte
	if zf, _, err := r.FormFile("zip"); err == nil {
		defer zf.Close()
		data, rerr := io.ReadAll(io.LimitReader(zf, 12<<20))
		if rerr != nil {
			writeErr(w, http.StatusBadRequest, simpleError("read zip failed"))
			return
		}
		certPEM, keyPEM, err = extractFromArchive(data)
		if err != nil {
			writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
			return
		}
	} else {
		certFile, _, err := r.FormFile("cert")
		if err != nil {
			writeErr(w, http.StatusBadRequest, simpleError("provide cert+key files or a zip archive"))
			return
		}
		defer certFile.Close()
		keyFile, _, err := r.FormFile("key")
		if err != nil {
			writeErr(w, http.StatusBadRequest, simpleError("private key file (key) is missing"))
			return
		}
		defer keyFile.Close()
		if certPEM, err = io.ReadAll(io.LimitReader(certFile, 4<<20)); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError("read cert failed"))
			return
		}
		if keyPEM, err = io.ReadAll(io.LimitReader(keyFile, 4<<20)); err != nil {
			writeErr(w, http.StatusBadRequest, simpleError("read key failed"))
			return
		}
	}

	if err := validatePair(certPEM, keyPEM); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(err.Error()))
		return
	}

	dir := filepath.Join(s.uploadsRoot(), name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	info := certInfoFromPEM(certPEM)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "name": name,
		"cert_path": filepath.Join(dir, "cert.pem"),
		"key_path":  filepath.Join(dir, "key.pem"),
		"subject":   info["subject"], "not_after": info["not_after"],
	})
}

// handleCertUploadDelete removes one certificate-library entry
// (DELETE /api/certificates/uploads/{name}). Deletion is refused while the
// entry is referenced by the active site config or bound as the console
// certificate — remove those references first.
func (s *Server) handleCertUploadDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if !validName(name) {
		writeErr(w, http.StatusBadRequest, simpleError("invalid certificate name"))
		return
	}
	dir := filepath.Join(s.uploadsRoot(), name)
	if _, err := os.Stat(dir); err != nil {
		writeErr(w, http.StatusNotFound, simpleError("certificate not found"))
		return
	}
	_, cfg := s.opts.Center.Current()
	for i := range cfg.Sites {
		if pathWithin(dir, cfg.Sites[i].TLSCert) || pathWithin(dir, cfg.Sites[i].TLSKey) {
			domains := ""
			if len(cfg.Sites[i].Domains) > 0 {
				domains = cfg.Sites[i].Domains[0]
			}
			writeErr(w, http.StatusConflict, simpleError("certificate is referenced by site "+domains+"; unbind it first"))
			return
		}
	}
	if s.opts.ConsoleTLS != nil && s.opts.ConsoleTLS.Current().CertName == name {
		writeErr(w, http.StatusConflict, simpleError("certificate is bound to the management console; switch the console certificate first"))
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "cert.delete", name, "uploaded certificate removed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// pathWithin reports whether p is the directory dir or a path under it.
func pathWithin(dir, p string) bool {
	if p == "" {
		return false
	}
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// certRefSites returns the primary domains of every active site whose
// tls_cert/tls_key lives inside dir (same path predicate as the delete
// guard above), so the console can show per-certificate references.
func (s *Server) certRefSites(cfg *config.Config, dir string) []string {
	out := []string{}
	for i := range cfg.Sites {
		if pathWithin(dir, cfg.Sites[i].TLSCert) || pathWithin(dir, cfg.Sites[i].TLSKey) {
			if len(cfg.Sites[i].Domains) > 0 {
				out = append(out, cfg.Sites[i].Domains[0])
			}
		}
	}
	return out
}

// handleCertUploads lists uploaded certificates. Each entry carries the
// "sites" list (referencing site primary domains) for the console.
func (s *Server) handleCertUploads(w http.ResponseWriter, r *http.Request) {
	root := s.uploadsRoot()
	_, cfg := s.opts.Center.Current()
	out := []map[string]any{}
	entries, err := os.ReadDir(root)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			certPath := filepath.Join(root, e.Name(), "cert.pem")
			b, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}
			info := certInfoFromPEM(b)
			info["name"] = e.Name()
			info["cert_path"] = certPath
			info["key_path"] = filepath.Join(root, e.Name(), "key.pem")
			info["sites"] = s.certRefSites(cfg, filepath.Join(root, e.Name()))
			out = append(out, info)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func validName(name string) bool {
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

// Archive extraction limits (defense against zip/tar bombs).
const (
	maxArchiveNesting = 5                // nested archive layers (was 3 dir levels)
	maxDecompressed   = 20 << 20         // total bytes across all layers
	maxEntryBytes     = 4 << 20          // per-file cap
	maxArchiveEntries = 5000             // entry count cap
)

// certCandidate is one certificate file found in an archive (full chain kept;
// leaf parsed for pairing).
type certCandidate struct {
	name string
	pem  []byte
	leaf *x509.Certificate
}

// keyCandidate is one private key file (PEM-normalized; pub used for
// pairing, nil for encrypted keys which cannot be matched).
type keyCandidate struct {
	name string
	pem  []byte
	pub  crypto.PublicKey
	enc  bool
}

type archiveWalk struct {
	certs   []certCandidate
	keys    []keyCandidate
	total   int64
	entries int
}

// extractFromArchive searches every file of the archive (recursing into
// nested zip/tar/gz layers, max 5) for a certificate and its private key by
// CONTENT — not by file extension. When several candidates exist, the
// cert+key pair with matching public keys wins; with no cryptographically
// matchable key (e.g. only encrypted keys), the first cert/key pair is
// returned and final pairing is verified by tls.X509KeyPair at reload time.
func extractFromArchive(data []byte) (certPEM, keyPEM []byte, err error) {
	w := &archiveWalk{}
	if err := w.walk(data, "archive", 0); err != nil {
		return nil, nil, err
	}
	if len(w.certs) == 0 || len(w.keys) == 0 {
		return nil, nil, fmt.Errorf(
			"archive must contain a certificate (.pem/.crt/.cer or DER) and a private key (.key/.pem or PEM/DER: PKCS#1, PKCS#8, EC)")
	}
	for _, k := range w.keys {
		if k.pub == nil {
			continue // encrypted keys cannot be paired
		}
		for _, c := range w.certs {
			if samePublicKey(c.leaf.PublicKey, k.pub) {
				return c.pem, k.pem, nil
			}
		}
	}
	// No crypto match: fall back to the first candidates (previous behavior).
	return w.certs[0].pem, w.keys[0].pem, nil
}

func (w *archiveWalk) walk(data []byte, name string, depth int) error {
	// depth = number of archive layers already open; opening layer
	// maxArchiveNesting+1 is rejected (5-layer cap, was 3 dir levels).
	if depth >= maxArchiveNesting {
		return fmt.Errorf("archive nesting too deep (> %d layers)", maxArchiveNesting)
	}
	switch {
	case isZipData(data):
		return w.walkZip(data, depth)
	case isGzipData(data):
		return w.walkGzip(data, name, depth)
	case isTarData(data):
		return w.walkTar(data, depth)
	default:
		w.classify(name, data)
		return nil
	}
}

func (w *archiveWalk) walkZip(data []byte, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		b, err := w.readEntry(zf.Name, func() (io.ReadCloser, error) { return zf.Open() }, int64(zf.UncompressedSize64))
		if err != nil {
			return err
		}
		if err := w.walkOrClassify(b, zf.Name, depth); err != nil {
			return err
		}
	}
	return nil
}

func (w *archiveWalk) walkTar(data []byte, depth int) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walk tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := w.readEntry(hdr.Name, func() (io.ReadCloser, error) { return io.NopCloser(tr), nil }, hdr.Size)
		if err != nil {
			return err
		}
		if err := w.walkOrClassify(b, hdr.Name, depth); err != nil {
			return err
		}
	}
}

func (w *archiveWalk) walkGzip(data []byte, name string, depth int) error {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer zr.Close()
	inner, err := io.ReadAll(io.LimitReader(zr, maxEntryBytes+1))
	if err != nil {
		return fmt.Errorf("gunzip %s: %w", name, err)
	}
	if len(inner) > maxEntryBytes {
		return fmt.Errorf("gzip entry %s too large (> %d MiB)", name, maxEntryBytes>>20)
	}
	innerName := strings.TrimSuffix(name, ".gz")
	if isTarData(inner) {
		return w.walkTar(inner, depth+1)
	}
	if isZipData(inner) {
		return w.walkZip(inner, depth+1)
	}
	w.classify(innerName, inner)
	return nil
}

// walkOrClassify recurses into nested archives; plain files are classified.
func (w *archiveWalk) walkOrClassify(b []byte, name string, depth int) error {
	if isZipData(b) || isGzipData(b) || isTarData(b) || hasArchiveExt(name) {
		return w.walk(b, name, depth+1)
	}
	w.classify(name, b)
	return nil
}

// readEntry enforces the per-entry and global decompression budgets.
func (w *archiveWalk) readEntry(name string, open func() (io.ReadCloser, error), declared int64) ([]byte, error) {
	w.entries++
	if w.entries > maxArchiveEntries {
		return nil, fmt.Errorf("archive has too many entries (> %d)", maxArchiveEntries)
	}
	if declared > maxEntryBytes {
		return nil, fmt.Errorf("entry %s too large (> %d MiB)", name, maxEntryBytes>>20)
	}
	rc, err := open()
	if err != nil {
		return nil, fmt.Errorf("entry %s: %w", name, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("entry %s: %w", name, err)
	}
	if len(b) > maxEntryBytes {
		return nil, fmt.Errorf("entry %s too large (> %d MiB)", name, maxEntryBytes>>20)
	}
	w.total += int64(len(b))
	if w.total > maxDecompressed {
		return nil, fmt.Errorf("archive too large (> %d MiB decompressed)", maxDecompressed>>20)
	}
	return b, nil
}

// classify inspects one file's CONTENT and records cert/key candidates.
// A single file may hold both (combined PEM); normalized PEM is stored so
// junk (text comments, MACs, unrelated blocks) never reaches the TLS stack.
func (w *archiveWalk) classify(name string, b []byte) {
	var certPEMs, keyPEMs [][]byte
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			certPEMs = append(certPEMs, pem.EncodeToMemory(blk))
		case strings.Contains(blk.Type, "PRIVATE KEY"):
			keyPEMs = append(keyPEMs, pem.EncodeToMemory(blk))
		}
		if len(rest) == 0 {
			break
		}
	}
	if len(certPEMs) == 0 && len(keyPEMs) == 0 && len(b) > 0 {
		// DER fallback (binary .crt/.key without PEM armor).
		if cert, err := x509.ParseCertificate(b); err == nil {
			certPEMs = append(certPEMs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
			_ = cert
		} else if priv, err := parseAnyPrivateKey(b); err == nil {
			if der, err := x509.MarshalPKCS8PrivateKey(priv); err == nil {
				keyPEMs = append(keyPEMs, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			}
		}
	}
	if len(certPEMs) > 0 {
		leaf := parseLeaf(certPEMs)
		w.certs = append(w.certs, certCandidate{name: name, pem: bytes.Join(certPEMs, nil), leaf: leaf})
	}
	if len(keyPEMs) > 0 {
		k := keyCandidate{name: name, pem: keyPEMs[0]}
		k.enc = isEncryptedKeyPEM(keyPEMs[0])
		if !k.enc {
			if priv, err := parseAnyPrivateKeyPEM(keyPEMs[0]); err == nil {
				k.pub = publicKeyOf(priv)
			}
		}
		w.keys = append(w.keys, k)
	}
}

// parseLeaf parses the first CERTIFICATE block of a normalized PEM file.
func parseLeaf(certPEMBlocks [][]byte) *x509.Certificate {
	for _, p := range certPEMBlocks {
		blk, _ := pem.Decode(p)
		if blk == nil || blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			return c
		}
	}
	return nil
}

// parseAnyPrivateKeyPEM parses a PEM-encoded private key of any common type.
func parseAnyPrivateKeyPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if blk.Headers["Proc-Type"] != "" {
		return nil, fmt.Errorf("legacy encrypted PEM")
	}
	return parseAnyPrivateKey(blk.Bytes)
}

// parseAnyPrivateKey tries PKCS#8, PKCS#1 (RSA) and SEC1 (EC) DER.
func parseAnyPrivateKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key DER")
}

func isEncryptedKeyPEM(keyPEM []byte) bool {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return false
	}
	return blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["Proc-Type"] != ""
}

// publicKeyOf extracts the public part of any supported private key.
func publicKeyOf(priv crypto.PrivateKey) crypto.PublicKey {
	if p, ok := priv.(interface{ Public() crypto.PublicKey }); ok {
		return p.Public()
	}
	return nil
}

// samePublicKey compares two public keys by their PKIX DER encoding.
func samePublicKey(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ab, err1 := x509.MarshalPKIXPublicKey(a)
	bb, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(ab, bb)
}

func isZipData(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 || b[2] == 5 || b[2] == 7) && (b[3] == 4 || b[3] == 6 || b[3] == 8)
}

func isGzipData(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

func isTarData(b []byte) bool {
	return len(b) > 262 && string(b[257:262]) == "ustar"
}

func hasArchiveExt(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") ||
		strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".gz")
}

// isPEMType reports whether the buffer contains a PEM block whose type
// contains the given substring (covers CERTIFICATE / PRIVATE KEY / RSA
// PRIVATE KEY / EC PRIVATE KEY).
func isPEMType(b []byte, blockType string) bool {
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return false
		}
		if strings.Contains(blk.Type, blockType) {
			return true
		}
		if len(rest) == 0 {
			return false
		}
	}
}

// validatePair parses the certificate, rejects encrypted keys with a clear
// message and verifies the cert/key public keys actually match — so a
// mismatched pair is caught at upload time instead of failing the site
// publish later (tls.X509KeyPair re-verifies at load time).
func validatePair(certPEM, keyPEM []byte) error {
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return fmt.Errorf("cert file does not contain a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	if isEncryptedKeyPEM(keyPEM) {
		return fmt.Errorf("private key is encrypted (password-protected); decrypt it first — encrypted keys are not supported")
	}
	if !isPEMType(keyPEM, "PRIVATE KEY") {
		return fmt.Errorf("key file does not contain a PEM PRIVATE KEY block (PKCS#1/PKCS#8/EC)")
	}
	if priv, err := parseAnyPrivateKeyPEM(keyPEM); err == nil {
		if pub := publicKeyOf(priv); pub != nil && !samePublicKey(cert.PublicKey, pub) {
			return fmt.Errorf("certificate and private key do not match (different public keys)")
		}
	}
	return nil
}

func certInfoFromPEM(b []byte) map[string]any {
	out := map[string]any{}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return out
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return out
	}
	out["subject"] = cert.Subject.CommonName
	out["issuer"] = cert.Issuer.CommonName
	out["not_after"] = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	out["domains"] = cert.DNSNames
	return out
}
