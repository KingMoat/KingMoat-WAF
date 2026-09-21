// Local certificate authority: create a self-signed CA once, then sign
// server certificates on demand from user-supplied request info (CN, SANs,
// validity). Issued certificates land in the regular uploads library
// (uploads/certs/<name>/) so site editors pick them like any uploaded pair.
package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/store"
)

// localCARoot resolves the local CA storage directory
// (<console db dir>/uploads/ca). The directory name keeps the CA out of the
// uploads listing, which only scans uploads/certs/*.
func (s *Server) localCARoot() string {
	dbPath := "kingmoat.db"
	if s.opts.Center != nil {
		if p := s.opts.Center.DBPath(); p != "" {
			dbPath = p
		}
	}
	return filepath.Join(filepath.Dir(dbPath), "uploads", "ca")
}

const (
	localCACertFile = "ca.cert.pem"
	localCAKeyFile  = "ca.key.pem"
)

// handleLocalCAGet serves GET /api/certificates/ca: current CA info.
func (s *Server) handleLocalCAGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	certPEM, err := os.ReadFile(filepath.Join(s.localCARoot(), localCACertFile))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"exists": false})
		return
	}
	info := certInfoFromPEM(certPEM)
	info["exists"] = true
	writeJSON(w, http.StatusOK, info)
}

// handleLocalCACreate serves POST /api/certificates/ca {common_name, days,
// force}: generates the self-signed local CA (ECDSA P-256, 10y default).
func (s *Server) handleLocalCACreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req struct {
		CommonName string `json:"common_name"`
		Days       int    `json:"days"`
		Force      bool   `json:"force"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		cn = "KingMoat Local CA"
	}
	days := req.Days
	if days <= 0 {
		days = 3650
	}
	if days < 30 || days > 7300 {
		writeErr(w, http.StatusBadRequest, simpleError("days 必须在 30..7300 之间"))
		return
	}
	root := s.localCARoot()
	if _, err := os.ReadFile(filepath.Join(root, localCACertFile)); err == nil && !req.Force {
		writeErr(w, http.StatusConflict, simpleError("本地 CA 已存在；如需重建请携带 force=true（已签发的证书仍对旧 CA 有效）"))
		return
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"KingMoat"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := writeKeyAndCert(root, localCAKeyFile, localCACertFile, key, der); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "cert.ca_create", cn, fmt.Sprintf("days=%d", days))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "subject": cn, "not_after": now.AddDate(0, 0, days).UTC().Format("2006-01-02T15:04:05Z")})
}

// handleLocalCASign serves POST /api/certificates/ca/sign {name,
// common_name, sans, days}: issues a server certificate from the local CA
// and registers it in the uploads library (site editors can reference it).
func (s *Server) handleLocalCASign(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req struct {
		Name       string   `json:"name"`
		CommonName string   `json:"common_name"`
		Sans       []string `json:"sans"`
		Days       int      `json:"days"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cn := strings.TrimSpace(req.CommonName)
	if cn == "" {
		writeErr(w, http.StatusBadRequest, simpleError("common_name（证书主体域名）必填"))
		return
	}
	days := req.Days
	if days <= 0 {
		days = 825
	}
	if days < 7 || days > 3650 {
		writeErr(w, http.StatusBadRequest, simpleError("days 必须在 7..3650 之间"))
		return
	}
	root := s.localCARoot()
	caCertPEM, err := os.ReadFile(filepath.Join(root, localCACertFile))
	if err != nil {
		writeErr(w, http.StatusBadRequest, simpleError("本地 CA 尚未创建，请先创建"))
		return
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(root, localCAKeyFile))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("parse local CA: %w", err))
		return
	}

	sans := dedupeSans(cn, req.Sans)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"KingMoat"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.Map(func(c rune) rune {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
				return c
			default:
				return '-'
			}
		}, cn)
		name = strings.Trim(name, "-")
	}
	if !validName(name) {
		writeErr(w, http.StatusBadRequest, simpleError("name 仅允许字母、数字、下划线与短横线（≤64 字符），或留空按主体域名自动生成"))
		return
	}
	dir := filepath.Join(s.uploadsRoot(), name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// cert.pem carries the full chain (leaf first, then the CA cert) so
	// TLS servers can present it directly and clients validate against the
	// local CA in one file.
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, caCertPEM...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), chain, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.recordChange(r, "cert.ca_sign", cn, fmt.Sprintf("name=%s sans=%d days=%d", name, len(sans), days))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "name": name, "subject": cn, "sans": sans,
		"cert_path": filepath.Join(dir, "cert.pem"),
		"key_path":  filepath.Join(dir, "key.pem"),
		"not_after": now.AddDate(0, 0, days).UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// parseCA decodes the local CA certificate and private key PEM pair.
func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("CA cert PEM invalid")
	}
	caCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBlk, _ := pem.Decode(keyPEM)
	if keyBlk == nil {
		return nil, nil, fmt.Errorf("CA key PEM invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}
	return caCert, key, nil
}

// writeKeyAndCert writes the PKCS8 private key and DER certificate as PEM.
func writeKeyAndCert(dir, keyFile, certFile string, key *ecdsa.PrivateKey, certDER []byte) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o600)
}

// dedupeSans builds the SAN list: the common name first, then the user
// entries (lowercased, deduplicated).
func dedupeSans(cn string, sans []string) []string {
	seen := map[string]bool{strings.ToLower(cn): true}
	out := []string{cn}
	for _, s := range sans {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
