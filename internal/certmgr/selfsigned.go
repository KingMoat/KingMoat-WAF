// Bootstrap self-signed certificate: generated once at first console start
// so the certificate library is never empty (10-year validity, CN=<hostname>,
// SAN: hostname + localhost + loopback IPs).
package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"net"
	"path/filepath"
	"time"
)

// EnsureSelfSigned generates a 10-year self-signed certificate into
// <root>/self-signed-default/ when absent. Returns the cert/key paths.
func EnsureSelfSigned(root, hostname string) (certPath, keyPath string, err error) {
	dir := filepath.Join(root, "self-signed-default")
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil // already generated
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("self-signed: mkdir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("self-signed: key: %w", err)
	}
	cn := hostname
	if cn == "" {
		cn = "kingmoat"
	}
	serial, _ := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "KingMoat Self-Signed (" + cn + ")"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn, "localhost", "kingmoat.local"},
	}
	if ip := netParseIP(cn); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, loopbackIPs()...)
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("self-signed: cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("self-signed: marshal key: %w", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// small local helpers (avoid importing net/http side effects)
func netParseIP(s string) net.IP { return net.ParseIP(s) }

func loopbackIPs() []net.IP {
	return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
}
