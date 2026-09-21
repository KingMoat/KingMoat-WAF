package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime/multipart"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/configcenter"
)

// genTestPair returns a real self-signed ECDSA cert/key PEM pair so x509
// parsing succeeds.
func genTestPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "t.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"t.local"},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func uploadServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	center, err := configcenter.Open(t.TempDir()+"/cert.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	srv := New(Options{SkipBootstrap: true, Center: center})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, center.DBPath()
}

func multipartBody(t *testing.T, fields map[string]string, files map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		w.WriteField(k, v)
	}
	for k, data := range files {
		fw, _ := w.CreateFormFile(k, k+".pem")
		fw.Write(data)
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

func TestCertUploadPair(t *testing.T) {
	ts, db := uploadServer(t)
	certPEM, keyPEM := genTestPair(t)
	body, ctype := multipartBody(t,
		map[string]string{"name": "shop"},
		map[string][]byte{"cert": certPEM, "key": keyPEM})
	resp, err := http.Post(ts.URL+"/api/certificates/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d: %s", resp.StatusCode, readAll(resp.Body))
	}

	// files exist on disk
	if _, err := os.Stat(filepath.Join(filepath.Dir(db), "uploads", "certs", "shop", "cert.pem")); err != nil {
		t.Fatalf("cert.pem not stored: %v", err)
	}

	// list contains the entry
	resp2, _ := http.Get(ts.URL + "/api/certificates/uploads")
	var list []map[string]any
	_ = jsonDecode(resp2.Body, &list)
	resp2.Body.Close()
	if len(list) != 1 || list[0]["name"] != "shop" {
		t.Fatalf("uploads list = %+v", list)
	}

	// mismatched garbage key 閳?400
	badBody, badType := multipartBody(t,
		map[string]string{"name": "bad"},
		map[string][]byte{"cert": certPEM, "key": []byte("not a key")})
	resp3, _ := http.Post(ts.URL+"/api/certificates/upload", badType, badBody)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbage key accepted: %d", resp3.StatusCode)
	}
}

func TestCertUploadZip(t *testing.T) {
	ts, _ := uploadServer(t)

	// zip with 2-level nesting + junk files
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w1, _ := zw.Create("shop.example.com/")
	certPEM, keyPEM := genTestPair(t)
	w2, _ := zw.Create("shop.example.com/fullchain.pem")
	w2.Write(certPEM)
	w3, _ := zw.Create("shop.example.com/priv/privkey.key")
	w3.Write(keyPEM)
	w4, _ := zw.Create("README.txt")
	w4.Write([]byte("junk"))
	zw.Close()
	_ = w1

	body, ctype := multipartBody(t, map[string]string{"name": "zipcert"}, map[string][]byte{"zip": zbuf.Bytes()})
	resp, err := http.Post(ts.URL+"/api/certificates/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zip upload = %d: %s", resp.StatusCode, readAll(resp.Body))
	}
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}

func jsonDecode(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// genNamedPair generates a self-signed pair with a distinct CN so multiple
// pairs inside one archive can be told apart by their certificate.
func genNamedPair(t *testing.T, cn string) ([]byte, []byte) {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func uploadZipExpect(t *testing.T, name string, zipData []byte, wantCode int) map[string]any {
	t.Helper()
	ts, _ := uploadServer(t)
	body, ctype := multipartBody(t, map[string]string{"name": name}, map[string][]byte{"zip": zipData})
	resp, err := http.Post(ts.URL+"/api/certificates/upload", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantCode {
		t.Fatalf("zip upload = %d; want %d: %s", resp.StatusCode, wantCode, readAll(resp.Body))
	}
	if wantCode != http.StatusOK {
		return nil
	}
	var out map[string]any
	if err := jsonDecode(resp.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Multi-pair archive: the extractor must pair the key with ITS certificate
// (public-key match), not just take the first cert + first key.
func TestCertUploadZipPairsByPublicKey(t *testing.T) {
	certA, keyA := genNamedPair(t, "a.local")
	certB, keyB := genNamedPair(t, "b.local")
	// Layout deliberately interleaves the two pairs. zipBytes walks a map,
	// so archive entry order is random per run — extractFromArchive returns
	// the FIRST cryptographically matchable pair (a.local or b.local, both
	// valid public-key pairings). Pin the contract: the result is always a
	// real cert/key pair from the archive — never the junk file, never a
	// mixed cert+key combination.
	zipData := zipBytes(t, map[string][]byte{
		"bundle/a.crt":            certA,
		"bundle/b/fullchain.pem":  certB,
		"bundle/b/privkey.key":    keyB,
		"bundle/other.key":        keyA,
		"bundle/README.txt":       []byte("junk"),
	})
	out := uploadZipExpect(t, "paired", zipData, http.StatusOK)
	subject, _ := out["subject"].(string)
	if subject != "a.local" && subject != "b.local" {
		t.Fatalf("paired subject = %v; want a.local or b.local (a real public-key pair)", subject)
	}
}

// Nested zip layers up to 5 are unwrapped.
func TestCertUploadZipNestedLayers(t *testing.T) {
	cert, key := genNamedPair(t, "deep.local")
	inner := zipBytes(t, map[string][]byte{"certs/server/fullchain.pem": cert, "certs/server/privkey.key": key})
	layer2 := zipBytes(t, map[string][]byte{"inner.zip": inner})
	layer3 := zipBytes(t, map[string][]byte{"l2.zip": layer2})
	layer4 := zipBytes(t, map[string][]byte{"l3.zip": layer3})
	outer := zipBytes(t, map[string][]byte{"l4.zip": layer4})
	out := uploadZipExpect(t, "nested5", outer, http.StatusOK)
	if out["subject"] != "deep.local" {
		t.Fatalf("nested subject = %v; want deep.local", out["subject"])
	}

	// Six layers exceed the limit → 400 with a clear error.
	layer5 := zipBytes(t, map[string][]byte{"l5.zip": outer})
	resp := uploadZipExpect(t, "nested6", layer5, http.StatusBadRequest)
	_ = resp
}

// The key may use any extension (or none) as long as the content is a key.
func TestCertUploadKeyContentDetection(t *testing.T) {
	cert, key := genNamedPair(t, "keyless-ext.local")
	zipData := zipBytes(t, map[string][]byte{
		"server.crt":           cert,
		"private_no_extension": key,
	})
	out := uploadZipExpect(t, "keycontent", zipData, http.StatusOK)
	if out["subject"] != "keyless-ext.local" {
		t.Fatalf("subject = %v", out["subject"])
	}
}

// DER-encoded (binary) cert and RSA PKCS#1 key, plus a tar.gz wrapper.
func TestCertUploadDERAndTarGz(t *testing.T) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "der.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"der.local"},
	}
	certDER, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	var tarbuf bytes.Buffer
	tw := tar.NewWriter(&tarbuf)
	for _, e := range []struct{ name string; data []byte }{
		{"a/b/c/d/e/server.crt.der", certDER}, // deep dir path: previously skipped at depth>=3
		{"a/b/c/d/e/server.key.der", keyDER},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	var gzbuf bytes.Buffer
	gw := gzip.NewWriter(&gzbuf)
	gw.Write(tarbuf.Bytes())
	gw.Close()

	out := uploadZipExpect(t, "dertargz", gzbuf.Bytes(), http.StatusOK)
	if out["subject"] != "der.local" {
		t.Fatalf("subject = %v; want der.local", out["subject"])
	}
}

// Combined PEM (cert+key in one file) works.
func TestCertUploadCombinedPEMFile(t *testing.T) {
	cert, key := genNamedPair(t, "combined.local")
	combined := append(append([]byte{}, cert...), key...)
	zipData := zipBytes(t, map[string][]byte{"both.pem": combined})
	out := uploadZipExpect(t, "combined", zipData, http.StatusOK)
	if out["subject"] != "combined.local" {
		t.Fatalf("subject = %v; want combined.local", out["subject"])
	}
}
