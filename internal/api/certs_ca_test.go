package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/passhash"
)

// TestLocalCACreateAndSign covers the local-CA lifecycle: sign-before-create
// guard, create, duplicate-create guard, CA info and the signed certificate
// appearing in the uploads library as a referenceable cert/key pair.
func TestLocalCACreateAndSign(t *testing.T) {
	hash, err := passhash.HashPassword("testpw")
	if err != nil {
		t.Fatal(err)
	}
	center := mustCenter(t)
	seedStoreAdmin(t, center, hash)
	srv := New(Options{Center: center, Logs: mustAudit(t), Auth: NewAuth(hash)})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// sign before CA exists → 400 with a clear hint
	code, body := doCASignedJSON(t, ts, "POST", "/api/certificates/ca/sign", map[string]any{"common_name": "demo.local"})
	if code != http.StatusBadRequest {
		t.Fatalf("sign before CA = %d (%s), want 400", code, body)
	}

	// create the CA
	code, body = doCASignedJSON(t, ts, "POST", "/api/certificates/ca", map[string]any{"common_name": "KingMoat Test CA", "days": 365})
	if code != http.StatusOK {
		t.Fatalf("create CA = %d (%s), want 200", code, body)
	}
	// duplicate create without force → 409
	if code, _ = doCASignedJSON(t, ts, "POST", "/api/certificates/ca", map[string]any{"common_name": "x"}); code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", code)
	}
	// CA info endpoint
	code, body = doCASignedJSON(t, ts, "GET", "/api/certificates/ca", nil)
	if code != http.StatusOK || !strings.Contains(body, `"exists":true`) {
		t.Fatalf("CA info = %d (%s), want 200 with exists:true", code, body)
	}

	// sign a leaf certificate
	code, body = doCASignedJSON(t, ts, "POST", "/api/certificates/ca/sign", map[string]any{
		"name": "demo-local", "common_name": "demo.local", "sans": []string{"alt.local", "127.0.0.1"}, "days": 365,
	})
	if code != http.StatusOK {
		t.Fatalf("sign = %d (%s), want 200", code, body)
	}
	// the pair is listed in the uploads library
	respBody := ""
	code, respBody = doCASignedJSON(t, ts, "GET", "/api/certificates/uploads", nil)
	if code != http.StatusOK {
		t.Fatalf("uploads list = %d", code)
	}
	var uploads []map[string]any
	_ = json.Unmarshal([]byte(respBody), &uploads)
	found := false
	for _, u := range uploads {
		if u["name"] == "demo-local" {
			found = true
		}
	}
	if !found {
		t.Fatalf("signed cert missing from uploads list: %v", uploads)
	}
	// files exist on disk and the cert file carries the full chain
	certPEM, err := os.ReadFile(filepath.Join(srv.uploadsRoot(), "demo-local", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Fatal("cert.pem should contain CERTIFICATE blocks")
	}
	if strings.Count(string(certPEM), "BEGIN CERTIFICATE") < 2 {
		t.Fatal("cert.pem should carry leaf + CA chain")
	}
}

// doCASignedJSON performs an authenticated (Basic) JSON request and returns
// the status code with the response body. Named distinctly from rbac_test's
// doJSON helper.
func doCASignedJSON(t *testing.T, ts *httptest.Server, method, path string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "testpw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}
