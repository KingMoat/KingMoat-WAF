package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestCertificateSitesReference scans both certificate endpoints for the
// "sites" field: an entry referenced by two sites lists both primary
// domains, a singly referenced entry lists one, and an unreferenced library
// entry reports an empty list.
func TestCertificateSitesReference(t *testing.T) {
	ts, db := uploadServer(t)
	root := filepath.Join(filepath.Dir(db), "uploads", "certs")

	// Upload two library entries; both pairs must really parse.
	shopPEM, shopKey := genTestPair(t)
	soloPEM, soloKey := genTestPair(t)
	for _, up := range []struct{ name string; cert, key []byte }{
		{"shop", shopPEM, shopKey}, {"solo", soloPEM, soloKey},
	} {
		body, ctype := multipartBody(t,
			map[string]string{"name": up.name},
			map[string][]byte{"cert": up.cert, "key": up.key})
		resp, err := http.Post(ts.URL+"/api/certificates/upload", ctype, body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("upload %s = %d", up.name, resp.StatusCode)
		}
	}
	// An unreferenced library entry, written directly to disk.
	orphan := filepath.Join(root, "orphan")
	if err := os.MkdirAll(orphan, 0o750); err != nil {
		t.Fatal(err)
	}
	orphanPEM, orphanKey := genTestPair(t)
	if err := os.WriteFile(filepath.Join(orphan, "cert.pem"), orphanPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "key.pem"), orphanKey, 0o600); err != nil {
		t.Fatal(err)
	}

	// Publish two sites sharing the shop entry and one on the solo entry.
	shopCert := filepath.Join(root, "shop", "cert.pem")
	shopKeyP := filepath.Join(root, "shop", "key.pem")
	soloCert := filepath.Join(root, "solo", "cert.pem")
	soloKeyP := filepath.Join(root, "solo", "key.pem")
	cfg := map[string]any{
		"listen_http": ":8080",
		"sites": []map[string]any{
			{"domains": []string{"a.local"}, "tls_cert": shopCert, "tls_key": shopKeyP,
				"upstream": map[string]any{"nodes": []map[string]any{{"address": "127.0.0.1:9001"}}}},
			{"domains": []string{"b.local"}, "tls_cert": shopCert, "tls_key": shopKeyP,
				"upstream": map[string]any{"nodes": []map[string]any{{"address": "127.0.0.1:9001"}}}},
			{"domains": []string{"c.local"}, "tls_cert": soloCert, "tls_key": soloKeyP,
				"upstream": map[string]any{"nodes": []map[string]any{{"address": "127.0.0.1:9001"}}}},
		},
	}
	if code := doJSON(t, http.DefaultClient, "POST", ts.URL+"/api/config/publish",
		map[string]any{"note": "cert sites test", "config": cfg}); code != http.StatusOK {
		t.Fatalf("publish = %d", code)
	}

	// Library list: shop referenced by a+b, solo by c, orphan by none.
	resp, err := http.Get(ts.URL + "/api/certificates/uploads")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET uploads = %d", resp.StatusCode)
	}
	var uploads []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&uploads); err != nil {
		t.Fatal(err)
	}
	sitesOf := map[string][]any{}
	for _, u := range uploads {
		name, _ := u["name"].(string)
		sites, _ := u["sites"].([]any)
		sitesOf[name] = sites
	}
	if got := sitesOf["shop"]; len(got) != 2 || got[0] != "a.local" || got[1] != "b.local" {
		t.Fatalf("shop sites = %v, want [a.local b.local]", got)
	}
	if got := sitesOf["solo"]; len(got) != 1 || got[0] != "c.local" {
		t.Fatalf("solo sites = %v, want [c.local]", got)
	}
	if got := sitesOf["orphan"]; len(got) != 0 {
		t.Fatalf("orphan sites = %v, want empty", got)
	}

	// Site inventory shares the grouping (same material → both sites).
	resp2, err := http.Get(ts.URL + "/api/certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var infos []map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&infos); err != nil {
		t.Fatal(err)
	}
	infoSites := map[string][]any{}
	for _, info := range infos {
		site, _ := info["site"].(string)
		sites, _ := info["sites"].([]any)
		infoSites[site] = sites
	}
	if got := infoSites["a.local"]; len(got) != 2 || got[0] != "a.local" || got[1] != "b.local" {
		t.Fatalf("inventory a.local sites = %v, want [a.local b.local]", got)
	}
	if got := infoSites["c.local"]; len(got) != 1 || got[0] != "c.local" {
		t.Fatalf("inventory c.local sites = %v, want [c.local]", got)
	}
}
