package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/webui"
)

func mustB64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func mustArgonHash(password string) string {
	salt := []byte("0123456789abcdef") // fixed salt is fine for tests
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(key)
}

func seedCfg() *config.Config {
	return &config.Config{
		ListenHTTP: ":8080",
		Sites: []config.Site{{
			Domains:  []string{"a.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9001"}}},
		}},
	}
}

func TestAPIPublishLogsWebUI(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/api-test.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()

	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	audit.Write(&logstore.Event{Action: "blocked", Rule: "coraza/rule-942100", Site: "a.local", Path: "/s"})
	if err := audit.Flush(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, WebUI: webui.Handler("test")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// WebUI shell renders.
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webui status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Current config.
	resp2, _ := http.Get(ts.URL + "/api/config")
	var cur struct {
		Revision int64         `json:"revision"`
		Config   config.Config `json:"config"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&cur)
	resp2.Body.Close()
	if cur.Revision != 1 {
		t.Fatalf("revision = %d, want 1", cur.Revision)
	}

	// Publish a two-site config via the API.
	newCfg := seedCfg()
	newCfg.Sites = append(newCfg.Sites, config.Site{
		Domains:  []string{"b.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9002"}}},
	})
	body, _ := json.Marshal(map[string]any{"note": "api test", "config": newCfg})
	resp3, err := http.Post(ts.URL+"/api/config/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var pub struct {
		Revision int64 `json:"revision"`
	}
	_ = json.NewDecoder(resp3.Body).Decode(&pub)
	resp3.Body.Close()
	if pub.Revision != 2 {
		t.Fatalf("publish revision = %d, want 2", pub.Revision)
	}

	// Logs reflect the written event.
	resp4, _ := http.Get(ts.URL + "/api/logs?limit=10")
	var logs []logstore.Event
	_ = json.NewDecoder(resp4.Body).Decode(&logs)
	resp4.Body.Close()
	if len(logs) != 1 || logs[0].Rule != "coraza/rule-942100" {
		t.Fatalf("logs = %+v", logs)
	}

	// Rollback endpoint.
	resp5, err := http.Post(ts.URL+"/api/revisions/1/rollback", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	_, cfg := center.Current()
	if len(cfg.Sites) != 1 {
		t.Fatalf("rollback not applied: sites=%d", len(cfg.Sites))
	}
}

func TestAuthEnforced(t *testing.T) {
	center, _ := configcenter.Open(t.TempDir()+"/auth.db", seedCfg(), nil)
	defer center.Close()

	hash := "$argon2id$v=19$m=65536,t=3,p=4$" + mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	seedStoreAdmin(t, center, hash)
	srv := New(Options{SkipBootstrap: true, Center: center, Auth: NewAuth(hash)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// No credentials → 401.
	resp, _ := http.Get(ts.URL + "/api/status")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// Correct credentials → 200.
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.SetBasicAuth("admin", "hunter2")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", resp2.StatusCode)
	}
}
