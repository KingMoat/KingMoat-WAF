package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/store"
)

func aiKeySeedCfg() *config.Config {
	c := seedCfg()
	c.AI = json.RawMessage(`{"enabled":true,"provider":{"template":"openai","base_url":"https://api.openai.example/v1","model":"test-model"}}`)
	return c
}

func quietSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// aiKeyServer assembles a console with an enabled ai section, a real KEK
// file and a live ai.Service wired through a swappable pointer. rebuild
// re-resolves the active revision's ai settings (Supervisor-equivalent) so
// key_source assertions run against a freshly built client.
func aiKeyServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "ai-kek.key")
	dbPath := filepath.Join(dir, "ai.db")

	center, err := configcenter.Open(filepath.Join(dir, "aikey.db"), aiKeySeedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := logstore.NewSQLiteStore(filepath.Join(dir, "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}

	adminHash := "$argon2id$v=19$m=65536,t=3,p=4$" + mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	if _, err := center.Store().CreateUser("admin", adminHash, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	opHash := "$argon2id$v=19$m=65536,t=3,p=4$" + mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("op-pass")
	if _, err := center.Store().CreateUser("op", opHash, store.RoleOperator); err != nil {
		t.Fatal(err)
	}

	var cur atomic.Pointer[ai.Service]
	srv := New(Options{
		SkipBootstrap: true,
		Center:        center,
		Logs:          audit,
		Auth:          NewAuth(adminHash),
		AIFn:          func() *ai.Service { return cur.Load() },
		AIKEKFn: func() []byte {
			k, err := ai.LoadOrCreateKEK(kekPath)
			if err != nil {
				return nil
			}
			return k
		},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	rebuild := func() {
		_, cfg := center.Current()
		st := ai.ResolveSettings(cfg.AI, "", kekPath, quietSlog())
		if st == nil || !st.Enabled {
			if old := cur.Swap(nil); old != nil {
				_ = old.Close()
			}
			return
		}
		svc, err := ai.NewService(st, &ai.DataSources{Version: "test"}, dbPath, st.KEK, quietSlog(), config.EmailSettings{})
		if err != nil {
			if old := cur.Swap(nil); old != nil {
				_ = old.Close()
			}
			return
		}
		if old := cur.Swap(svc); old != nil {
			_ = old.Close()
		}
	}
	rebuild()
	t.Cleanup(func() {
		if s := cur.Load(); s != nil {
			_ = s.Close()
		}
		center.Close()
		audit.Close()
	})
	return ts, rebuild
}

func loginAs(t *testing.T, ts *httptest.Server, username, password string) *http.Cookie {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(mustJSON(t, map[string]string{"username": username, "password": password})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d", username, resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login %s: no session cookie", username)
	}
	return cookies[0]
}

func doReq(t *testing.T, ts *httptest.Server, method, path string, cookie *http.Cookie, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(mustJSON(t, body))
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func aiConfigSource(t *testing.T, ts *httptest.Server, cookie *http.Cookie) (bool, string) {
	t.Helper()
	code, b := doReq(t, ts, "GET", "/api/ai/config", cookie, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/ai/config = %d", code)
	}
	var d struct {
		Enabled   bool   `json:"enabled"`
		KeySource string `json:"key_source"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d.Enabled, d.KeySource
}

func TestAIKeyLifecycleAndConfigSource(t *testing.T) {
	ts, rebuild := aiKeyServer(t)
	cookie := loginAs(t, ts, "admin", "hunter2")

	// No stored key, no env → usable=false (effective availability), none.
	// enabled reports "configured on AND a key resolves"; without a key every
	// chat would fail, so the console must treat the assistant as off.
	if enabled, src := aiConfigSource(t, ts, cookie); enabled || src != ai.KeySourceNone {
		t.Fatalf("initial ai/config = (enabled=%v, %q), want (false, none)", enabled, src)
	}

	revCount := func() int {
		code, b := doReq(t, ts, "GET", "/api/revisions", cookie, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/revisions = %d", code)
		}
		var list []map[string]any
		_ = json.Unmarshal(b, &list)
		return len(list)
	}

	// Store a key: hot-applies after rebuild → key_source stored.
	if code, b := doReq(t, ts, "POST", "/api/ai/key", cookie, map[string]string{"key": "sk-live-123"}); code != http.StatusOK {
		t.Fatalf("POST /api/ai/key = %d: %s", code, b)
	}
	rebuild()
	if enabled, src := aiConfigSource(t, ts, cookie); !enabled || src != ai.KeySourceStored {
		t.Fatalf("ai/config after set = (enabled=%v, %q), want (true, stored)", enabled, src)
	}
	revs := revCount()

	// Storing the identical key is a no-op (no dirty revision, still 200).
	if code, b := doReq(t, ts, "POST", "/api/ai/key", cookie, map[string]string{"key": "sk-live-123"}); code != http.StatusOK {
		t.Fatalf("duplicate POST /api/ai/key = %d: %s", code, b)
	}
	if n := revCount(); n != revs {
		t.Fatalf("duplicate key store created %d new revisions, want 0", n-revs)
	}
	rebuild()
	if enabled, src := aiConfigSource(t, ts, cookie); !enabled || src != ai.KeySourceStored {
		t.Fatalf("ai/config after duplicate set = (enabled=%v, %q), want (true, stored)", enabled, src)
	}

	// Clear: back to none (env fallback unset).
	if code, b := doReq(t, ts, "DELETE", "/api/ai/key", cookie, nil); code != http.StatusOK {
		t.Fatalf("DELETE /api/ai/key = %d: %s", code, b)
	}
	rebuild()
	if enabled, src := aiConfigSource(t, ts, cookie); enabled || src != ai.KeySourceNone {
		t.Fatalf("ai/config after clear = (enabled=%v, %q), want (false, none)", enabled, src)
	}

	// Clearing again stays 200 (nothing to remove).
	if code, _ := doReq(t, ts, "DELETE", "/api/ai/key", cookie, nil); code != http.StatusOK {
		t.Fatalf("idempotent DELETE /api/ai/key = %d, want 200", code)
	}
}

func TestAIKeyRequiresAdmin(t *testing.T) {
	ts, _ := aiKeyServer(t)

	// Unauthenticated → 401 by the auth middleware.
	if code, _ := doReq(t, ts, "POST", "/api/ai/key", nil, map[string]string{"key": "sk-x"}); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /api/ai/key = %d, want 401", code)
	}
	if code, _ := doReq(t, ts, "DELETE", "/api/ai/key", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated DELETE /api/ai/key = %d, want 401", code)
	}

	// Operator session → 403 on both endpoints.
	cookie := loginAs(t, ts, "op", "op-pass")
	if code, b := doReq(t, ts, "POST", "/api/ai/key", cookie, map[string]string{"key": "sk-x"}); code != http.StatusForbidden {
		t.Fatalf("operator POST /api/ai/key = %d: %s, want 403", code, strings.TrimSpace(string(b)))
	}
	if code, _ := doReq(t, ts, "DELETE", "/api/ai/key", cookie, nil); code != http.StatusForbidden {
		t.Fatalf("operator DELETE /api/ai/key = %d, want 403", code)
	}
}
