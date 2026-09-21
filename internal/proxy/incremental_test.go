package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// incrementalTestCfg builds a two-site config (a.local / b.local) sharing the
// same upstream so identical deep copies produce byte-identical sites.
func incrementalTestCfg(upstreamAddr string) *config.Config {
	mk := func(domain string) config.Site {
		return config.Site{
			Domains: []string{domain},
			Mode:    "intercept",
			WAF:     &config.WAFSettings{Enabled: boolPtr(false)},
			Upstream: config.Upstream{
				Nodes: []config.UpstreamNode{{Address: upstreamAddr}},
			},
		}
	}
	return &config.Config{ListenHTTP: ":0", Sites: []config.Site{mk("a.local"), mk("b.local")}}
}

func deepCopyCfg(c *config.Config) *config.Config {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	var out config.Config
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}

func poolOf(h *Handler, domain string) *Pool {
	sr := h.state.Load().router.byDomain[domain]
	if sr == nil {
		return nil
	}
	return sr.pool
}

func TestIncrementalReloadAdoptsUnchangedSites(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	addr := strings.TrimPrefix(up.URL, "http://")

	h, err := NewReloadable(incrementalTestCfg(addr), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}
	pA0 := poolOf(h, "a.local")
	pB0 := poolOf(h, "b.local")
	if pA0 == nil || pB0 == nil {
		t.Fatal("initial pools missing")
	}

	// 1. identical reload: both pools must be adopted (pointer-identical).
	if err := h.Reload(deepCopyCfg(h.CurrentConfig())); err != nil {
		t.Fatalf("identical Reload: %v", err)
	}
	if pA1 := poolOf(h, "a.local"); pA1 != pA0 {
		t.Fatal("unchanged site a.local pool was rebuilt instead of adopted")
	}
	if pB1 := poolOf(h, "b.local"); pB1 != pB0 {
		t.Fatal("unchanged site b.local pool was rebuilt instead of adopted")
	}

	// 2. change only b.local: a.local stays adopted, b.local is rebuilt.
	next := deepCopyCfg(h.CurrentConfig())
	next.Sites[1].Upstream.Nodes[0].Address = "127.0.0.1:1"
	if err := h.Reload(next); err != nil {
		t.Fatalf("partial Reload: %v", err)
	}
	if pA2 := poolOf(h, "a.local"); pA2 != pA0 {
		t.Fatal("unchanged site a.local should survive a partial reload")
	}
	if pB2 := poolOf(h, "b.local"); pB2 == pB0 {
		t.Fatal("changed site b.local must be rebuilt")
	}

	// 3. failed reload keeps the live state (and adopted pools) untouched.
	//    (Reload fails at runtime build; config validation errors surface at
	//    the configcenter publish layer — covered by the API tests.)
	bad := deepCopyCfg(h.CurrentConfig())
	bad.Sites[0].Security = &config.SecuritySettings{
		ACL: &config.ACLSettings{Whitelist: []string{"not-an-ip"}},
	}
	if err := h.Reload(bad); err == nil {
		t.Fatal("expected runtime build error for bad site config")
	}
	if pA3 := poolOf(h, "a.local"); pA3 != pA0 {
		t.Fatal("failed reload must not disturb the live router")
	}

	// 4. traffic still flows through the adopted pool after all reloads.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://a.local/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("post-reload request = %d, want 200", rec.Code)
	}
}
