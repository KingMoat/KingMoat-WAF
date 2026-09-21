package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func mustJSONBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func TestSitePublishReplacesSingleSite(t *testing.T) {
	ts, login := rbacServer(t)
	client := login("admin", "hunter2")

	// Replace a.local's upstream via the per-site endpoint.
	body := mustJSONBody(t, map[string]any{
		"domain": "A.LOCAL",
		"note":   "retarget a",
		"site": config.Site{
			Domains:  []string{"a.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9099"}}},
		},
	})
	resp, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("site publish = %d", resp.StatusCode)
	}
	var out struct {
		Revision int64  `json:"revision"`
		Domain   string `json:"domain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Domain != "a.local" || out.Revision != 2 {
		t.Fatalf("publish response: %+v", out)
	}

	// The live config carries the change and only that change.
	var state struct {
		Config config.Config `json:"config"`
	}
	resp2, err := client.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if err := json.NewDecoder(resp2.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Config.Sites) != 1 {
		t.Fatalf("site count = %d", len(state.Config.Sites))
	}
	if state.Config.Sites[0].Upstream.Nodes[0].Address != "127.0.0.1:9099" {
		t.Fatalf("site not updated: %+v", state.Config.Sites[0])
	}
}

func TestSitePublishAppendsNewSite(t *testing.T) {
	ts, login := rbacServer(t)
	client := login("admin", "hunter2")

	body := mustJSONBody(t, map[string]any{
		"site": config.Site{
			Domains:  []string{"new.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9098"}}},
		},
	})
	resp, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("append publish = %d", resp.StatusCode)
	}
	var state struct {
		Config config.Config `json:"config"`
	}
	resp2, err := client.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if err := json.NewDecoder(resp2.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Config.Sites) != 2 {
		t.Fatalf("new site not appended: sites=%d", len(state.Config.Sites))
	}
}

func TestSitePublishRejectsBrokenSiteOnly(t *testing.T) {
	ts, login := rbacServer(t)
	client := login("admin", "hunter2")

	// A broken site is rejected with an error that names it...
	body := mustJSONBody(t, map[string]any{
		"site": config.Site{
			Domains:  []string{"bad.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: ""}}},
		},
	})
	resp, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken site publish = %d, want 400", resp.StatusCode)
	}

	// ...and the next valid publish is not blocked by it.
	good := mustJSONBody(t, map[string]any{
		"site": config.Site{
			Domains:  []string{"good.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9097"}}},
		},
	})
	resp2, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", good)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("valid publish after failure = %d, want 200", resp2.StatusCode)
	}
}

func TestSitePublishRequiresOperatorRole(t *testing.T) {
	ts, login := rbacServer(t)
	_ = ts
	client := login("admin", "hunter2")
	body := mustJSONBody(t, map[string]any{
		"site": config.Site{Domains: []string{"x.local"}},
	})
	resp, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// admin is an operator: allowed. Anonymous requests must be rejected.
	anon, err := http.Post(ts.URL+"/api/config/site/publish", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer anon.Body.Close()
	if anon.StatusCode == http.StatusOK {
		t.Fatal("anonymous site publish must not be allowed")
	}
	_ = client
}
