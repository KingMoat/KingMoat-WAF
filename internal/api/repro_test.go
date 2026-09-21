package api

import (
	"encoding/json"
	"bytes"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestReproSmokeIsolationHTTP(t *testing.T) {
	ts, login := rbacServer(t)
	client := login("admin", "hunter2")

	post := func(name string, body any) {
		req, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Post(ts.URL+"/api/config/site/publish", "application/json", bytes.NewReader(req))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf [1024]byte
		n, _ := resp.Body.Read(buf[:])
		t.Logf("%s -> %d body: %s", name, resp.StatusCode, string(buf[:n]))
	}

	// rev 2: strong profile on a.local (same as smoke)
	post("rev2 strong", map[string]any{
		"domain": "a.local",
		"note":   "smoke site publish",
		"site": config.Site{
			Domains:    []string{"a.local"},
			WAF:        &config.WAFSettings{Enabled: boolPtr(true)},
			TLSProfile: "strong",
			Upstream:   config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:19090"}}},
		},
	})

	// broken site
	post("bad.local", map[string]any{
		"domain": "bad.local",
		"site": config.Site{
			Domains:  []string{"bad.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: ""}}},
		},
	})

	// good site after failure
	post("good c.local", map[string]any{
		"domain": "c.local",
		"site": config.Site{
			Domains:  []string{"c.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:19090"}}},
		},
	})

	// final config
	resp, err := client.Get(ts.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var state struct {
		Revision int64         `json:"revision"`
		Config   config.Config `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	for i, s := range state.Config.Sites {
		t.Logf("final sites[%d] = %v upstream=%v", i, s.Domains, s.Upstream.Nodes)
	}
	if len(state.Config.Sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(state.Config.Sites))
	}
}

func boolPtr(b bool) *bool { return &b }
