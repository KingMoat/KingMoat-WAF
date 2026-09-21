package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCompletionsEndpointNormalization pins the four base_url shapes the
// console receives: a bare host (the classic "llm status 404: 404 page not
// found" when posted to /chat/completions), a /v1 root, a full endpoint used
// verbatim, and a custom path (template defaults like GLM /api/paas/v4 or
// Volcano /api/v3) that must keep the user's path.
func TestCompletionsEndpointNormalization(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare host gains /v1", "https://gw.example.com", "https://gw.example.com/v1/chat/completions"},
		{"v1 root appends chat completions", "https://api.openai.com/v1", "https://api.openai.com/v1/chat/completions"},
		{"full endpoint used verbatim", "https://gw.example.com/v1/chat/completions", "https://gw.example.com/v1/chat/completions"},
		{"custom path keeps user input", "https://open.bigmodel.cn/api/paas/v4", "https://open.bigmodel.cn/api/paas/v4/chat/completions"},
		{"trailing slash on v1", "https://api.openai.com/v1/", "https://api.openai.com/v1/chat/completions"},
		{"trailing slash on bare host", "https://gw.example.com/", "https://gw.example.com/v1/chat/completions"},
		{"http scheme (self-hosted)", "http://127.0.0.1:8000", "http://127.0.0.1:8000/v1/chat/completions"},
		{"volcano api/v3 path", "https://ark.cn-beijing.volces.com/api/v3", "https://ark.cn-beijing.volces.com/api/v3/chat/completions"},
		{"unparseable input falls back to append", "not a url", "not a url/chat/completions"},
	}
	for _, tc := range cases {
		if got := completionsEndpoint(tc.in); got != tc.want {
			t.Errorf("%s: completionsEndpoint(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestClientPostsNormalizedEndpoint drives a real request through the client
// with a path-less base_url and asserts the server saw the /v1-prefixed
// completions path (the end-to-end regression for the gateway 404).
func TestClientPostsNormalizedEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{}}`))
	}))
	defer srv.Close()

	// httptest URLs have no path — exactly the shape that produced the 404.
	p := &ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	client, err := NewClient(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("request path = %q, want /v1/chat/completions", gotPath)
	}
}
