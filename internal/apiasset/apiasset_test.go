package apiasset

import (
	"testing"
	"time"
)

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/":                 "/",
		"/api/v1/users":     "/api/v1/users",
		"/api/v1/users/123": "/api/v1/users/{param}",
		"/api/v1/users/550e8400-e29b-41d4-a716-446655440000": "/api/v1/users/{param}",
		"/orders/20260915/items":                             "/orders/{param}/items",
		"/files/deadbeefdeadbeefdeadbeef":                    "/files/{param}",
		"/users/mail@example.com":                            "/users/{param}",
		"/a/b/c/d/e/f/g/h/i/j/k/l":                           "/a/b/c/d/e/f/g/h/i/j/...",
		"/search?q=1":                                        "/search",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyTags(t *testing.T) {
	if tags := ClassifyTags("/api/admin/console"); len(tags) == 0 || tags[0] != TagAdmin {
		t.Errorf("admin tags = %v", tags)
	}
	if tags := ClassifyTags("/api/v1/users"); len(tags) != 0 {
		t.Errorf("plain path tags = %v", tags)
	}
}

func TestQueryKeysAndJSONTopKeys(t *testing.T) {
	if keys := QueryKeys("a=1&b=2&a=3"); len(keys) != 2 {
		t.Errorf("query keys = %v", keys)
	}
	keys := JSONTopKeys([]byte(`{"user":"u","password":"p","nested":{"x":1}}`), 1<<20)
	if len(keys) != 3 || keys[0] != "user" || keys[1] != "password" || keys[2] != "nested" {
		t.Errorf("json keys = %v", keys)
	}
	if JSONTopKeys([]byte(`[1,2,3]`), 1<<20) != nil {
		t.Error("array body must yield no keys")
	}
	if JSONTopKeys([]byte("not json"), 1<<20) != nil {
		t.Error("non-json must yield no keys")
	}
}

func TestCollectorLearnAndPromote(t *testing.T) {
	store, err := Open(t.TempDir() + "/assets.db")
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(store, 3, nil)

	for i := 0; i < 5; i++ {
		c.Submit(AccessTick{
			Site: "s.local", Method: "GET", Path: "/api/v1/users/42",
			Status: 200, UA: "Mozilla/5.0 Chrome", ClientIP: "10.0.0.9",
			HasAuth: i%2 == 0, TS: time.Now(),
		})
	}
	c.Submit(AccessTick{Site: "s.local", Method: "GET", Path: "/one-off", Status: 404, ClientIP: "10.0.0.9", TS: time.Now()})
	time.Sleep(50 * time.Millisecond)
	c.Close() // final flush
	time.Sleep(50 * time.Millisecond)

	assets, total, err := store.ListAssets("", "", "", "", true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2; assets=%+v", total, assets)
	}
	var confirmed, candidate int
	for _, a := range assets {
		if a.NormPath == "/api/v1/users/{param}" && a.Hits == 5 && !a.Candidate {
			confirmed++
		}
		if a.NormPath == "/one-off" && a.Candidate {
			candidate++
		}
	}
	if confirmed != 1 || candidate != 1 {
		t.Fatalf("confirmed=%d candidate=%d", confirmed, candidate)
	}
	store.Close()
}

func TestCollectorBruteForceHook(t *testing.T) {
	store, err := Open(t.TempDir() + "/assets.db")
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(store, 5, nil)

	fired := make(chan string, 4)
	c.SetBruteForceHook(func(site, path, ip string, count int) {
		fired <- ip
	})
	for i := 0; i < 40; i++ {
		c.Submit(AccessTick{
			Site: "s.local", Method: "POST", Path: "/api/login",
			Status: 401, ClientIP: "203.0.113.99", TS: time.Now(),
		})
	}
	deadline := time.After(2 * time.Second)
	select {
	case ip := <-fired:
		if ip != "203.0.113.99" {
			t.Fatalf("hook ip = %q", ip)
		}
	case <-deadline:
		t.Fatal("brute force hook never fired")
	}
	c.Close()
	store.Close()
}
