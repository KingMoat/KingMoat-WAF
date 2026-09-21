package logshipper

import (
	"encoding/json"
	"strings"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

func TestLokiShipperBatchesAndPushes(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/push" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		payloads = append(payloads, m)
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := New(config.ShipperSettings{
		Type: "loki", URL: ts.URL, Index: "kingmoat-test",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	for i := 0; i < 3; i++ {
		sh.Write(&logstore.Event{
			TS:     time.Now().UTC().Format(time.RFC3339Nano),
			Action: "blocked",
			Rule:   "semantic/sqli",
			Site:   "t.local",
			Path:   "/p",
		})
	}

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) == 0 {
		t.Fatal("no payload delivered")
	}
	streams, _ := payloads[0]["streams"].([]any)
	if len(streams) == 0 {
		t.Fatal("loki payload missing streams")
	}
}

func TestShipperRejectsUnknownType(t *testing.T) {
	if _, err := New(config.ShipperSettings{Type: "kafka", URL: "http://x"}, nil); err == nil {
		t.Fatal("unknown type must be rejected")
	}
}

func TestShipperDropsUnderBackpressure(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer ts.Close()

	sh, err := newShipper(config.ShipperSettings{Type: "elasticsearch", URL: ts.URL, BatchSize: 1, FlushSec: 60, TimeoutSec: 1}, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Release the hanging server before Close drains the queue (LIFO).
	defer close(release)
	defer sh.Close()

	for i := 0; i < 20; i++ {
		sh.Write(&logstore.Event{TS: time.Now().Format(time.RFC3339Nano), Action: "blocked"})
	}
	if sh.Dropped() == 0 {
		t.Fatal("expected drops under backpressure")
	}
}

func TestClickHouseShipperBatchesAndPushes(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var queries []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		queries = append(queries, r.URL.Query().Get("query"))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := New(config.ShipperSettings{
		Type: "clickhouse", URL: ts.URL, Index: "kingmoat_events",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	for i := 0; i < 3; i++ {
		sh.Write(&logstore.Event{
			TS: time.Now().UTC().Format(time.RFC3339Nano),
			Action: "blocked", Rule: "semantic/sqli", Site: "t.local",
		})
	}

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no payload delivered")
	}
	if !strings.Contains(queries[0], "INSERT INTO kingmoat_events FORMAT JSONEachRow") {
		t.Fatalf("bad CH query: %q", queries[0])
	}
	var ev logstore.Event
	if err := json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(bodies[0]), "\n", 2)[0]), &ev); err != nil {
		t.Fatalf("row is not JSON: %v", err)
	}
	if ev.Rule != "semantic/sqli" {
		t.Fatalf("row mismatch: %+v", ev)
	}
}
