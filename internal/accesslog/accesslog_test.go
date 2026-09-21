package accesslog

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestShipperClickHouseJSONEachRow(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var paths []string
	got := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		paths = append(paths, r.URL.Query().Get("query"))
		mu.Unlock()
		got <- struct{}{}
	}))
	defer ts.Close()

	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "clickhouse", URL: ts.URL, Index: "kingmoat_access",
		BatchSize: 2, FlushSec: 1, TimeoutSec: 2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	for i := 0; i < 3; i++ {
		sh.Write(&Entry{
			TS: time.Now().UTC().Format(time.RFC3339Nano), Site: "t.local",
			Method: "GET", Path: "/a", Status: 200, Outcome: "forwarded",
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
	if !strings.Contains(paths[0], "INSERT INTO kingmoat_access FORMAT JSONEachRow") {
		t.Fatalf("bad CH query: %q", paths[0])
	}
	lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
	if len(lines) < 1 {
		t.Fatal("empty JSONEachRow body")
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("row is not JSON: %v", err)
	}
	if e.Outcome != "forwarded" {
		t.Fatalf("row content mismatch: %+v", e)
	}
}

func TestSampling(t *testing.T) {
	sh, err := New(config.AccessLogSettings{
		Enabled: true, Type: "loki", URL: "http://127.0.0.1:1", Index: "x",
		SamplePct: 0, // invalid → treated as 100%
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if sh.samplePct != 100 {
		t.Fatalf("sample pct = %d, want 100", sh.samplePct)
	}
}

func TestRecorderCapturesStatusAndBytes(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusForbidden)
	rec.Write([]byte("blocked-by-kingmoat"))
	if rec.Status() != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Status())
	}
	if rec.BytesWritten() != len("blocked-by-kingmoat") {
		t.Fatalf("bytes = %d", rec.BytesWritten())
	}
}

func TestRecorderHijackUnsupported(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("plain recorder must not support hijack")
	}
}

func TestShipperRejectsUnknownType(t *testing.T) {
	if _, err := New(config.AccessLogSettings{Enabled: true, Type: "kafka", URL: "http://x"}, nil); err == nil {
		t.Fatal("unknown type must be rejected")
	}
}
