package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestUpstreamTransportTuning(t *testing.T) {
	tr := newUpstreamTransport(config.Upstream{})
	if tr.Proxy != nil {
		t.Fatal("upstream transport must not inherit HTTP(S)_PROXY environment settings")
	}
	if tr.MaxIdleConnsPerHost != upstreamMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, upstreamMaxIdleConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 must stay enabled so https upstreams can use h2")
	}
	if tr.IdleConnTimeout <= 0 {
		t.Fatal("IdleConnTimeout must be set so idle connections are reaped")
	}
}

func TestReverseProxyReusesUpstreamConnections(t *testing.T) {
	var conns atomic.Int64
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	up.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	up.Start()
	defer up.Close()

	h, err := NewReloadable(reloadTestCfg(strings.TrimPrefix(up.URL, "http://"), false), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	burst := func(path string, n int) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil))
				if rec.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rec.Code)
				}
			}()
		}
		wg.Wait()
	}

	burst("/wave1", 50)
	time.Sleep(100 * time.Millisecond) // let wave1 connections settle into the idle pool
	burst("/wave2", 50)

	// With a tuned keep-alive pool the second wave must ride wave1's idle
	// connections (total ~= 50). The stock DefaultTransport keeps only 2 idle
	// conns per host and would re-open ~48 more (~98 total).
	if got := conns.Load(); got > 75 {
		t.Fatalf("upstream connections opened = %d, want <= 75 (keep-alive pool not reused)", got)
	}
}

func TestReloadClosesIdleUpstreamConnections(t *testing.T) {
	var conns, closed atomic.Int64
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	up.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			conns.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	up.Start()
	defer up.Close()
	addr := strings.TrimPrefix(up.URL, "http://")

	h, err := NewReloadable(reloadTestCfg(addr, false), nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadable: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-reload status = %d", rec.Code)
	}

	if err := h.Reload(reloadTestCfg(addr, true)); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conns.Load() > 0 && closed.Load() >= conns.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("idle upstream connections not closed after reload: opened=%d closed=%d",
		conns.Load(), closed.Load())
}
