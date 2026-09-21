package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// TestAssetsSnapshotConcurrentSwap pins the P0 race fix: asset/risk handlers
// must read exactly one immutable AssetsOptions snapshot per request while a
// rebuild goroutine swaps fresh snapshots into the atomic container. The
// previous in-place mutation of a shared struct raced the two-phase handler
// reads (nil-check → use) on every publish; under -race any regression here
// fails this test.
func TestAssetsSnapshotConcurrentSwap(t *testing.T) {
	center := mustCenter(t)
	audit, err := logstore.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Close() })

	st, err := apiasset.Open(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	col := apiasset.NewCollector(st, 1, nil)
	t.Cleanup(func() { _ = col.Close() })
	eng := apiasset.NewEngine(st, nil, apiasset.NewWebhookNotifier("", nil), nil)

	ref := &atomic.Pointer[AssetsOptions]{}
	ref.Store(&AssetsOptions{Store: st})
	srv := New(Options{SkipBootstrap: true, Center: center, Logs: audit, AssetsRef: ref})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Two immutable snapshots alternate: module off vs module on (with
	// collector + risk engine). Handlers must tolerate either, never a torn
	// mix (e.g. Engine present while the nil-check saw none).
	on := &AssetsOptions{Store: st, Collector: col, Engine: eng, RisksEnabled: true}
	off := &AssetsOptions{Store: st}

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			if i%2 == 0 {
				ref.Store(on)
			} else {
				ref.Store(off)
			}
		}
	}()

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/risks"},
		{http.MethodPost, "/api/risks/scan"},
		{http.MethodGet, "/api/assets/apis"},
		{http.MethodGet, "/api/assets/sites"},
	}
	var requests sync.WaitGroup
	for g := 0; g < 4; g++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			for j := 0; j < 100; j++ {
				for _, p := range paths {
					req, err := http.NewRequest(p.method, ts.URL+p.path, nil)
					if err != nil {
						t.Error(err)
						return
					}
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Error(err)
						return
					}
					resp.Body.Close()
					// Both snapshots answer 200 (scan on the "off" snapshot
					// answers 404 module-disabled — also a valid outcome).
					if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
						t.Errorf("%s %s = %d, want 200 or 404", p.method, p.path, resp.StatusCode)
						return
					}
				}
			}
		}()
	}
	requests.Wait()
	close(stop)
	swapper.Wait()
}
