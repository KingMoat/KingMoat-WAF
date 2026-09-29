package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
)

// applyConsumer mimics the all-in-one hot-reload consumer: it applies each
// published revision and reports the outcome to the center. errFor decides
// the reported result per revision (nil = applied).
func applyConsumer(c *configcenter.Center, errFor func(rev int64) error) (cancel func()) {
	ch, cancelFn := c.Subscribe()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case ev := <-ch:
				var err error
				if errFor != nil {
					err = errFor(ev.Rev)
				}
				c.SetApplyStatus(ev.Rev, err)
			}
		}
	}()
	return func() { cancelFn(); close(stop); <-done }
}

func postPublish(t *testing.T, ts *httptest.Server, note string, cfg *config.Config) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"note": note, "config": cfg})
	resp, err := http.Post(ts.URL+"/api/config/publish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func applyOf(t *testing.T, out map[string]any) (rev int64, status, errMsg string) {
	t.Helper()
	m, ok := out["apply"].(map[string]any)
	if !ok {
		t.Fatalf("publish response missing apply object: %v", out)
	}
	if v, ok := m["revision"].(float64); ok {
		rev = int64(v)
	}
	status, _ = m["status"].(string)
	errMsg, _ = m["error"].(string)
	return rev, status, errMsg
}

// TestPublishApplyThreeStates: the publish response reports exactly the
// consumer-reported outcome for the published revision 鈥?applied, failed
// (error carried through) and pending (slow consumer).
func TestPublishApplyThreeStates(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/pub.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	srv := New(Options{SkipBootstrap: true, Center: center})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	oldWait := publishApplyWait
	publishApplyWait = 300 * time.Millisecond
	defer func() { publishApplyWait = oldWait }()

	var failRev int64
	var once sync.Once
	consumerCancel := applyConsumer(center, func(rev int64) error {
		if rev == failRev {
			return simpleError("site router: read tls_cert: open /data/x.pem: no such file")
		}
		return nil
	})
	cancel := func() { once.Do(consumerCancel) }
	defer cancel()

	// applied path.
	code, out := postPublish(t, ts, "ok", twoSiteTestCfg())
	if code != http.StatusOK {
		t.Fatalf("publish code = %d", code)
	}
	rev, status, errMsg := applyOf(t, out)
	if status != "applied" || errMsg != "" || rev != 2 {
		t.Fatalf("apply = rev %d %q %q, want rev2 applied", rev, status, errMsg)
	}

	// failed path: revision stored, engine kept the old one, error visible.
	failRev = 3
	code, out = postPublish(t, ts, "broken", threeSiteTestCfg())
	if code != http.StatusOK {
		t.Fatalf("publish code = %d (failed applies still store the revision)", code)
	}
	rev, status, errMsg = applyOf(t, out)
	if status != "failed" || errMsg == "" || rev != 3 {
		t.Fatalf("apply = rev %d %q %q, want rev3 failed with error", rev, status, errMsg)
	}
	if _, cfg := center.Current(); len(cfg.Sites) != 3 {
		t.Fatalf("failed publish must still store the revision: sites=%d", len(cfg.Sites))
	}
	failRev = 0
	cancel() // stop the reporting consumer before the pending path

	// pending path: a consumer that drains events but never reports any
	// apply outcome (engine stuck/slow) → the publish response stays pending.
	publishApplyWait = 150 * time.Millisecond
	ch, cancelFn := center.Subscribe()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-ch:
			}
		}
	}()
	_, out = postPublish(t, ts, "slow", twoSiteTestCfg())
	_, status, _ = applyOf(t, out)
	if status != "pending" {
		t.Fatalf("apply status = %q, want pending", status)
	}
	cancelFn()
	close(stop)
	<-done
}

// TestPublishApplyMismatchRegression locks the WaitForApply fix at the API
// boundary: rev N fails, rev N+1 succeeds 鈥?the response for N must be
// "failed", never masked by the newer revision's "applied" (and vice versa).
func TestPublishApplyMismatchRegression(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/mis.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	srv := New(Options{SkipBootstrap: true, Center: center})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cancel := applyConsumer(center, func(rev int64) error {
		if rev == 2 {
			return simpleError("site router: duplicate domain")
		}
		return nil
	})
	defer cancel()

	// rev2 fails, rev3 succeeds immediately after.
	_, out := postPublish(t, ts, "broken", twoSiteTestCfg())
	_, status, errMsg := applyOf(t, out)
	if status != "failed" || errMsg == "" {
		t.Fatalf("rev2 apply = %q %q, want failed with error (not masked by rev3)", status, errMsg)
	}
	_, out = postPublish(t, ts, "fixed", threeSiteTestCfg())
	_, status, _ = applyOf(t, out)
	if status != "applied" {
		t.Fatalf("rev3 apply = %q, want applied", status)
	}

	// Reverse order: a success followed by a failure must not let the older
	// success stand in for the newer failure.
	center2, _ := configcenter.Open(t.TempDir()+"/mis2.db", seedCfg(), nil)
	defer center2.Close()
	srv2 := New(Options{SkipBootstrap: true, Center: center2})
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	cancel2 := applyConsumer(center2, func(rev int64) error {
		if rev == 3 {
			return simpleError("geo: open db failed")
		}
		return nil
	})
	defer cancel2()
	_, out = postPublish(t, ts2, "ok", twoSiteTestCfg())
	_, status, _ = applyOf(t, out)
	if status != "applied" {
		t.Fatalf("rev2 apply = %q, want applied", status)
	}
	_, out = postPublish(t, ts2, "broken-geo", threeSiteTestCfg())
	_, status, errMsg = applyOf(t, out)
	if status != "failed" || errMsg == "" {
		t.Fatalf("rev3 apply = %q %q, want failed with error", status, errMsg)
	}
}

// TestStatusDualRevision: /api/status exposes the engine's running revision
// and the config store head, so the console can warn on divergence.
func TestStatusDualRevision(t *testing.T) {
	center, err := configcenter.Open(t.TempDir()+"/st.db", seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	_, err = center.Publish(twoSiteTestCfg(), "t", "v2")
	if err != nil {
		t.Fatal(err)
	}

	running := int64(1) // engine still on rev1 (failed publish kept old state)
	srv := New(Options{SkipBootstrap: true, Center: center, RunningRevisionFn: func() int64 { return running }})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func() map[string]any {
		resp, err := http.Get(ts.URL + "/api/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	out := get()
	latest, _ := out["latest_revision"].(float64)
	run, _ := out["running_revision"].(float64)
	if int64(latest) != 2 || int64(run) != 1 {
		t.Fatalf("status latest=%v running=%v, want 2/1 (divergent)", latest, run)
	}
	if _, ok := out["apply"].(map[string]any); !ok {
		t.Fatalf("status missing apply object: %v", out)
	}

	running = 2 // engine caught up
	out = get()
	latest, _ = out["latest_revision"].(float64)
	run, _ = out["running_revision"].(float64)
	if int64(latest) != 2 || int64(run) != 2 {
		t.Fatalf("status latest=%v running=%v, want 2/2 (aligned)", latest, run)
	}
}

// TestStatusNoRunningFn: without a wired data plane (remote/static assemblies)
// running falls back to latest so no false divergence is reported.
func TestStatusNoRunningFn(t *testing.T) {
	center, _ := configcenter.Open(t.TempDir()+"/st2.db", seedCfg(), nil)
	defer center.Close()
	srv := New(Options{SkipBootstrap: true, Center: center})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	latest, _ := out["latest_revision"].(float64)
	run, _ := out["running_revision"].(float64)
	if int64(latest) != 1 || int64(run) != 1 {
		t.Fatalf("status latest=%v running=%v, want 1/1 (no false divergence)", latest, run)
	}
}

func twoSiteTestCfg() *config.Config {
	c := seedCfg()
	c.Sites = append(c.Sites, config.Site{
		Domains:  []string{"b.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9002"}}},
	})
	return c
}

func threeSiteTestCfg() *config.Config {
	c := twoSiteTestCfg()
	c.Sites = append(c.Sites, config.Site{
		Domains:  []string{"c.local"},
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9003"}}},
	})
	return c
}
