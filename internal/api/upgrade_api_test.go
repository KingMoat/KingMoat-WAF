package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/upgrade"
)

// upgradeServer builds a console server wired to the given upgrade service
// (nil = module absent, endpoints must degrade to 501).
func upgradeServer(t *testing.T, svc *upgrade.Service) (*Server, *httptest.Server) {
	t.Helper()
	seed := &config.Config{ListenHTTP: "0.0.0.0:8080"}
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "upgrade.db"), seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	srv := New(Options{SkipBootstrap: true, Center: center, Version: "v0.7.8-beta", Upgrade: svc})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// cannedReleases is a deterministic releases feed: v0.7.9-beta is newer
// than the test server's v0.7.8-beta build.
func cannedReleases() []upgrade.Release {
	return []upgrade.Release{
		{TagName: "v0.7.7-beta", Name: "v0.7.7-beta", Body: "older release"},
		{TagName: "v0.7.9-beta", Name: "v0.7.9-beta", Body: "新版本说明"},
	}
}

// postEmpty issues a POST with no request body (the "upgrade to latest"
// call shape) and decodes the JSON response.
func postEmpty(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	return resp.StatusCode, out
}

// waitTaskState polls GET /api/upgrade/task until the task reports want.
func waitTaskState(t *testing.T, ts *httptest.Server, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ts.URL + "/api/upgrade/task?id=" + id)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		decodeInto(t, resp, &out)
		if out["state"] == want {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s never reached state %s", id, want)
	return nil
}

// TestUpgradeDisabled pins the degraded mode: without a wired upgrade
// service every endpoint answers 501 with a reason (registered routes, not
// 404s), mirroring the console-port changeable=false convention.
func TestUpgradeDisabled(t *testing.T) {
	_, ts := upgradeServer(t, nil)

	resp, err := http.Get(ts.URL + "/api/upgrade/status")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d (%v), want 501", resp.StatusCode, out)
	}
	if msg, _ := out["error"].(string); msg == "" {
		t.Fatalf("501 body missing reason: %v", out)
	}

	for _, tc := range []struct {
		name, method, url string
	}{
		{"check", "POST", ts.URL + "/api/upgrade/check"},
		{"start", "POST", ts.URL + "/api/upgrade/start"},
		{"task", "GET", ts.URL + "/api/upgrade/task?id=x"},
	} {
		req, err := http.NewRequest(tc.method, tc.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		decodeInto(t, resp, &body)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s = %d (%v), want 501", tc.name, resp.StatusCode, body)
		}
	}
}

// TestUpgradeStatusCache covers the 60s TTL cache: first call checks live,
// repeat calls are served from the cache, ?refresh=1 bypasses it, TTL
// expiry (backdated timestamp, no waiting) re-checks, and POST check
// bypasses and repopulates the cache.
func TestUpgradeStatusCache(t *testing.T) {
	checks := 0
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithChecker(func(context.Context) ([]upgrade.Release, error) {
			checks++
			return cannedReleases(), nil
		}))
	srv, ts := upgradeServer(t, svc)

	getStatus := func(url string) map[string]any {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		decodeInto(t, resp, &out)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d (%v), want 200", url, resp.StatusCode, out)
		}
		return out
	}

	// First call: live check, full snapshot shape.
	out := getStatus(ts.URL + "/api/upgrade/status")
	if out["version"] != "v0.7.8-beta" {
		t.Fatalf("version = %v, want v0.7.8-beta", out["version"])
	}
	latest, _ := out["latest"].(map[string]any)
	if latest["version"] != "v0.7.9-beta" || latest["update_available"] != true {
		t.Fatalf("latest = %v, want v0.7.9-beta update_available", latest)
	}
	if out["running_task"] != nil {
		t.Fatalf("running_task = %v, want null", out["running_task"])
	}
	if hist, _ := out["history"].([]any); len(hist) != 0 {
		t.Fatalf("history = %v, want empty", out["history"])
	}
	if checks != 1 {
		t.Fatalf("checks = %d, want 1", checks)
	}

	// Second call: cache hit, no new feed request.
	getStatus(ts.URL + "/api/upgrade/status")
	if checks != 1 {
		t.Fatalf("checks = %d after cached call, want still 1", checks)
	}

	// refresh=1 forces a live check.
	getStatus(ts.URL + "/api/upgrade/status?refresh=1")
	if checks != 2 {
		t.Fatalf("checks = %d after refresh, want 2", checks)
	}
	// ...and repopulates the cache for the next plain call.
	getStatus(ts.URL + "/api/upgrade/status")
	if checks != 2 {
		t.Fatalf("checks = %d after refresh-backed call, want still 2", checks)
	}

	// TTL expiry: backdate the fetch timestamp instead of waiting 60s.
	srv.upgCache.mu.Lock()
	srv.upgCache.fetched = time.Now().Add(-upgradeCheckTTL - time.Second)
	srv.upgCache.mu.Unlock()
	getStatus(ts.URL + "/api/upgrade/status")
	if checks != 3 {
		t.Fatalf("checks = %d after TTL expiry, want 3", checks)
	}

	// POST check bypasses the cache and repopulates it.
	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/upgrade/check", nil)
	if code != http.StatusOK || body["version"] != "v0.7.9-beta" || body["update_available"] != true {
		t.Fatalf("POST check = %d (%v), want 200 with latest view", code, body)
	}
	if checks != 4 {
		t.Fatalf("checks = %d after forced check, want 4", checks)
	}
	getStatus(ts.URL + "/api/upgrade/status")
	if checks != 4 {
		t.Fatalf("checks = %d after check-backed status, want still 4", checks)
	}
}

// TestUpgradeCheckFailures covers the failure mappings: an unreachable feed
// answers 502 on POST check and degrades the status snapshot to
// latest=null (200), while a dev build (no upgrade lineage) answers 400 on
// check and start.
func TestUpgradeCheckFailures(t *testing.T) {
	failing := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithChecker(func(context.Context) ([]upgrade.Release, error) {
			return nil, errors.New("gitee unreachable")
		}))
	_, ts := upgradeServer(t, failing)

	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/upgrade/check", nil)
	if code != http.StatusBadGateway {
		t.Fatalf("POST check = %d (%v), want 502", code, body)
	}
	if msg, _ := body["error"].(string); msg == "" {
		t.Fatalf("502 body missing error: %v", body)
	}
	resp, err := http.Get(ts.URL + "/api/upgrade/status")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if resp.StatusCode != http.StatusOK || out["latest"] != nil || out["version"] != "v0.7.8-beta" {
		t.Fatalf("status with failing feed = %d (%v), want 200 with latest null", resp.StatusCode, out)
	}

	dev := upgrade.NewService("dev", t.TempDir(),
		upgrade.WithChecker(func(context.Context) ([]upgrade.Release, error) {
			return cannedReleases(), nil
		}))
	_, devTS := upgradeServer(t, dev)
	code, _ = doJSONBody(t, http.DefaultClient, "POST", devTS.URL+"/api/upgrade/check", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("dev build check = %d, want 400", code)
	}
	code, _ = postEmpty(t, devTS.URL+"/api/upgrade/start")
	if code != http.StatusBadRequest {
		t.Fatalf("dev build start = %d, want 400", code)
	}
}

// TestUpgradeStartTaskFlow drives the task lifecycle through the API with
// test-injected pipeline hooks: start (empty body = latest) returns a task
// id, the task is pollable, a concurrent start answers 409 with the running
// task, and the settled task lands in history with nothing running.
func TestUpgradeStartTaskFlow(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(release) }) }
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithChecker(func(context.Context) ([]upgrade.Release, error) {
			return cannedReleases(), nil
		}),
		upgrade.WithDownloader(func(ctx context.Context, _ *upgrade.Task, _ *upgrade.Release) (string, error) {
			<-release
			return "", errors.New("stopped by test")
		}),
		upgrade.WithVerifier(func(context.Context, *upgrade.Task, *upgrade.Release, string) (string, error) {
			return "", errors.New("unreachable")
		}),
		upgrade.WithReplacer(func(context.Context, *upgrade.Task) error { return errors.New("unreachable") }),
		upgrade.WithRestarter(func(context.Context, *upgrade.Task) error { return errors.New("unreachable") }),
	)
	t.Cleanup(stop)
	_, ts := upgradeServer(t, svc)

	// Invalid target version: rejected before any task exists.
	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/upgrade/start",
		map[string]any{"target_version": "garbage"})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid target = %d (%v), want 400", code, body)
	}

	// Empty body = upgrade to latest: the task starts and blocks in the
	// (test) download stage.
	code, body = postEmpty(t, ts.URL+"/api/upgrade/start")
	if code != http.StatusOK {
		t.Fatalf("start = %d (%v), want 200", code, body)
	}
	id, _ := body["task_id"].(string)
	if id == "" {
		t.Fatalf("start response missing task_id: %v", body)
	}
	waitTaskState(t, ts, id, upgrade.TaskDownloading)

	// Concurrent start: 409 carrying the running task.
	code, body = doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/upgrade/start",
		map[string]any{"target_version": ""})
	if code != http.StatusConflict {
		t.Fatalf("second start = %d (%v), want 409", code, body)
	}
	running, _ := body["task"].(map[string]any)
	if running == nil || running["id"] != id {
		t.Fatalf("409 body = %v, want the running task %s", body, id)
	}

	// Release the download stage: the task settles as failed.
	stop()
	task := waitTaskState(t, ts, id, upgrade.TaskFailed)
	if msg, _ := task["error"].(string); msg == "" {
		t.Fatalf("failed task missing error: %v", task)
	}

	// Status composes the settled task; nothing is running anymore.
	resp, err := http.Get(ts.URL + "/api/upgrade/status")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if out["running_task"] != nil {
		t.Fatalf("running_task = %v, want null after failure", out["running_task"])
	}
	hist, _ := out["history"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history = %v, want exactly the failed task", out["history"])
	}
	entry, _ := hist[0].(map[string]any)
	if entry["id"] != id || entry["state"] != upgrade.TaskFailed {
		t.Fatalf("history entry = %v, want failed task %s", entry, id)
	}
}

// TestUpgradeTaskLookup covers the task endpoint's argument handling: a
// missing id is 400, an unknown id is 404.
func TestUpgradeTaskLookup(t *testing.T) {
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithChecker(func(context.Context) ([]upgrade.Release, error) {
			return cannedReleases(), nil
		}))
	_, ts := upgradeServer(t, svc)

	resp, err := http.Get(ts.URL + "/api/upgrade/task")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing id = %d (%v), want 400", resp.StatusCode, out)
	}

	resp, err = http.Get(ts.URL + "/api/upgrade/task?id=deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	decodeInto(t, resp, &out)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id = %d (%v), want 404", resp.StatusCode, out)
	}
}

// TestUpgradeAdminGate pins the role gate: a non-admin account gets 403 on
// every upgrade endpoint (the gate runs before the degradation check), an
// admin passes the gate and reaches the module-absent 501.
func TestUpgradeAdminGate(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")
	const audPass = "hunter2x"
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "aud", "password": audPass, "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create auditor = %d", code)
	}
	aud := login("aud", audPass)

	endpoints := []struct {
		method, url string
	}{
		{"GET", ts.URL + "/api/upgrade/status"},
		{"POST", ts.URL + "/api/upgrade/check"},
		{"POST", ts.URL + "/api/upgrade/start"},
		{"GET", ts.URL + "/api/upgrade/task?id=x"},
	}
	for _, ep := range endpoints {
		if code := doJSON(t, aud, ep.method, ep.url, nil); code != http.StatusForbidden {
			t.Fatalf("auditor %s %s = %d, want 403", ep.method, ep.url, code)
		}
	}
	if code := doJSON(t, admin, "GET", ts.URL+"/api/upgrade/status", nil); code != http.StatusNotImplemented {
		t.Fatalf("admin status = %d, want 501 (gate passed, module absent)", code)
	}
}
