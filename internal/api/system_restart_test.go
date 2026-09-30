package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/upgrade"
)

// restartServer builds an RBAC console (rbacServer shape) wired to the
// given upgrade service and a near-instant restart submission (test hook),
// returning the server, a login helper and the center for audit reads.
func restartServer(t *testing.T, svc *upgrade.Service) (*httptest.Server, func(user, pass string) *http.Client, *configcenter.Center) {
	t.Helper()
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "restart.db"), seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	srv := New(Options{SkipBootstrap: true, Center: center, Auth: NewAuth(hash), Upgrade: svc, SystemRestartDelay: 10 * time.Millisecond})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	login := func(user, pass string) *http.Client {
		body := mustJSON(t, map[string]string{"username": user, "password": pass})
		resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login %s = %d", user, resp.StatusCode)
		}
		return &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
	}
	return ts, login, center
}

// waitSubmit polls until the mock submitter has been invoked n times.
func waitSubmit(t *testing.T, calls *atomic.Int32, n int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("submitter invoked %d times, want >= %d", calls.Load(), n)
}

// auditRestartEntries returns the recorded change-audit entries.
func auditRestartEntries(t *testing.T, center *configcenter.Center) []map[string]any {
	t.Helper()
	logs, err := center.Store().ListChangeLogs(100)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range logs {
		out = append(out, map[string]any{
			"actor": l.Actor, "role": l.Role, "action": l.Action,
			"target": l.Target, "detail": l.Detail,
		})
	}
	return out
}

// TestSystemRestartRoleGate pins the role gate and the module-absent
// degradation: operator/auditor get 403 (the gate runs before the
// degradation check), the admin passes the gate and reaches the 501 of a
// console without a wired upgrade service.
func TestSystemRestartRoleGate(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")
	for _, tc := range []struct{ user, pass, role string }{
		{"ops", "operator-pw", "operator"},
		{"aud", "auditor-pw", "auditor"},
	} {
		if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
			"username": tc.user, "password": tc.pass, "role": tc.role,
		}); code != http.StatusOK {
			t.Fatalf("create %s = %d", tc.role, code)
		}
	}
	ops := login("ops", "operator-pw")
	aud := login("aud", "auditor-pw")

	if code := doJSON(t, ops, "POST", ts.URL+"/api/system/restart", nil); code != http.StatusForbidden {
		t.Fatalf("operator restart = %d, want 403", code)
	}
	if code := doJSON(t, aud, "POST", ts.URL+"/api/system/restart", nil); code != http.StatusForbidden {
		t.Fatalf("auditor restart = %d, want 403", code)
	}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/system/restart", nil); code != http.StatusNotImplemented {
		t.Fatalf("admin restart (module absent) = %d, want 501", code)
	}
}

// TestSystemRestartAdminSuccess: the admin happy path answers 200 with the
// restarting status, submits exactly once through the injected restarter,
// and leaves exactly one system.restart audit entry carrying the actor and
// the source IP.
func TestSystemRestartAdminSuccess(t *testing.T) {
	var submits atomic.Int32
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithProber(func() error { return nil }),
		upgrade.WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	ts, login, center := restartServer(t, svc)
	admin := login("admin", "hunter2")

	// Empty body = default delay.
	code, body := doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", nil)
	if code != http.StatusOK || body["status"] != "restarting" {
		t.Fatalf("restart = %d (%v), want 200 restarting", code, body)
	}
	waitSubmit(t, &submits, 1)

	entries := auditRestartEntries(t, center)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d (%v), want exactly one", len(entries), entries)
	}
	e := entries[0]
	if e["action"] != "system.restart" || e["actor"] != "admin" || e["role"] != "admin" {
		t.Fatalf("audit entry = %v, want system.restart by admin", e)
	}
	if e["target"] != "kingmoatwaf" {
		t.Fatalf("audit target = %v, want kingmoatwaf", e["target"])
	}
	detail, _ := e["detail"].(string)
	if !containsAll(detail, "source_ip=", "delay_seconds=0") {
		t.Fatalf("audit detail = %q, want source_ip and delay_seconds", detail)
	}

	// A valid extra delay is accepted too (submission fires later; the
	// response is final either way).
	code, body = doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", map[string]int{"delay_seconds": 30})
	if code != http.StatusOK || body["status"] != "restarting" {
		t.Fatalf("restart(delay=30) = %d (%v), want 200 restarting", code, body)
	}
}

// TestSystemRestartBodyBounds: out-of-range delay_seconds is a 400 and
// never reaches the submitter or the audit.
func TestSystemRestartBodyBounds(t *testing.T) {
	var submits atomic.Int32
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithProber(func() error { return nil }),
		upgrade.WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	ts, login, center := restartServer(t, svc)
	admin := login("admin", "hunter2")

	for _, delay := range []int{-1, 61} {
		code, body := doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", map[string]int{"delay_seconds": delay})
		if code != http.StatusBadRequest {
			t.Fatalf("restart(delay=%d) = %d (%v), want 400", delay, code, body)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if submits.Load() != 0 {
		t.Fatalf("submitter invoked %d times after 400s, want 0", submits.Load())
	}
	if entries := auditRestartEntries(t, center); len(entries) != 0 {
		t.Fatalf("audit entries = %v, want none", entries)
	}
}

// TestSystemRestartNotSystemd: a probe verdict of ErrRestartUnavailable
// (static/Windows/no-systemctl) answers 501 with manual guidance, never
// submits and records no audit entry.
func TestSystemRestartNotSystemd(t *testing.T) {
	var submits atomic.Int32
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithProber(func() error {
			return upgrade.ErrRestartUnavailable
		}),
		upgrade.WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	ts, login, center := restartServer(t, svc)
	admin := login("admin", "hunter2")

	code, body := doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", nil)
	if code != http.StatusNotImplemented {
		t.Fatalf("restart on non-systemd = %d (%v), want 501", code, body)
	}
	if msg, _ := body["error"].(string); !containsAll(msg, "手动", "systemctl restart") {
		t.Fatalf("501 body = %v, want manual guidance", body)
	}
	time.Sleep(50 * time.Millisecond)
	if submits.Load() != 0 {
		t.Fatalf("submitter invoked %d times after 501, want 0", submits.Load())
	}
	if entries := auditRestartEntries(t, center); len(entries) != 0 {
		t.Fatalf("audit entries = %v, want none", entries)
	}
}

// TestSystemRestartProbeFailure500: a systemd deployment that still cannot
// restart (e.g. non-root) answers 500 with the same manual guidance, never
// submits and records no audit entry.
func TestSystemRestartProbeFailure500(t *testing.T) {
	var submits atomic.Int32
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithProber(func() error {
			return errNonRootProbe
		}),
		upgrade.WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	ts, login, center := restartServer(t, svc)
	admin := login("admin", "hunter2")

	code, body := doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("restart with failed probe = %d (%v), want 500", code, body)
	}
	if msg, _ := body["error"].(string); !containsAll(msg, "手动", "systemctl restart") {
		t.Fatalf("500 body = %v, want manual guidance", body)
	}
	time.Sleep(50 * time.Millisecond)
	if submits.Load() != 0 {
		t.Fatalf("submitter invoked %d times after 500, want 0", submits.Load())
	}
	if entries := auditRestartEntries(t, center); len(entries) != 0 {
		t.Fatalf("audit entries = %v, want none", entries)
	}
}

// errNonRootProbe mimics the production non-root probe failure (500 class,
// distinct from ErrRestartUnavailable).
var errNonRootProbe = errors.New("当前进程非 root 运行，polkit 默认拒绝其重启 kingmoatwaf 服务")

// TestSystemRestartUpgradeInProgress: an in-flight upgrade task owns the
// process lifecycle - the API refuses a concurrent restart with 409
// BEFORE any probe, audit or submission, and the normal idle flow
// (probe → audit → 200 → submit) recovers once the task settles.
func TestSystemRestartUpgradeInProgress(t *testing.T) {
	var submits atomic.Int32
	release := make(chan struct{})
	svc := upgrade.NewService("v0.7.8-beta", t.TempDir(),
		upgrade.WithChecker(func(ctx context.Context) ([]upgrade.Release, error) {
			<-release
			return nil, errors.New("cancelled by test")
		}),
		upgrade.WithProber(func() error { return nil }),
		upgrade.WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	ts, login, center := restartServer(t, svc)
	admin := login("admin", "hunter2")

	task, err := svc.Start("")
	if err != nil {
		t.Fatal(err)
	}
	if _, busy := svc.Running(); !busy {
		t.Fatal("upgrade task not in flight right after Start")
	}
	code, body := doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", nil)
	if code != http.StatusConflict {
		t.Fatalf("restart during upgrade = %d (%v), want 409", code, body)
	}
	if msg, _ := body["error"].(string); !containsAll(msg, "升级任务进行中", "禁止重启") {
		t.Fatalf("409 body = %v, want the upgrade-in-progress refusal", body)
	}
	time.Sleep(50 * time.Millisecond)
	if submits.Load() != 0 {
		t.Fatalf("submitter invoked %d times during upgrade, want 0", submits.Load())
	}
	if entries := auditRestartEntries(t, center); len(entries) != 0 {
		t.Fatalf("audit entries = %v, want none during upgrade", entries)
	}

	// Settle the task (checker unblocked → detect-stage failure) and the
	// restart path returns to the normal idle flow.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, busy := svc.Running(); !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upgrade task %s never settled", task.ID)
		}
		time.Sleep(5 * time.Millisecond)
	}
	code, body = doJSONBody(t, admin, "POST", ts.URL+"/api/system/restart", nil)
	if code != http.StatusOK || body["status"] != "restarting" {
		t.Fatalf("restart after upgrade settled = %d (%v), want 200 restarting", code, body)
	}
	waitSubmit(t, &submits, 1)
}

// containsAll reports whether s contains every substring.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
