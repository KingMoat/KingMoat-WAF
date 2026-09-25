package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
)

// portServer builds a console API wired for port-change tests: the process
// reports console port 9443, the EnvironmentFile lives in a temp data dir,
// the restart is captured (never actually executed) and the occupancy probe
// is injectable (nil = real net.Listen probe).
func portServer(t *testing.T, probe func(int) error) (*httptest.Server, string, *[]int) {
	t.Helper()
	seed := &config.Config{
		ListenHTTP:  "0.0.0.0:8080",
		ListenHTTPS: "0.0.0.0:8443",
		Sites: []config.Site{{
			Domains:  []string{"a.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9001"}}},
		}},
	}
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "port.db"), seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	envPath := filepath.Join(t.TempDir(), "console.env")
	var restarted []int
	srv := New(Options{
		SkipBootstrap:  true,
		Center:         center,
		ConsolePort:    9443,
		ConsoleEnvPath: envPath,
		PortProbe:      probe,
		RestartDelay:   time.Millisecond,
		Restart: func() error {
			restarted = append(restarted, 1)
			return nil
		},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, envPath, &restarted
}

// waitRestarted polls until the captured restart count reaches want.
func waitRestarted(t *testing.T, got *[]int, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(*got) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("restart count = %d, want >= %d", len(*got), want)
}

// TestConsolePortGet covers the settings-card read: the boot-time port and
// the changeable flag (true only for a fully wired systemd deployment: env
// path set, file present, process started by systemd).
func TestConsolePortGet(t *testing.T) {
	t.Setenv("INVOCATION_ID", "test-invocation")
	ts, envPath, _ := portServer(t, nil)
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/api/settings/console-port")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if out["port"].(float64) != 9443 {
		t.Fatalf("port = %v, want 9443", out["port"])
	}
	if out["changeable"] != true {
		t.Fatalf("changeable = %v, want true", out["changeable"])
	}
	if _, has := out["reason"]; has {
		t.Fatalf("changeable response must not carry a reason: %v", out)
	}
}

// TestConsolePortDisabled covers the degraded mode (no EnvironmentFile
// wired): GET stays readable, POST answers 501 and never restarts.
func TestConsolePortDisabled(t *testing.T) {
	seed := &config.Config{ListenHTTP: "0.0.0.0:8080"}
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "port.db"), seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	var restarted int
	srv := New(Options{
		SkipBootstrap: true,
		Center:        center,
		ConsolePort:   9443,
		RestartDelay:  time.Millisecond,
		Restart: func() error {
			restarted++
			return nil
		},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/settings/console-port")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	decodeInto(t, resp, &out)
	if out["port"].(float64) != 9443 || out["changeable"] != false {
		t.Fatalf("get = %v, want port 9443 changeable false", out)
	}
	if reason, _ := out["reason"].(string); reason == "" {
		t.Fatalf("degraded get missing reason: %v", out)
	}
	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/settings/console-port",
		map[string]any{"port": 9444})
	if code != http.StatusNotImplemented {
		t.Fatalf("post = %d (%v), want 501", code, body)
	}
	time.Sleep(50 * time.Millisecond)
	if restarted != 0 {
		t.Fatalf("restart ran %d times in disabled mode", restarted)
	}
}

// TestConsolePortValidation covers every rejection the card requires:
// out-of-range ports, same-as-current, data-plane collisions and an occupied
// port (injected probe) - none of which may write the env file or restart.
func TestConsolePortValidation(t *testing.T) {
	t.Setenv("INVOCATION_ID", "test-invocation")
	ts, envPath, restarts := portServer(t, func(int) error { return errors.New("listen tcp: bind: address already in use") })
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"too large", 70000},
		{"same as current", 9443},
		{"data-plane http", 8080},
		{"data-plane https", 8443},
		{"occupied", 9444},
	}
	for _, tc := range cases {
		code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/settings/console-port",
			map[string]any{"port": tc.port})
		if code != http.StatusBadRequest {
			t.Fatalf("%s: post = %d (%v), want 400", tc.name, code, body)
		}
		if msg, _ := body["error"].(string); msg == "" {
			t.Fatalf("%s: empty error message: %v", tc.name, body)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if len(*restarts) != 0 {
		t.Fatalf("rejected changes restarted the service %d times", len(*restarts))
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "CONSOLE_PORT=9443\n" {
		t.Fatalf("env file changed by rejected change: %q", b)
	}
}

// TestConsolePortChange covers the happy path: 200 with the change message,
// an atomically rewritten EnvironmentFile (pre-existing content replaced)
// and exactly one scheduled restart.
func TestConsolePortChange(t *testing.T) {
	t.Setenv("INVOCATION_ID", "test-invocation")
	ts, envPath, restarts := portServer(t, nil)
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, body := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/settings/console-port",
		map[string]any{"port": 9444})
	if code != http.StatusOK {
		t.Fatalf("post = %d (%v), want 200", code, body)
	}
	if body["ok"] != true || body["port"].(float64) != 9444 {
		t.Fatalf("response = %v, want ok/port 9444", body)
	}
	if msg, _ := body["message"].(string); msg == "" {
		t.Fatalf("response missing change message: %v", body)
	}

	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != fmt.Sprintf("CONSOLE_PORT=%d\n", 9444) {
		t.Fatalf("env file = %q, want CONSOLE_PORT=9444", b)
	}
	waitRestarted(t, restarts, 1)
	time.Sleep(30 * time.Millisecond)
	if len(*restarts) != 1 {
		t.Fatalf("restart ran %d times, want exactly 1", len(*restarts))
	}
}

// TestDefaultPortProbe exercises the real wildcard-bind probe: an open
// listener makes the port report occupied, closing it frees the port again.
func TestDefaultPortProbe(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skipf("cannot open a probe socket: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := defaultPortProbe(port); err == nil {
		t.Fatalf("probe on open listener port %d = free, want occupied", port)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := defaultPortProbe(port); err != nil {
		t.Fatalf("probe on closed port %d = %v, want free", port, err)
	}
}

// TestListenerPort covers the listen-address port extraction used for
// data-plane collision checks.
func TestListenerPort(t *testing.T) {
	cases := map[string]int{
		"0.0.0.0:80": 80, ":443": 443, "127.0.0.1:8443": 8443,
		"": 0, "localhost": 0, "0.0.0.0:http": 0, "0.0.0.0:-1": 0,
	}
	for addr, want := range cases {
		if got := listenerPort(addr); got != want {
			t.Fatalf("listenerPort(%q) = %d, want %d", addr, got, want)
		}
	}
}

// TestConsolePortChangeable pins the three-condition deployment probe: the
// EnvironmentFile must be wired AND exist on disk AND the process must run
// under systemd (INVOCATION_ID); every failure carries a reason.
func TestConsolePortChangeable(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "console.env")
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("env not wired", func(t *testing.T) {
		ok, reason := consolePortChangeable("")
		if ok || reason == "" {
			t.Fatalf("empty path: ok=%v reason=%q, want false with reason", ok, reason)
		}
	})
	t.Run("env file missing", func(t *testing.T) {
		ok, reason := consolePortChangeable(filepath.Join(t.TempDir(), "absent.env"))
		if ok || reason == "" {
			t.Fatalf("missing file: ok=%v reason=%q, want false with reason", ok, reason)
		}
	})
	t.Run("not systemd", func(t *testing.T) {
		t.Setenv("INVOCATION_ID", "")
		ok, reason := consolePortChangeable(envPath)
		if ok || reason == "" {
			t.Fatalf("non-systemd: ok=%v reason=%q, want false with reason", ok, reason)
		}
	})
	t.Run("systemd deployment", func(t *testing.T) {
		t.Setenv("INVOCATION_ID", "test-invocation")
		ok, reason := consolePortChangeable(envPath)
		if !ok || reason != "" {
			t.Fatalf("wired systemd deployment: ok=%v reason=%q, want true", ok, reason)
		}
	})
}

// TestConsolePortChangeableHTTP covers the probe at the API layer: the card
// reports changeable=true only for the fully wired systemd deployment,
// otherwise it carries a reason and POST is rejected 501 before any side
// effect (no env write, no restart).
func TestConsolePortChangeableHTTP(t *testing.T) {
	cases := []struct {
		name       string
		invocation bool
		writeEnv   bool
		wantOK     bool
	}{
		{"systemd + env file", true, true, true},
		{"env file missing", true, false, false},
		{"not systemd", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.invocation {
				t.Setenv("INVOCATION_ID", "test-invocation")
			} else {
				t.Setenv("INVOCATION_ID", "")
			}
			ts, envPath, restarts := portServer(t, nil)
			if tc.writeEnv {
				if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			resp, err := http.Get(ts.URL + "/api/settings/console-port")
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			decodeInto(t, resp, &out)
			if out["changeable"] != tc.wantOK {
				t.Fatalf("changeable = %v, want %v", out["changeable"], tc.wantOK)
			}
			reason, hasReason := out["reason"]
			if tc.wantOK && hasReason {
				t.Fatalf("changeable=true must not carry a reason: %v", out)
			}
			if tc.wantOK {
				return
			}
			if r, _ := reason.(string); r == "" {
				t.Fatalf("changeable=false missing reason: %v", out)
			}
			code, _ := doJSONBody(t, http.DefaultClient, "POST", ts.URL+"/api/settings/console-port",
				map[string]any{"port": 9444})
			if code != http.StatusNotImplemented {
				t.Fatalf("post = %d (%v), want 501", code, out)
			}
			time.Sleep(30 * time.Millisecond)
			if len(*restarts) != 0 {
				t.Fatalf("rejected change restarted the service %d times", len(*restarts))
			}
		})
	}
}

// slowChild returns a command that runs for about d and then exits, portable
// across platforms (Windows: ping; Unix: sleep).
func slowChild(d time.Duration) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("ping", "-n", strconv.Itoa(int(d.Seconds())+1), "127.0.0.1")
	}
	return exec.Command("sleep", strconv.Itoa(int(d.Seconds())))
}

// TestStartRestartDoesNotBlock pins the fire-and-forget restart submit: the
// submit must return while the child is still running. Blocking on the
// restart child would let systemd's cgroup teardown (KillMode=control-group)
// SIGTERM the very process waiting on it, so every successful restart
// surfaced `signal: terminated` as a spurious error.
func TestStartRestartDoesNotBlock(t *testing.T) {
	cmd := slowChild(3 * time.Second)
	start := time.Now()
	if err := submitRestart(cmd); err != nil {
		t.Fatalf("submit = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("restart submit blocked for %v; it must not wait for the child", elapsed)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
