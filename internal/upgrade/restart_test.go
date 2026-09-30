package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRestarterInvokedOnce: the restart stage runs exactly once per task,
// after replace, and task-level success carries the "service restarting"
// message (the restart outcome itself is reconciled elsewhere).
func TestRestarterInvokedOnce(t *testing.T) {
	var calls atomic.Int32
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) { return "/fake/archive.tar.gz", nil }),
		WithVerifier(func(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
			return "/fake/artifact", nil
		}),
		WithReplacer(func(ctx context.Context, t *Task) error { return nil }),
		WithRestarter(func(ctx context.Context, t *Task) error { calls.Add(1); return nil }))
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	done := waitTask(t, s, task.ID, TaskSuccess)
	if calls.Load() != 1 {
		t.Fatalf("restarter invoked %d times, want exactly 1", calls.Load())
	}
	if done.Message != "升级完成，服务重启中，请稍后刷新页面" {
		t.Fatalf("success message = %q", done.Message)
	}
}

// fakeSystemctl plants a platform-native fake systemctl binary in a
// fresh directory and prepends that directory to PATH for the duration of
// the test, returning the path of the args file the recording fake writes
// on every invocation (its own directory). Scripts are written with CRLF
// line endings on Windows: cmd.exe misparses some LF-only batches.
func fakeSystemctl(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	name := "systemctl"
	if runtime.GOOS == "windows" {
		name = "systemctl.cmd"
		script = strings.ReplaceAll(script, "\n", "\r\n")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(dir, "systemctl-args.txt")
}

// Fake systemctl scripts (POSIX sh; the Windows variants run through the
// same helper with CRLF endings). fail: nonzero exit with a stderr
// diagnostic - the polkit-denial shape real systemctl produces for a
// non-root caller. noBlock: records its argument vector and succeeds only
// when invoked exactly as the production code must invoke it.
const fakeSystemctlFail = `#!/bin/sh
echo "polkit: access denied for user kingmoat" >&2
exit 1
`

const fakeSystemctlFailWin = `@echo off
echo polkit: access denied for user kingmoat 1>&2
exit /b 1
`

const fakeSystemctlNoBlock = `#!/bin/sh
printf '%s\n' "$*" > "$(dirname "$0")/systemctl-args.txt"
if [ "$1" = "--no-block" ]; then
    exit 0
fi
echo "expected --no-block as the first argument, got: $*" >&2
exit 1
`

const fakeSystemctlNoBlockWin = `@echo off
echo %* > "%~dp0systemctl-args.txt"
if "%~1"=="--no-block" exit /b 0
echo expected --no-block as the first argument, got: %* 1>&2
exit /b 1
`

func fakeSystemctlScripts() (fail, noBlock string) {
	if runtime.GOOS == "windows" {
		return fakeSystemctlFailWin, fakeSystemctlNoBlockWin
	}
	return fakeSystemctlFail, fakeSystemctlNoBlock
}

// TestSubmitRestartObservesVerdict: submitRestart is the observation
// point for the `--no-block` submission - a zero exit is success, a
// nonzero exit fails WITH the command's stderr folded into the error (the
// only place systemctl's polkit/unit diagnostics live).
func TestSubmitRestartObservesVerdict(t *testing.T) {
	fail, noBlock := fakeSystemctlScripts()

	fakeSystemctl(t, fail)
	path, err := exec.LookPath("systemctl")
	if err != nil {
		t.Fatal(err)
	}
	err = submitRestart(context.Background(), exec.Command(path))
	if err == nil || !strings.Contains(err.Error(), "polkit: access denied") {
		t.Fatalf("submitRestart(failing systemctl) = %v, want the stderr summary in the error", err)
	}

	fakeSystemctl(t, noBlock)
	path, err = exec.LookPath("systemctl")
	if err != nil {
		t.Fatal(err)
	}
	// The success case passes the production argument vector; the
	// recording fake only succeeds for it.
	if err := submitRestart(context.Background(), exec.Command(path, "--no-block", "restart", "kingmoatwaf")); err != nil {
		t.Fatalf("submitRestart(successful systemctl) = %v", err)
	}
}

// TestSubmitRestartBounded: the observation is bounded by the caller's
// context - a hung systemctl cannot wedge the upgrade task, and expiry is
// reported as its own failure, distinct from a systemd verdict.
func TestSubmitRestartBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Direct exe: killing it closes its pipes, so the bounded
		// CombinedOutput returns at the deadline (a cmd /c wrapper would
		// leave the orphaned child holding the pipes).
		cmd = exec.CommandContext(ctx, "ping", "-n", "3", "127.0.0.1") // ~2s
	} else {
		cmd = exec.CommandContext(ctx, "sleep", "2")
	}
	started := time.Now()
	err := submitRestart(ctx, cmd)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("submitRestart ignored its deadline: %v", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("submitRestart(hung systemctl) = %v, want a timeout failure", err)
	}
}

// TestSubmitRestartToleratesCgroupSIGTERM: systemd's stop phase may tear
// down the unit cgroup (and the systemctl client with it, SIGTERM) after
// the restart job was accepted - that must count as a successful
// submission, not a failure. Distinguishing signal: the bounded-wait path
// kills with SIGKILL. Linux-only: Windows has no SIGTERM for child
// processes (and the production path is GOOS-gated anyway).
func TestSubmitRestartToleratesCgroupSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM for child processes on windows")
	}
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	if err := submitRestart(context.Background(), cmd); err != nil {
		t.Fatalf("submitRestart(SIGTERM'd client) = %v, want nil (accepted submission)", err)
	}
}

// TestSubmitRestartCleanExitBeatsContextExpiry: a verdict (exit 0) reached
// even when the context has expired stays a success - the job is queued,
// the expiry only governs how long we wait for the verdict. The command is
// deliberately NOT context-bound (simulating a verdict that lands after
// the deadline): submitRestart must classify by the verdict, not the ctx.
func TestSubmitRestartCleanExitBeatsContextExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit 0")
	} else {
		cmd = exec.Command("true")
	}
	if err := submitRestart(ctx, cmd); err != nil {
		t.Fatalf("submitRestart(exit 0, expired ctx) = %v, want nil", err)
	}
}

// TestDefaultRestartRequiresIntent: the production restart stage refuses
// to submit without the intent marker - the self-heal net would be blind
// (guard fires before any systemctl interaction, so this is deterministic
// on every host).
func TestDefaultRestartRequiresIntent(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir())
	err := s.defaultRestartStage(context.Background(), &Task{ID: "restart001"})
	if err == nil || !strings.Contains(err.Error(), "升级意图标记缺失") {
		t.Fatalf("restart without intent marker = %v, want refusal", err)
	}
}

// TestStandaloneRestartSubmitsAfterProbe: the console API's Restart probes
// capability then submits exactly once through the injected seam - the
// standalone path shares the probe discipline but never the upgrade task
// machinery (no intent marker requirement).
func TestStandaloneRestartSubmitsAfterProbe(t *testing.T) {
	var probes, submits atomic.Int32
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithProber(func() error { probes.Add(1); return nil }),
		WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	if err := s.Restart(context.Background()); err != nil {
		t.Fatalf("Restart = %v", err)
	}
	if probes.Load() != 1 || submits.Load() != 1 {
		t.Fatalf("probes=%d submits=%d, want exactly one of each", probes.Load(), submits.Load())
	}
}

// TestStandaloneRestartProbeRefusal: a failed capability probe stops
// Restart before any submission - a refused restart must never reach
// systemctl.
func TestStandaloneRestartProbeRefusal(t *testing.T) {
	var submits atomic.Int32
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithProber(func() error { return errors.New("当前进程非 root 运行") }),
		WithRestartSubmitter(func(context.Context) error { submits.Add(1); return nil }))
	err := s.Restart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "非 root") {
		t.Fatalf("Restart = %v, want the probe refusal", err)
	}
	if submits.Load() != 0 {
		t.Fatalf("submit invoked %d times after probe refusal, want 0", submits.Load())
	}
}

// TestStandaloneRestartUnavailableClassification: the probe classifies
// "no automatic restart path at all" deployments with ErrRestartUnavailable
// (console API → 501): on Windows the GOOS branch answers first; on Linux
// a missing systemctl is classified the same way.
func TestStandaloneRestartUnavailableClassification(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir())
	if runtime.GOOS == "windows" {
		err := s.RestartProbe()
		if !errors.Is(err, ErrRestartUnavailable) {
			t.Fatalf("RestartProbe(windows) = %v, want ErrRestartUnavailable", err)
		}
		return
	}
	t.Setenv("PATH", "")
	err := s.RestartProbe()
	if !errors.Is(err, ErrRestartUnavailable) {
		t.Fatalf("RestartProbe(no systemctl) = %v, want ErrRestartUnavailable", err)
	}
}

// TestStandaloneRestartProbeIgnoresBinaryDirWritability: a PLAIN restart
// writes nothing, so the standalone probe must NOT gate on
// binary-directory writability - that check is the upgrade path's
// (probeRestartCapability, whose swap renames inside the directory). With
// systemctl on PATH (fake) and a root identity the standalone probe
// passes even for a missing (thus unwritable) binary directory, while the
// upgrade-side three-in-one probe still refuses the same deployment.
func TestStandaloneRestartProbeIgnoresBinaryDirWritability(t *testing.T) {
	_, noBlock := fakeSystemctlScripts()
	fakeSystemctl(t, noBlock)
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(filepath.Join(t.TempDir(), "missing-bin-dir")),
		WithEuidProbe(func() int { return 0 }))
	if err := s.probeRestartBasics(); err != nil {
		t.Fatalf("probeRestartBasics with unwritable binary dir = %v, want pass (dir writability is upgrade-specific)", err)
	}
	if err := s.probeRestartCapability(); err == nil {
		t.Fatal("probeRestartCapability with missing binary dir = nil, want the writable-directory refusal")
	}
	if runtime.GOOS == "linux" {
		if err := s.RestartProbe(); err != nil {
			t.Fatalf("RestartProbe(linux, unwritable binary dir) = %v, want pass", err)
		}
	}
}

// TestRestartSubmissionFailureFailsTask: the DEFAULT restart stage runs
// the real systemctl submission against a fake on PATH that exits nonzero
// with a stderr diagnostic (the polkit-denial shape). The task must FAIL
// carrying that diagnostic - the pre-fix behavior reported "upgrade
// complete" - and the self-heal contract survives: binaries stay swapped,
// intent marker on disk.
func TestRestartSubmissionFailureFailsTask(t *testing.T) {
	fail, _ := fakeSystemctlScripts()
	fakeSystemctl(t, fail)
	archive := buildTarGz(t, map[string][]byte{"kingmoatwaf": []byte(testPayloadA), "kmwafctl": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")

	s := NewService("v0.7.8-beta", t.TempDir(), append(testServiceOptions(srv),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*testRelease(srv, true)}, nil
		}),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }),
		// No WithRestarter: the DEFAULT (systemctl) stage is under test.
	)...)
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s, task.ID, TaskFailed)
	if !strings.Contains(failed.Error, "提交服务重启失败") || !strings.Contains(failed.Error, "polkit: access denied") {
		t.Fatalf("failed task error = %q, want the submission failure with the stderr summary", failed.Error)
	}
	// The swap already happened before the restart attempt.
	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName))
	if err != nil || string(got) != testPayloadA {
		t.Fatalf("server binary = %q, %v; want the swapped payload", got, err)
	}
	// The intent marker survives for the next boot.
	if _, err := os.Stat(s.intentPath()); err != nil {
		t.Fatalf("intent marker must survive a failed restart: %v", err)
	}
}

// TestRestartSubmissionNoBlockContract pins the invocation contract of
// the default restart stage: the recording fake succeeds only for the
// required argument vector (`--no-block` first) - the flag is what keeps
// the observed submission out of the KillMode=control-group kill window.
// A conforming fake lets the whole pipeline reach success.
func TestRestartSubmissionNoBlockContract(t *testing.T) {
	_, noBlock := fakeSystemctlScripts()
	argsFile := fakeSystemctl(t, noBlock)
	archive := buildTarGz(t, map[string][]byte{"kingmoatwaf": []byte(testPayloadA), "kmwafctl": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")

	s := NewService("v0.7.8-beta", t.TempDir(), append(testServiceOptions(srv),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*testRelease(srv, true)}, nil
		}),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }),
	)...)
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, task.ID, TaskSuccess)
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("fake systemctl was never invoked: %v", err)
	}
	if got, want := strings.Join(strings.Fields(string(data)), " "), "--no-block restart kingmoatwaf"; got != want {
		t.Fatalf("systemctl invoked as %q, want %q", got, want)
	}
}

// TestRestartFailureKeepsIntent: the restart submission failing fails the
// task, but the binaries stay swapped and the intent marker survives - the
// next boot's self-heal (L1 reconcile) still closes the upgrade out.
func TestRestartFailureKeepsIntent(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoatwaf": []byte(testPayloadA), "kmwafctl": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")

	s := NewService("v0.7.8-beta", t.TempDir(), append(testServiceOptions(srv),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*testRelease(srv, true)}, nil
		}),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }),
		WithRestarter(func(ctx context.Context, t *Task) error { return errors.New("systemctl restart 失败（模拟）") }),
	)...)
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s, task.ID, TaskFailed)
	if !strings.Contains(failed.Error, "模拟") {
		t.Fatalf("failed task error = %q, want the restarter failure", failed.Error)
	}
	// The swap already happened before the restart attempt.
	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName))
	if err != nil || string(got) != testPayloadA {
		t.Fatalf("server binary = %q, %v; want the swapped payload", got, err)
	}
	// The intent marker survives for the next boot.
	data, err := os.ReadFile(s.intentPath())
	if err != nil {
		t.Fatalf("intent marker must survive a failed restart: %v", err)
	}
	var rec intentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.TargetVersion != testVersion || rec.TargetSHA256 != sha256Hex([]byte(testPayloadA)) {
		t.Fatalf("intent record = %+v", rec)
	}
}
