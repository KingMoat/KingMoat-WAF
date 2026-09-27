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
		WithVerifier(func(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) { return "/fake/artifact", nil }),
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

// TestSubmitRestartDoesNotBlock pins the fire-and-forget guarantee with a
// slow child (a platform-native sleeper: deliberately NOT this test
// binary, whose image file go test deletes right after the run): the
// submit returns immediately after a successful exec - blocking on Wait
// would surface as a multi-second submit. The sleeping child is reaped by
// the background Wait (or by init when this process exits first).
func TestSubmitRestartDoesNotBlock(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "ping", "-n", "3", "127.0.0.1") // ~2s
	} else {
		cmd = exec.Command("sleep", "2")
	}
	started := time.Now()
	if err := submitRestart(cmd); err != nil {
		t.Fatalf("submitRestart = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("submitRestart took %v; it must never wait for the child", elapsed)
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

// TestRestartFailureKeepsIntent: the restart submission failing fails the
// task, but the binaries stay swapped and the intent marker survives - the
// next boot's self-heal (L1 reconcile) still closes the upgrade out.
func TestRestartFailureKeepsIntent(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
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
