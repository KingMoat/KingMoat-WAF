package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// writeBinaries seeds dir with the two running-binary fakes.
func writeBinaries(t *testing.T, dir, server, cli string) {
	t.Helper()
	for name, content := range map[string]string{serverBinaryName: server, cliBinaryName: cli} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// namesWithPrefix lists the file names in dir carrying the prefix.
func namesWithPrefix(t *testing.T, dir, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestBackupRolling: both running binaries are backed up beside themselves
// with the current version tag, and the rolling window keeps only the
// backupKeep newest backups per name (sorted by name, oldest dropped).
func TestBackupRolling(t *testing.T) {
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")
	for _, v := range []string{"v0.7.5-beta", "v0.7.6-beta", "v0.7.7-beta"} {
		for _, name := range []string{serverBinaryName, cliBinaryName} {
			if err := os.WriteFile(filepath.Join(binDir, name+backupSuffix+v), []byte("bak"+v), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := NewService("v0.7.8-beta", t.TempDir(), WithBinaryDir(binDir))
	serverBak, err := s.backupCurrentBinaries(binDir)
	if err != nil {
		t.Fatal(err)
	}
	if serverBak != filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta") {
		t.Fatalf("server backup path = %q", serverBak)
	}
	got, err := os.ReadFile(serverBak)
	if err != nil || string(got) != "old-server" {
		t.Fatalf("server backup = %q, %v; want old-server", got, err)
	}
	cliBak := filepath.Join(binDir, cliBinaryName+backupSuffix+"v0.7.8-beta")
	got, err = os.ReadFile(cliBak)
	if err != nil || string(got) != "old-cli" {
		t.Fatalf("cli backup = %q, %v; want old-cli", got, err)
	}
	// 3 seeded + 1 fresh = 4 → keep the 2 newest by name.
	want := []string{serverBinaryName + backupSuffix + "v0.7.7-beta", serverBinaryName + backupSuffix + "v0.7.8-beta"}
	if baks := namesWithPrefix(t, binDir, serverBinaryName+backupSuffix); strings.Join(baks, ",") != strings.Join(want, ",") {
		t.Fatalf("server backups = %v, want %v", baks, want)
	}
	wantCli := []string{cliBinaryName + backupSuffix + "v0.7.7-beta", cliBinaryName + backupSuffix + "v0.7.8-beta"}
	if baks := namesWithPrefix(t, binDir, cliBinaryName+backupSuffix); strings.Join(baks, ",") != strings.Join(wantCli, ",") {
		t.Fatalf("cli backups = %v, want %v", baks, wantCli)
	}
}

// TestPruneBackups pins the pruning rule directly: sorted by name, newest
// keep survive.
func TestPruneBackups(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"kingmoat.bak-a", "kingmoat.bak-b", "kingmoat.bak-c", "kingmoat-cli.bak-a"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneBackups(dir, serverBinaryName, 2); err != nil {
		t.Fatal(err)
	}
	if got := namesWithPrefix(t, dir, serverBinaryName+backupSuffix); strings.Join(got, ",") != "kingmoat.bak-b,kingmoat.bak-c" {
		t.Fatalf("after prune = %v, want the 2 newest", got)
	}
	// Other names' backups are untouched.
	if got := namesWithPrefix(t, dir, cliBinaryName+backupSuffix); len(got) != 1 {
		t.Fatalf("cli backup pruned by the server window: %v", got)
	}
}

// TestAtomicReplace: the payload lands at the target with identical bytes
// and executable permissions, and no temporary file survives.
func TestAtomicReplace(t *testing.T) {
	binDir := t.TempDir()
	artDir := t.TempDir()
	writeBinaries(t, binDir, "old", "old-cli")
	newServer := []byte(strings.Repeat("A", 1<<20)) // 1 MiB: exercise multi-chunk copy
	if err := os.WriteFile(filepath.Join(artDir, serverBinaryName), newServer, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, cliBinaryName), []byte("new-cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewService("v0.7.8-beta", t.TempDir(), WithBinaryDir(binDir))
	if err := s.atomicInstall(filepath.Join(artDir, serverBinaryName), binDir, serverBinaryName, "atomic001"); err != nil {
		t.Fatal(err)
	}
	if err := s.atomicInstall(filepath.Join(artDir, cliBinaryName), binDir, cliBinaryName, "atomic001"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName))
	if err != nil || string(got) != string(newServer) {
		t.Fatalf("replaced server mismatch (%d bytes read, %v)", len(got), err)
	}
	got, err = os.ReadFile(filepath.Join(binDir, cliBinaryName))
	if err != nil || string(got) != "new-cli" {
		t.Fatalf("replaced cli = %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{serverBinaryName, cliBinaryName} {
			fi, err := os.Stat(filepath.Join(binDir, name))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s mode = %v, want 0755", name, fi.Mode().Perm())
			}
		}
	}
	for _, n := range namesWithPrefix(t, binDir, "") {
		if strings.Contains(n, ".new-") {
			t.Fatalf("temporary file %q survived the swap", n)
		}
	}
}

// TestReplaceProbeFailure: a failed capability probe (injected read-only
// verdict) aborts before anything is touched - binaries unchanged, no
// backups, no intent marker - and the task message guides to the manual
// download path.
func TestReplaceProbeFailure(t *testing.T) {
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(binDir),
		WithProber(func() error { return errors.New("二进制目录为只读（模拟）") }))
	task := &Task{ID: "probefail01", TargetVersion: "v0.7.9-beta"}
	task.artifactDir = t.TempDir() // would hold the new payloads; never read

	err := s.defaultReplace(context.Background(), task)
	if err == nil || !strings.Contains(err.Error(), "升级能力探测失败") {
		t.Fatalf("defaultReplace = %v, want capability probe failure", err)
	}
	if !strings.Contains(err.Error(), "只读") {
		t.Fatalf("probe failure must carry the cause: %v", err)
	}
	if !strings.Contains(task.Message, "手动下载") {
		t.Fatalf("probe failure message = %q, want manual-download guidance", task.Message)
	}
	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName))
	if err != nil || string(got) != "old-server" {
		t.Fatalf("binaries must be untouched after a failed probe, got %q, %v", got, err)
	}
	if baks := namesWithPrefix(t, binDir, backupSuffix); len(baks) != 0 {
		t.Fatalf("no backups may exist after a failed probe: %v", baks)
	}
	if _, err := os.Stat(s.intentPath()); !os.IsNotExist(err) {
		t.Fatal("no intent marker may exist after a failed probe")
	}
}

// TestIntentMarker: after a successful replace both binaries are swapped,
// and intent.json records exactly the self-heal contract (target version,
// new server SHA256, server backup path, timestamp) with 0600 permissions
// and no temporary residue.
func TestIntentMarker(t *testing.T) {
	binDir := t.TempDir()
	artDir := t.TempDir()
	dataDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")
	newServer := []byte("brand-new-server-bytes")
	if err := os.WriteFile(filepath.Join(artDir, serverBinaryName), newServer, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, cliBinaryName), []byte("brand-new-cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewService("v0.7.8-beta", dataDir,
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }))
	task := &Task{ID: "intent0001", TargetVersion: "v0.7.9-beta"}
	task.artifactDir = artDir
	if err := s.defaultReplace(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName))
	if err != nil || string(got) != "brand-new-server-bytes" {
		t.Fatalf("server not swapped: %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(binDir, serverBinaryName)); fi.Mode().Perm() != 0o755 {
			t.Fatalf("swapped server mode = %v, want 0755", fi.Mode().Perm())
		}
	}

	fi, err := os.Stat(s.intentPath())
	if err != nil {
		t.Fatalf("intent marker missing: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("intent marker mode = %v, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(s.intentPath())
	if err != nil {
		t.Fatal(err)
	}
	var rec intentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("intent marker is not valid JSON: %v", err)
	}
	if rec.TargetVersion != "v0.7.9-beta" {
		t.Fatalf("intent target_version = %q", rec.TargetVersion)
	}
	if want := sha256Hex(newServer); rec.TargetSHA256 != want {
		t.Fatalf("intent target_sha256 = %q, want %q", rec.TargetSHA256, want)
	}
	if rec.Backup != filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta") {
		t.Fatalf("intent backup = %q", rec.Backup)
	}
	if _, err := time.Parse(time.RFC3339, rec.Timestamp); err != nil {
		t.Fatalf("intent timestamp %q is not RFC3339: %v", rec.Timestamp, err)
	}
	// No residue: the binary dir holds exactly the pair plus their backups,
	// the upgrade dir exactly the intent marker.
	for _, n := range namesWithPrefix(t, binDir, "") {
		if strings.Contains(n, ".new-") {
			t.Fatalf("temporary file %q survived the replace", n)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(dataDir, "upgrade")); len(entries) != 1 || entries[0].Name() != intentFileName {
		t.Fatalf("upgrade dir residue after replace: %v", entries)
	}
}

// TestReplaceRestoresOnLateFailure: a failure after the first swap (here:
// the artifact lacks the cli payload) puts the pre-upgrade binaries back,
// so a failed upgrade never leaves a mixed installation.
func TestReplaceRestoresOnLateFailure(t *testing.T) {
	binDir := t.TempDir()
	artDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")
	if err := os.WriteFile(filepath.Join(artDir, serverBinaryName), []byte("new-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }))
	task := &Task{ID: "restore001", TargetVersion: "v0.7.9-beta"}
	task.artifactDir = artDir

	if err := s.defaultReplace(context.Background(), task); err == nil {
		t.Fatal("replace without the cli payload must fail")
	}
	for name, want := range map[string]string{serverBinaryName: "old-server", cliBinaryName: "old-cli"} {
		got, err := os.ReadFile(filepath.Join(binDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s after failed replace = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := os.Stat(s.intentPath()); !os.IsNotExist(err) {
		t.Fatal("no intent marker may exist after a failed replace")
	}
}

// TestCleanupWorkspacesAtConstruction: NewService removes leftover task
// workspaces (nested content included) but never files under upgrade/.
func TestCleanupWorkspacesAtConstruction(t *testing.T) {
	dataDir := t.TempDir()
	up := filepath.Join(dataDir, "upgrade")
	if err := os.MkdirAll(filepath.Join(up, "deadtask01", "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, "deadtask01", "kingmoat"), []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, "deadtask01", "nested", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, intentFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, "stray.txt"), []byte("files are never touched"), 0o600); err != nil {
		t.Fatal(err)
	}
	NewService("v0.7.8-beta", dataDir)
	if dirExists(filepath.Join(up, "deadtask01")) {
		t.Fatal("leftover task workspace must be removed at construction")
	}
	if _, err := os.Stat(filepath.Join(up, intentFileName)); err != nil {
		t.Fatalf("intent marker must survive the cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(up, "stray.txt")); err != nil {
		t.Fatalf("files under upgrade/ must survive the cleanup: %v", err)
	}
}

// TestStartCleansOldWorkspaces pins the start-time cleanup wiring: the
// residue is gone by the time the new task's stages run.
func TestStartCleansOldWorkspaces(t *testing.T) {
	dataDir := t.TempDir()
	up := filepath.Join(dataDir, "upgrade")
	if err := os.MkdirAll(filepath.Join(up, "midtask03"), 0o750); err != nil {
		t.Fatal(err)
	}
	s := NewService("v0.7.8-beta", dataDir,
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) { return "/fake/archive.tar.gz", nil }),
		WithVerifier(func(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
			return "/fake/artifact", nil
		}),
		WithReplacer(nil)) // fails the task at the replace stage; cleanup already ran
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, task.ID, TaskFailed)
	if dirExists(filepath.Join(up, "midtask03")) {
		t.Fatal("Start must clean previous task workspaces")
	}
}

// TestTaskEndToEndReplace wires the real feed, download, verify and the
// DEFAULT replace stage (probe injected to pass, binaries in a fake
// installation directory) with a fake restart hook: the full pipeline must
// swap both binaries, back the old ones up and record the intent marker.
func TestTaskEndToEndReplace(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})
	dataDir := t.TempDir()
	binDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")

	s := NewService("v0.7.8-beta", dataDir, append(testServiceOptions(srv),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*testRelease(srv, true)}, nil
		}),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }),
		WithRestarter(func(ctx context.Context, t *Task) error { return nil }),
	)...)
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	done := waitTask(t, s, task.ID, TaskSuccess)
	if done.TargetVersion != testVersion {
		t.Fatalf("target = %q, want %s", done.TargetVersion, testVersion)
	}
	for name, want := range map[string]string{serverBinaryName: testPayloadA, cliBinaryName: testPayloadB} {
		got, err := os.ReadFile(filepath.Join(binDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("installed %s = %q, %v; want %q", name, got, err, want)
		}
	}
	got, err := os.ReadFile(filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"))
	if err != nil || string(got) != "old-server" {
		t.Fatalf("server backup = %q, %v; want old-server", got, err)
	}
	data, err := os.ReadFile(s.intentPath())
	if err != nil {
		t.Fatalf("intent marker missing after end-to-end replace: %v", err)
	}
	var rec intentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.TargetSHA256 != sha256Hex([]byte(testPayloadA)) || rec.TargetVersion != testVersion {
		t.Fatalf("intent record = %+v", rec)
	}
}

// TestProbeRestartCapabilityEuid: the restart authorization is probed
// like the console port change gates it (consolePortChangeable and its
// EuidProbe in internal/api/console_port.go) - a non-root caller gets an
// early, distinct refusal (polkit default-deny) instead of a
// mid-upgrade restart failure, and root passes. Runs through the
// post-platform probe on any host, with a fake systemctl on PATH so the
// preceding checks succeed.
func TestProbeRestartCapabilityEuid(t *testing.T) {
	_, noBlock := fakeSystemctlScripts()
	fakeSystemctl(t, noBlock)

	s := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(t.TempDir()),
		WithEuidProbe(func() int { return 1000 }))
	err := s.probeRestartCapability()
	if err == nil || !strings.Contains(err.Error(), "需要 root 或 polkit 授权重启服务") {
		t.Fatalf("probe as non-root = %v, want the polkit guidance", err)
	}

	sRoot := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(t.TempDir()),
		WithEuidProbe(func() int { return 0 }))
	if err := sRoot.probeRestartCapability(); err != nil {
		t.Fatalf("probe as root = %v, want pass", err)
	}
}

// TestReplaceRestoresOnChmodFailure: the post-rename chmod failing (the
// only publish step after the directory entry is swapped) must not leave
// the new binary published - the pre-upgrade pair is restored and no
// intent marker is written (the restore-on-failure contract covers the
// server swap, not just the cli swap). The failure is injected via
// WithChmod because a post-rename chmod failure is unreachable with
// filesystem tricks: the freshly created file is process-owned. The
// injected failure is one-shot so the restore's own chmod succeeds,
// modeling a transient failure.
func TestReplaceRestoresOnChmodFailure(t *testing.T) {
	binDir := t.TempDir()
	artDir := t.TempDir()
	writeBinaries(t, binDir, "old-server", "old-cli")
	if err := os.WriteFile(filepath.Join(artDir, serverBinaryName), []byte("new-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, cliBinaryName), []byte("new-cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	var serverChmods atomic.Int32
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithBinaryDir(binDir),
		WithProber(func() error { return nil }),
		WithChmod(func(path string, mode os.FileMode) error {
			if filepath.Base(path) != serverBinaryName {
				return os.Chmod(path, mode)
			}
			if serverChmods.Add(1) == 1 {
				return errors.New("设置执行权限失败（模拟）")
			}
			return os.Chmod(path, mode)
		}))
	task := &Task{ID: "chmodfail1", TargetVersion: "v0.7.9-beta"}
	task.artifactDir = artDir

	err := s.defaultReplace(context.Background(), task)
	if err == nil || !strings.Contains(err.Error(), "模拟") {
		t.Fatalf("defaultReplace = %v, want the injected chmod failure", err)
	}
	// The failure happened after the publish (chmod is strictly
	// post-rename), so without the restore the new binary would still be
	// in place.
	if serverChmods.Load() < 1 {
		t.Fatal("injected chmod never fired for the server binary")
	}
	for name, want := range map[string]string{serverBinaryName: "old-server", cliBinaryName: "old-cli"} {
		got, err := os.ReadFile(filepath.Join(binDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s after failed chmod = %q, %v; want %q (restored)", name, got, err, want)
		}
	}
	if _, err := os.Stat(s.intentPath()); !os.IsNotExist(err) {
		t.Fatal("no intent marker may exist after a failed chmod")
	}
}
