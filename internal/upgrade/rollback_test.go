package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeIntentMarker seeds <dataDir>/upgrade/intent.json the way the replace
// stage leaves it behind (raw write is enough in tests).
func writeIntentMarker(t *testing.T, dataDir string, rec intentRecord) {
	t.Helper()
	dir := filepath.Join(dataDir, "upgrade")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, intentFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// intentMarkerExists reports whether the marker file is present.
func intentMarkerExists(t *testing.T, dataDir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dataDir, "upgrade", intentFileName))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatal(err)
	return false
}

// brokenCopies lists the diagnostic copies kept for the named binary.
func brokenCopies(t *testing.T, dir, name string) []string {
	t.Helper()
	return namesWithPrefix(t, dir, name+brokenSuffix)
}

// TestCheckIntentSuccessConsumes: the on-disk binary already matches the
// intent target → the upgrade SUCCEEDED, the verdict is "no rollback" and
// the marker is consumed, so the next boot sees no marker at all.
func TestCheckIntentSuccessConsumes(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBin := filepath.Join(binDir, serverBinaryName)
	if err := os.WriteFile(serverBin, []byte("new-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("new-server")),
		Backup:        filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"),
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	needed, reason := CheckUpgradeIntent(dataDir, serverBin)
	if needed {
		t.Fatalf("matching sha must not need a rollback, reason = %q", reason)
	}
	if !strings.Contains(reason, "升级成功") {
		t.Fatalf("reason = %q, want an upgrade-success note", reason)
	}
	if intentMarkerExists(t, dataDir) {
		t.Fatal("a successful check must consume (delete) the intent marker")
	}
	// Next boot: no marker → plain no-op.
	needed, reason = CheckUpgradeIntent(dataDir, serverBin)
	if needed || !strings.Contains(reason, "无升级意图标记") {
		t.Fatalf("after consumption: needed=%v reason=%q, want a no-marker no-op", needed, reason)
	}
}

// TestCheckIntentMismatchNeedsRollback: the on-disk binary does not match
// the target (the new binary never ran successfully) → rollback needed.
func TestCheckIntentMismatchNeedsRollback(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBin := filepath.Join(binDir, serverBinaryName)
	if err := os.WriteFile(serverBin, []byte("broken-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("never-ran-server")),
		Backup:        filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"),
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	needed, reason := CheckUpgradeIntent(dataDir, serverBin)
	if !needed {
		t.Fatalf("mismatching sha must need a rollback, reason = %q", reason)
	}
	if !strings.Contains(reason, "回滚") {
		t.Fatalf("reason = %q, want a rollback hint", reason)
	}
	if !intentMarkerExists(t, dataDir) {
		t.Fatal("the mismatch check must leave the marker for PerformRollback")
	}
}

// TestCheckIntentAbsentMarker: no marker anywhere → no-op (the everyday
// boot path for machines that never upgraded).
func TestCheckIntentAbsentMarker(t *testing.T) {
	needed, _ := CheckUpgradeIntent(t.TempDir(), filepath.Join(t.TempDir(), serverBinaryName))
	if needed {
		t.Fatal("no marker must mean no rollback")
	}
}

// TestCheckIntentCorruptJSON: a torn/corrupted marker disables the net
// instead of triggering a bogus rollback (the marker is the only rollback
// reference); the check must not panic.
func TestCheckIntentCorruptJSON(t *testing.T) {
	dataDir := t.TempDir()
	dir := filepath.Join(dataDir, "upgrade")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, intentFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	needed, reason := CheckUpgradeIntent(dataDir, filepath.Join(t.TempDir(), serverBinaryName))
	if needed {
		t.Fatalf("a corrupt marker must disable the net, reason = %q", reason)
	}
	if !strings.Contains(reason, "无法解析") {
		t.Fatalf("reason = %q, want the unparseable-marker note", reason)
	}
}

// TestCheckIntentMissingBinary: the binary itself is gone (deepest brick
// state) → attempt the rollback, the recorded backup is the only rescue.
func TestCheckIntentMissingBinary(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("new-server")),
		Backup:        filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"),
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	needed, reason := CheckUpgradeIntent(dataDir, filepath.Join(binDir, serverBinaryName))
	if !needed {
		t.Fatalf("a missing binary must attempt the rollback rescue, reason = %q", reason)
	}
	if !strings.Contains(reason, "无法读取") {
		t.Fatalf("reason = %q, want the unreadable-binary note", reason)
	}
}

// TestPerformRollbackRestores: the full L2 recovery - the broken server and
// cli are set aside as .broken-<ts> diagnostics, the recorded backups land
// back at the binary paths with 0755, the marker is consumed and a second
// check is a no-op (loop protection).
func TestPerformRollbackRestores(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBak := filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta")
	cliBak := filepath.Join(binDir, cliBinaryName+backupSuffix+"v0.7.8-beta")
	if err := os.WriteFile(serverBak, []byte("old-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliBak, []byte("old-cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	serverBin := filepath.Join(binDir, serverBinaryName)
	cliBin := filepath.Join(binDir, cliBinaryName)
	if err := os.WriteFile(serverBin, []byte("broken-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliBin, []byte("broken-cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("never-ran-server")),
		Backup:        serverBak,
		Timestamp:     "2026-09-27T00:00:00Z",
	})

	needed, _ := CheckUpgradeIntent(dataDir, serverBin)
	if !needed {
		t.Fatal("setup mismatch: rollback must be needed")
	}
	if err := PerformRollback(dataDir, serverBin); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(serverBin)
	if err != nil || string(got) != "old-server" {
		t.Fatalf("server after rollback = %q, %v; want old-server", got, err)
	}
	got, err = os.ReadFile(cliBin)
	if err != nil || string(got) != "old-cli" {
		t.Fatalf("cli after rollback = %q, %v; want old-cli", got, err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{serverBin, cliBin} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s mode = %v, %v; want 0755", p, fi.Mode().Perm(), err)
			}
		}
	}
	// Diagnostics: exactly one broken copy per binary, carrying the broken
	// bytes for the post-mortem.
	for name, brokenBytes := range map[string]string{serverBinaryName: "broken-server", cliBinaryName: "broken-cli"} {
		copies := brokenCopies(t, binDir, name)
		if len(copies) != 1 {
			t.Fatalf("%s broken copies = %v, want exactly one", name, copies)
		}
		got, err := os.ReadFile(filepath.Join(binDir, copies[0]))
		if err != nil || string(got) != brokenBytes {
			t.Fatalf("broken copy %s = %q, %v; want %q", copies[0], got, err, brokenBytes)
		}
	}
	if intentMarkerExists(t, dataDir) {
		t.Fatal("a completed rollback must consume the intent marker (loop protection)")
	}
	// Second boot after the rollback: no marker → no-op.
	if needed, _ := CheckUpgradeIntent(dataDir, serverBin); needed {
		t.Fatal("after a completed rollback the next check must be a no-op")
	}
}

// TestPerformRollbackCLIBakMissing: the cli backup is absent (pruned,
// unrecognized name) - the server restore must still succeed and the
// rollback must not fail.
func TestPerformRollbackCLIBakMissing(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBak := filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta")
	if err := os.WriteFile(serverBak, []byte("old-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	serverBin := filepath.Join(binDir, serverBinaryName)
	if err := os.WriteFile(serverBin, []byte("broken-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("never-ran-server")),
		Backup:        serverBak,
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	if err := PerformRollback(dataDir, serverBin); err != nil {
		t.Fatalf("a missing cli backup must not block the server restore: %v", err)
	}
	got, err := os.ReadFile(serverBin)
	if err != nil || string(got) != "old-server" {
		t.Fatalf("server after rollback = %q, %v; want old-server", got, err)
	}
	if intentMarkerExists(t, dataDir) {
		t.Fatal("the marker must still be consumed")
	}
}

// TestPerformRollbackNoMarker: idempotent everyday case - no marker, no
// action, no error.
func TestPerformRollbackNoMarker(t *testing.T) {
	if err := PerformRollback(t.TempDir(), filepath.Join(t.TempDir(), serverBinaryName)); err != nil {
		t.Fatalf("no marker must be a no-op, got %v", err)
	}
}

// TestPerformRollbackNoopWhenTargetMatches: if the on-disk binary already
// matches the target (the L1 reconcile consumed the upgrade between the
// caller's check and this call), nothing is restored and the marker is
// cleaned up so no residue can re-trigger the net.
func TestPerformRollbackNoopWhenTargetMatches(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBin := filepath.Join(binDir, serverBinaryName)
	if err := os.WriteFile(serverBin, []byte("already-new"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("already-new")),
		Backup:        filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"),
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	if err := PerformRollback(dataDir, serverBin); err != nil {
		t.Fatalf("matching target must be a no-op, got %v", err)
	}
	got, err := os.ReadFile(serverBin)
	if err != nil || string(got) != "already-new" {
		t.Fatalf("binary must be untouched: %q, %v", got, err)
	}
	if intentMarkerExists(t, dataDir) {
		t.Fatal("the marker must be cleaned up on the no-op path")
	}
}

// TestPerformRollbackCorruptIntent: a present-but-broken marker refuses the
// rollback with an error (the caller decides what to do - the L2 path logs
// and exits 0); no panic, no half actions.
func TestPerformRollbackCorruptIntent(t *testing.T) {
	dataDir := t.TempDir()
	dir := filepath.Join(dataDir, "upgrade")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, intentFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PerformRollback(dataDir, filepath.Join(t.TempDir(), serverBinaryName)); err == nil {
		t.Fatal("a corrupt marker must refuse the rollback with an error")
	}
}

// TestPerformRollbackMissingBackup: the marker points at a backup that is
// gone - the rollback fails loudly (nothing was touched) instead of
// pretending to have recovered.
func TestPerformRollbackMissingBackup(t *testing.T) {
	binDir := t.TempDir()
	dataDir := t.TempDir()
	serverBin := filepath.Join(binDir, serverBinaryName)
	if err := os.WriteFile(serverBin, []byte("broken-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIntentMarker(t, dataDir, intentRecord{
		TargetVersion: "v0.7.9-beta",
		TargetSHA256:  sha256Hex([]byte("never-ran-server")),
		Backup:        filepath.Join(binDir, serverBinaryName+backupSuffix+"v0.7.8-beta"),
		Timestamp:     "2026-09-27T00:00:00Z",
	})
	if err := PerformRollback(dataDir, serverBin); err == nil {
		t.Fatal("a missing backup must fail the rollback")
	}
	got, err := os.ReadFile(serverBin)
	if err != nil || string(got) != "broken-server" {
		t.Fatalf("the binary must be untouched after a failed rollback: %q, %v", got, err)
	}
}

// TestSiblingBackupPath pins the cli-backup derivation from the server
// backup recorded in the marker, including the refusal to guess for
// unrecognized names.
func TestSiblingBackupPath(t *testing.T) {
	got := siblingBackupPath(filepath.Join("bin", serverBinaryName+backupSuffix+"v0.7.8-beta"), cliBinaryName)
	if want := filepath.Join("bin", cliBinaryName+backupSuffix+"v0.7.8-beta"); got != want {
		t.Fatalf("sibling path = %q, want %q", got, want)
	}
	for _, weird := range []string{"", "random-file", serverBinaryName + "-unversioned"} {
		if got := siblingBackupPath(weird, cliBinaryName); got != "" {
			t.Fatalf("unrecognized server backup %q must yield an empty sibling, got %q", weird, got)
		}
	}
}
