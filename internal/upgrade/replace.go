// Binary replacement (upgrade card T-04): capability probe, rolling
// backups, atomic swap of the running kingmoat and kingmoat-cli, and the
// upgrade intent marker consumed by the self-heal net (T-05). The running
// process is never disturbed - the swap only re-points directory entries,
// so the old binary keeps serving until the restart stage (T-06) takes
// over.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	// intentFileName is the upgrade intent marker inside
	// <dataDir>/upgrade/. It is the contract between the replace stage and
	// the self-heal net (T-05): the L1 startup reconcile compares the
	// running version against target_version, and the L2 ExecStartPre
	// rollback compares the on-disk server binary's SHA256 against
	// target_sha256, restoring the recorded backup on mismatch.
	intentFileName = "intent.json"
	// backupKeep is how many backups per binary the rolling window keeps.
	backupKeep = 2
	// backupSuffix separates the binary name from the backed-up version.
	backupSuffix = ".bak-"
)

// intentRecord is the on-disk shape of the intent marker.
type intentRecord struct {
	TargetVersion string `json:"target_version"`
	TargetSHA256  string `json:"target_sha256"`
	Backup        string `json:"backup"`
	Timestamp     string `json:"timestamp"`
}

// defaultReplace is the production replace stage: probe → backup → swap →
// intent. Every failure leaves the installation either untouched or
// restored to the pre-upgrade binaries, and never reports success: the
// restart stage only runs after the intent marker is durably on disk.
func (s *Service) defaultReplace(ctx context.Context, t *Task) error {
	probe := s.probeFn
	if probe == nil {
		probe = s.probeReplaceCapability
	}
	if err := probe(); err != nil {
		// Early failure, before anything on disk is touched. The task
		// message guides to the manual path; the error carries the exact
		// reason (surfaced as the task's Error by finishTask).
		s.setState(t, TaskReplacing, "当前环境不支持在线升级，请从 Gitee 发布页手动下载升级包")
		return fmt.Errorf("升级能力探测失败: %w", err)
	}
	dir, err := s.currentBinaryDir()
	if err != nil {
		return fmt.Errorf("定位当前安装目录失败: %w", err)
	}
	if t.artifactDir == "" {
		return errors.New("升级产物目录缺失（内部错误）")
	}
	serverBak, err := s.backupCurrentBinaries(dir)
	if err != nil {
		return err
	}
	if err := s.atomicInstall(filepath.Join(t.artifactDir, serverBinaryName), dir, serverBinaryName, t.ID); err != nil {
		return err
	}
	if err := s.atomicInstall(filepath.Join(t.artifactDir, cliBinaryName), dir, cliBinaryName, t.ID); err != nil {
		// The server binary is already swapped: put the pre-upgrade pair
		// back so a failed upgrade never leaves a mixed installation (a
		// new server running with an old cli would only surface at the
		// next start, outside this task's failure reporting).
		s.restoreFromBackups(dir)
		return err
	}
	sum, err := sha256File(filepath.Join(t.artifactDir, serverBinaryName))
	if err != nil {
		s.restoreFromBackups(dir)
		return err
	}
	// Write success defines replace completion: without the marker the
	// self-heal net cannot tell a completed upgrade from a broken one, so
	// a marker failure fails the stage (and restores the old binaries).
	if err := s.writeIntent(t, serverBak, sum); err != nil {
		s.restoreFromBackups(dir)
		return err
	}
	return nil
}

// restoreFromBackups best-effort re-installs the pre-upgrade binaries from
// the backups created moments ago by the same upgrade run. Errors are
// deliberately ignored: the backups stay on disk for manual recovery
// regardless, and the stage failure is reported to the caller anyway.
func (s *Service) restoreFromBackups(dir string) {
	version := sanitizeFileName(s.currentVersion)
	if version == "" {
		return
	}
	for _, name := range []string{serverBinaryName, cliBinaryName} {
		bak := filepath.Join(dir, name+backupSuffix+version)
		_ = s.atomicInstall(bak, dir, name, "restore")
	}
}

// probeReplaceCapability reports whether this deployment can swap the
// running binaries and restart the service. Every check answers a question
// that only the live environment knows:
//
//  0. linux only: the self-upgrade pipeline (systemd restart, ExecStartPre
//     rollback) is a Linux/systemd shape; Windows deployments get the
//     manual-download guidance instead (upgrade card: no auto-replacement
//     on Windows).
//  1. the binary directory is writable: the swap is a rename inside that
//     directory, and under ProtectSystem=strict the verdict depends on the
//     unit's ReadWritePaths mounts - a real create-and-delete probe beats
//     parsing unit text (old units lack the path and must re-run
//     install.sh first).
//  2. systemctl exists: the restart stage submits the unit restart through
//     it; without it the upgrade could replace binaries but never hand
//     over to the new ones.
func (s *Service) probeReplaceCapability() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("当前平台 %s 不支持在线替换二进制（仅支持 systemd 部署的 Linux）", runtime.GOOS)
	}
	dir, err := s.currentBinaryDir()
	if err != nil {
		return fmt.Errorf("定位当前二进制目录失败: %w", err)
	}
	if err := probeDirWritable(dir); err != nil {
		return fmt.Errorf("二进制目录 %s 不可写（存量部署请重跑 install.sh 更新 systemd 单元后再试）: %w", dir, err)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("未找到 systemctl，无法自动重启服务（非 systemd 部署）")
	}
	return nil
}

// probeDirWritable answers whether the process can create files in dir by
// actually creating one (O_CREATE|O_EXCL via os.CreateTemp) and removing
// it again - the same ground-truth-over-text idea as the engine's startup
// writability probe, implemented with plain os APIs (no coraza build-tag
// surface involved).
func probeDirWritable(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s 不是目录", dir)
	}
	f, err := os.CreateTemp(dir, ".kingmoat-upgrade-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	closeErr := f.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

// currentBinaryDir resolves the directory holding the running binaries.
// Production derives it from this process's own executable path
// (/opt/kingmoat/kingmoat → /opt/kingmoat), so the swap always targets
// exactly the installation that is running; kingmoat-cli lives beside it.
// Tests pin the directory explicitly.
func (s *Service) currentBinaryDir() (string, error) {
	if s.binaryDir != "" {
		return s.binaryDir, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// backupCurrentBinaries copies the running kingmoat and kingmoat-cli next
// to themselves as <name>.bak-<current version> (same directory as the
// binaries, so a manual `cp` back needs no path hunting) and prunes each
// name's backups to the backupKeep newest by file name. Returns the server
// backup path - the file recorded in the intent marker and restored by the
// L2 rollback. Backups happen entirely BEFORE the first swap, so a backup
// failure aborts with the old binaries untouched.
func (s *Service) backupCurrentBinaries(dir string) (string, error) {
	version := sanitizeFileName(s.currentVersion)
	if version == "" {
		return "", fmt.Errorf("当前版本号 %q 无法用于备份命名", s.currentVersion)
	}
	var serverBak string
	for _, name := range []string{serverBinaryName, cliBinaryName} {
		src := filepath.Join(dir, name)
		if fi, err := os.Stat(src); err != nil {
			return "", fmt.Errorf("当前二进制 %s 不存在，无法备份: %w", src, err)
		} else if fi.IsDir() {
			return "", fmt.Errorf("当前二进制 %s 是目录，无法备份", src)
		}
		bak := filepath.Join(dir, name+backupSuffix+version)
		if err := copyFile(src, bak, 0o755, false); err != nil {
			return "", fmt.Errorf("备份 %s 失败: %w", name, err)
		}
		if name == serverBinaryName {
			serverBak = bak
		}
		if err := pruneBackups(dir, name, backupKeep); err != nil {
			return "", err
		}
	}
	return serverBak, nil
}

// pruneBackups keeps only the keep newest backups of name (files named
// <name>.bak-* directly in dir), comparing by file name. Version tags are
// compared lexicographically - not true semver order across digit-width
// boundaries (v0.7.10 sorts before v0.7.9), but deterministic, and the
// window's purpose is only to bound residue, not to build a rollback chain.
func pruneBackups(dir, name string, keep int) error {
	prefix := name + backupSuffix
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("扫描备份目录失败: %w", err)
	}
	var baks []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		baks = append(baks, e.Name())
	}
	if len(baks) <= keep {
		return nil
	}
	sort.Strings(baks)
	for _, old := range baks[:len(baks)-keep] {
		if err := os.Remove(filepath.Join(dir, old)); err != nil {
			return fmt.Errorf("清理旧备份 %s 失败: %w", old, err)
		}
	}
	return nil
}

// atomicInstall publishes src as dir/name: the payload is copied to a
// temporary file in the SAME directory (same filesystem, so the rename is
// an atomic directory-entry swap), fsynced so the bytes survive a crash,
// renamed over the target, and forced executable. The running process is
// unaffected by the swap - it keeps executing its old inode until the
// restart. Any failure before the rename removes the temporary file and
// leaves the target untouched.
func (s *Service) atomicInstall(src, dir, name, taskID string) error {
	tmp := filepath.Join(dir, name+".new-"+taskID)
	if err := copyFile(src, tmp, 0o755, true); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("写入新二进制 %s 失败: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换 %s 失败: %w", name, err)
	}
	// Card order: chmod after the rename, so the published binary is
	// executable regardless of the mode the copy carried. The crash window
	// between rename and chmod leaves a non-executable binary - exactly
	// the broken state the L2 ExecStartPre rollback (T-05) recovers from.
	if err := os.Chmod(filepath.Join(dir, name), 0o755); err != nil {
		return fmt.Errorf("设置 %s 执行权限失败: %w", name, err)
	}
	return nil
}

// writeIntent records the upgrade intent AFTER both binaries are swapped.
// The marker is deliberately NOT removed when the restart is submitted -
// the NEXT boot consumes and clears it (L1 reconcile: running version ==
// target → clear + history success; L2 ExecStartPre: on-disk SHA256 !=
// target_sha256 → restore the recorded backup). It is fsynced and renamed
// into place so it reliably survives the restart it precedes.
func (s *Service) writeIntent(t *Task, serverBak, serverSHA string) error {
	rec := intentRecord{
		TargetVersion: t.TargetVersion,
		TargetSHA256:  serverSHA,
		Backup:        serverBak,
		Timestamp:     rfc3339(s.now()),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("生成升级意图标记失败: %w", err)
	}
	path := s.intentPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建升级目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+intentFileName+"-*")
	if err != nil {
		return fmt.Errorf("写入升级意图标记失败: %w", err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	merr := tmp.Chmod(0o600)
	serr := tmp.Sync()
	clerr := tmp.Close()
	if werr != nil || merr != nil || serr != nil || clerr != nil {
		_ = os.Remove(name)
		if werr != nil {
			return fmt.Errorf("写入升级意图标记失败: %w", werr)
		}
		if merr != nil {
			return fmt.Errorf("写入升级意图标记失败: %w", merr)
		}
		if serr != nil {
			return fmt.Errorf("写入升级意图标记失败: %w", serr)
		}
		return fmt.Errorf("写入升级意图标记失败: %w", clerr)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("写入升级意图标记失败: %w", err)
	}
	return nil
}

// intentPath is the upgrade intent marker's location in the data directory.
func (s *Service) intentPath() string {
	return filepath.Join(s.baseDir, "upgrade", intentFileName)
}

// cleanupWorkspaces removes leftover per-task workspaces
// (<dataDir>/upgrade/<task-id>/) from previous runs - crashed tasks, or
// completed upgrades whose artifacts are already installed. Files directly
// under upgrade/ (the intent marker) are never touched. Best-effort:
// residue only wastes disk, so failures are ignored.
func (s *Service) cleanupWorkspaces() {
	root := filepath.Join(s.baseDir, "upgrade")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// sha256File returns the lowercase hex SHA256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("计算 %s 的 SHA256 失败: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile copies src to dst with the given permission bits; with fsync
// the data is forced to disk before close. Backups skip the sync (a torn
// backup is simply overwritten by the next upgrade attempt); the published
// binary requires it (a crash right after the rename must never expose a
// truncated executable).
func copyFile(src, dst string, mode os.FileMode, fsync bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	if fsync && cerr == nil {
		cerr = out.Sync()
	}
	if ferr := out.Close(); cerr == nil {
		cerr = ferr
	}
	return cerr
}
