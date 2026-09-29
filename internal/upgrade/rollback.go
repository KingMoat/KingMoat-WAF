// Self-heal rollback (upgrade card T-05): the decision core shared by the
// L1 in-process startup reconcile (wired by the server's own boot path) and
// the L2 systemd ExecStartPre hook (kmwafctl upgrade-rollback, invoked
// before every unit start). Both consumers compare the on-disk state against
// the upgrade intent marker left by the replace stage (replace.go) and
// restore the recorded pre-upgrade backups when the new binaries did not
// make it. These are package-level functions on purpose: the L2 consumer is
// the standalone kmwafctl binary, which has no Service instance.
package upgrade

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// brokenSuffix separates the binary name from the diagnostic copy of
	// the binary it replaced (<name>.broken-<timestamp>, kept next to the
	// restored one for post-mortem; one pair per rollback attempt - the
	// intent marker is consumed afterwards, so the net fires once per
	// upgrade, not on every boot).
	brokenSuffix = ".broken-"
	// brokenTimeLayout is the timestamp format for broken copies: sortable,
	// and free of ':' so the name stays legal on Windows filesystems too
	// (the L2 path itself only ever runs on Linux, but the tests do not).
	brokenTimeLayout = "20060102T150405Z"
)

// CheckUpgradeIntent reconciles the on-disk server binary against the
// upgrade intent marker (<dataDir>/upgrade/intent.json). Outcomes:
//
//   - marker absent or unparseable → (false, reason): nothing can be
//     concluded, no action is ever taken (the marker is the only rollback
//     reference, so a broken one disables the net rather than triggers it);
//   - marker's target_sha256 matches the current binary → the upgrade
//     SUCCEEDED: the marker is consumed (deleted) and (false, reason) is
//     returned, so later boots skip the check entirely;
//   - mismatch, or the current binary cannot be read at all → (true,
//     reason): the new binary did not make it (crash loop, truncated
//     swap, missing file) and the recorded backup is the only self-rescue
//     path - the caller should run PerformRollback.
//
// The function never panics and never returns an error: the L2 consumer's
// contract is "always exit 0" and every abnormality is folded into the
// (needed, reason) pair for the caller to log.
func CheckUpgradeIntent(dataDir, currentBinaryPath string) (bool, string) {
	marker := intentMarkerPath(dataDir)
	rec, err := readIntent(marker)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "无升级意图标记"
		}
		return false, fmt.Sprintf("升级意图标记无法解析，自愈核对跳过: %v", err)
	}
	if strings.TrimSpace(rec.TargetSHA256) == "" {
		return false, "升级意图标记缺少 target_sha256，自愈核对跳过"
	}
	sum, err := sha256File(currentBinaryPath)
	if err != nil {
		// A missing/unreadable binary is the deepest brick state: even the
		// comparison is impossible, but the recorded backup still exists -
		// attempting the rollback is the only self-rescue left.
		return true, fmt.Sprintf("当前二进制无法读取（%v），按升级未成功处理", err)
	}
	if sum == strings.ToLower(rec.TargetSHA256) {
		// The upgraded binary is the one the intent describes: the upgrade
		// succeeded on this boot. Consume the marker so the net never
		// fires again for this upgrade (a failed removal is reported in
		// the reason but does not change the verdict - the next boot would
		// simply re-check and re-consume).
		if rmErr := os.Remove(marker); rmErr != nil {
			return false, fmt.Sprintf("升级成功（sha256 已确认一致），但清理意图标记失败: %v", rmErr)
		}
		return false, fmt.Sprintf("升级成功（%s），已消费意图标记", rec.TargetVersion)
	}
	return true, fmt.Sprintf("当前二进制与升级意图不符（目标 %s），需要回滚", rec.TargetVersion)
}

// PerformRollback restores the pre-upgrade binaries from the backups
// recorded in the intent marker. It is a no-op (nil) when there is no
// marker, the marker is unusable for rollback decisions, or the current
// binary already matches the target (someone else reconciled first - the
// marker is cleaned up so no residue is left). Otherwise:
//
//  1. the possibly-broken current server binary is set aside as
//     <binary>.broken-<timestamp> (diagnostics stay on disk);
//  2. the recorded server backup is published back over the binary path
//     (temp file in the same directory, fsync, atomic rename, chmod 0755);
//  3. the cli is treated the same way, deriving its backup path from the
//     server backup's sibling name (<dir>/kmwafctl.bak-<version>) - a
//     missing cli backup is tolerated and never blocks the server restore;
//  4. the intent marker is deleted so the net does not loop (the restore
//     itself is idempotent, so even a failed marker removal on the next
//     boot would only redo harmless work, and the error surfaces).
//
// Every failure is returned as an error for the caller to decide - the L2
// ExecStartPre consumer logs it and exits 0 regardless (blocking the unit
// start would be strictly worse than a failed rollback).
func PerformRollback(dataDir, currentBinaryPath string) error {
	marker := intentMarkerPath(dataDir)
	rec, err := readIntent(marker)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("升级意图标记无法解析，拒绝回滚: %w", err)
	}
	if strings.TrimSpace(rec.TargetSHA256) == "" {
		return errors.New("升级意图标记缺少 target_sha256，拒绝回滚")
	}
	// Idempotence guard: if the on-disk binary already matches the target
	// (e.g. the L1 reconcile consumed the upgrade between the caller's
	// check and this call), there is nothing to restore - just make sure
	// the marker does not linger.
	if sum, err := sha256File(currentBinaryPath); err == nil && sum == strings.ToLower(rec.TargetSHA256) {
		_ = os.Remove(marker)
		return nil
	}
	if strings.TrimSpace(rec.Backup) == "" {
		return errors.New("升级意图标记缺少备份路径，无法回滚")
	}
	if err := restoreBinary(rec.Backup, currentBinaryPath); err != nil {
		return fmt.Errorf("回滚 %s 失败: %w", serverBinaryName, err)
	}
	// The cli's backup sits beside the server's, tagged with the same
	// pre-upgrade version. Absent backup (unrecognized name, pruned or
	// never created) is not an error: the server restore already happened
	// and is what keeps the service alive. A present-but-broken cli
	// backup, however, still fails the rollback loudly.
	if cliBak := siblingBackupPath(rec.Backup, cliBinaryName); cliBak != "" {
		if _, err := os.Stat(cliBak); err == nil {
			if err := restoreBinary(cliBak, filepath.Join(filepath.Dir(currentBinaryPath), cliBinaryName)); err != nil {
				return fmt.Errorf("回滚 %s 失败: %w", cliBinaryName, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("检查 %s 备份失败: %w", cliBinaryName, err)
		}
	}
	if err := os.Remove(marker); err != nil {
		return fmt.Errorf("回滚完成但删除意图标记失败（下次启动将重做幂等的恢复动作）: %w", err)
	}
	return nil
}

// restoreBinary republishes the pre-upgrade backup src at dst: the current
// dst (possibly broken) is first preserved as dst.broken-<timestamp> for
// diagnostics, then src is published atomically. A missing dst is fine -
// restoring over nothing is exactly the self-rescue for a vanished binary.
func restoreBinary(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("备份 %s 不可用: %w", src, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("备份 %s 是目录，无法用于恢复", src)
	}
	if _, err := os.Stat(dst); err == nil {
		broken := dst + brokenSuffix + time.Now().UTC().Format(brokenTimeLayout)
		// Best-effort but checked: if the broken copy cannot be written
		// (unwritable directory), the publish below would fail too - fail
		// early with the precise reason instead of a confusing rename one.
		if err := copyFile(dst, broken, 0o600, false); err != nil {
			return fmt.Errorf("保留现场副本 %s 失败: %w", broken, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查当前二进制 %s 失败: %w", dst, err)
	}
	return publishFile(src, dst)
}

// publishFile atomically copies src over dst: the payload is written to a
// temporary file in dst's directory (same filesystem, so the rename is an
// atomic directory-entry swap), fsynced so the bytes survive a crash,
// renamed over the target and explicitly chmod'ed executable.
func publishFile(src, dst string) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".rbk-*")
	if err != nil {
		return fmt.Errorf("创建恢复临时文件失败: %w", err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("创建恢复临时文件失败: %w", err)
	}
	if err := copyFile(src, name, 0o755, true); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("写入恢复临时文件失败: %w", err)
	}
	if err := os.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("恢复 %s 失败: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return fmt.Errorf("设置 %s 执行权限失败: %w", dst, err)
	}
	return nil
}

// siblingBackupPath derives the backup path of the named binary from the
// server backup recorded in the intent marker: both backups were created
// beside the binaries with the same version tag
// (<dir>/kingmoatwaf.bak-<version> → <dir>/kmwafctl.bak-<version>). An
// unrecognized server backup name yields "" (the caller skips that
// restore instead of guessing a path).
func siblingBackupPath(serverBak, name string) string {
	base := filepath.Base(serverBak)
	version := strings.TrimPrefix(base, serverBinaryName+backupSuffix)
	if version == "" || version == base {
		return ""
	}
	return filepath.Join(filepath.Dir(serverBak), name+backupSuffix+version)
}

// intentMarkerPath is the upgrade intent marker's location for the
// package-level self-heal consumers (same layout as Service.intentPath).
func intentMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, "upgrade", intentFileName)
}

// readIntent loads and parses the intent marker; the returned error keeps
// the fs error so callers can distinguish "absent" (os.IsNotExist) from
// "present but broken".
func readIntent(path string) (intentRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return intentRecord{}, err
	}
	var rec intentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return intentRecord{}, fmt.Errorf("intent.json 不是有效 JSON: %w", err)
	}
	return rec, nil
}
