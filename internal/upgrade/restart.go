// Restart orchestration (upgrade card T-06): hand the replaced
// installation over to systemd. The submission is fire-and-forget by
// design - the rationale is replicated below from
// internal/api/console_port.go (same deployment mechanics; duplicated
// because the upgrade package must not import the api package).
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// defaultRestartStage is the production restart stage. The upgrade intent
// marker written by the replace stage must exist: it is the self-heal
// net's only reference for the next boot (the L1 reconcile compares the
// running version against target_version; the L2 ExecStartPre rollback
// compares the on-disk binary's SHA256 against target_sha256). Submitting
// a restart without it would leave a possibly-broken new binary with no
// recovery path - the exact brick scenario this module prevents.
func (s *Service) defaultRestartStage(ctx context.Context, t *Task) error {
	if _, err := os.Stat(s.intentPath()); err != nil {
		return errors.New("升级意图标记缺失，拒绝重启（内部错误）")
	}
	if err := defaultRestarter(); err != nil {
		return fmt.Errorf("提交服务重启失败: %w（可手动执行 systemctl restart kingmoat 完成重启，升级意图已记录，下次启动系统会自动核对）", err)
	}
	// Deliberately no post-restart tracking: this process is about to be
	// torn down with the unit cgroup. The restart outcome is settled by
	// the self-heal net (T-05) and the UI polling (T-08), never here -
	// task-level success only means "restart submitted".
	return nil
}

// defaultRestarter SUBMITS the kingmoat unit restart to systemd, without
// waiting for it.
//
// Waiting here is self-kill: `systemctl restart kingmoat` is a dbus IPC
// call to PID 1, and the restart's stop phase SIGTERMs every process in
// the unit's cgroup - the default KillMode=control-group includes this
// very systemctl client. Blocking on it (CombinedOutput/Wait) therefore
// surfaces `signal: terminated` as a spurious error on every successful
// restart. The dbus submission precedes the stop phase (the queued job is
// what triggers the stop), so start-and-forget is safe: the job always
// ends up queued in PID 1, and the torn-down client is reaped by init
// moments later. Note that systemctl IPC is NOT restricted by
// ProtectSystem=strict (that sandbox limits filesystem writes, not IPC) -
// to be confirmed on the real machine (openEuler hardened profile). If
// real-machine testing ever shows the submission losing that race, switch
// to `systemd-run --on-active=...` (transient timer outside the unit's
// cgroup).
func defaultRestarter() error {
	cmd := exec.Command("systemctl", "restart", "kingmoat")
	if err := submitRestart(cmd); err != nil {
		return fmt.Errorf("systemctl restart kingmoat: %w", err)
	}
	return nil
}

// submitRestart starts cmd fire-and-forget: only a failed exec is an
// error. The child is reaped by a background Wait so a failed submission
// (polkit denial, missing unit, dbus error) does not leak a zombie; on
// success this process is torn down with the unit cgroup moments later
// and the child is reaped by init - the goroutine simply never completes
// in that case. Test seam for the must-not-block guarantee.
func submitRestart(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("upgrade restart client exited with error", "err", err)
		}
	}()
	return nil
}
