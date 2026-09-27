// Restart orchestration (upgrade card T-06): hand the replaced
// installation over to systemd. The submission is OBSERVED but not
// awaited: `systemctl --no-block` queues the restart job and exits
// immediately with a verdict-bearing exit code, so a rejected submission
// (missing unit, polkit denial, dbus error) fails the task instead of
// being reported as a completed upgrade. The deployment mechanics are
// shared with internal/api/console_port.go (same unit, same KillMode
// reasoning; duplicated because the upgrade package must not import the
// api package) - the upgrade flow additionally observes the verdict,
// because a false "upgrade complete" is worse than a logged warning.
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// restartSubmitTimeout bounds one `systemctl --no-block` submission.
// --no-block returns as soon as the job is queued (well under a second in
// practice); the bound is a hang safety net, not expected latency - past
// it the client is killed and the submission reported as failed instead
// of wedging the upgrade task.
const restartSubmitTimeout = 5 * time.Second

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
	if err := defaultRestarter(ctx); err != nil {
		return fmt.Errorf("提交服务重启失败: %w（可手动执行 systemctl restart kingmoat 完成重启，升级意图已记录，下次启动系统会自动核对）", err)
	}
	// Deliberately no post-restart tracking: this process is about to be
	// torn down with the unit cgroup. The restart outcome is settled by
	// the self-heal net (T-05) and the UI polling (T-08), never here -
	// task-level success only means "restart submitted" (now strengthened
	// to "the submission was accepted by systemd").
	return nil
}

// defaultRestarter SUBMITS the kingmoat unit restart to systemd and
// observes the submission verdict without waiting for the restart itself.
//
// The original shape - `systemctl restart` + fire-and-forget Start - was
// a trade between two failure modes and lost on both ends:
//
//   - Blocking is self-kill: `systemctl restart kingmoat` is a dbus IPC
//     call to PID 1, and the restart's stop phase SIGTERMs every process
//     in the unit's cgroup - the default KillMode=control-group includes
//     this very systemctl client. Waiting on a plain restart
//     (CombinedOutput/Wait) therefore surfaces `signal: terminated` as a
//     spurious error on every successful restart.
//   - Not observing the exit code at all turned every rejected
//     submission (missing unit, polkit denial for a non-root caller,
//     dbus error) into a bogus "upgrade complete": Start() succeeds the
//     moment the client process is spawned, and the client's own nonzero
//     exit went to a fire-and-forget log line nobody reads.
//
// `--no-block` resolves the dilemma: systemctl queues the restart job via
// dbus and exits immediately, before the stop phase begins - the client
// is gone by the time the stop phase would run, so the KillMode kill
// window is closed by construction and a synchronous CombinedOutput is
// safe. The exit code then reflects the submission only (job accepted =
// 0; otherwise non-zero with a diagnostic on stderr), and submitRestart
// folds that diagnostic into the task error. The restart outcome itself
// is still settled by the self-heal net (T-05) and the UI polling (T-08).
//
// Note that systemctl IPC is NOT restricted by ProtectSystem=strict
// (that sandbox limits filesystem writes, not IPC) - still to be
// confirmed on the real machine (openEuler hardened profile). If
// real-machine testing ever shows the submission losing a race with the
// stop phase, switch to `systemd-run --on-active=...` (transient timer
// outside the unit's cgroup).
func defaultRestarter(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, restartSubmitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "--no-block", "restart", "kingmoat")
	if err := submitRestart(ctx, cmd); err != nil {
		return fmt.Errorf("systemctl --no-block restart kingmoat: %w", err)
	}
	return nil
}

// submitRestart runs the systemctl submission to completion and reports
// its verdict: exit 0 means the restart job was accepted; any other exit
// fails the submission with the command's combined stdout/stderr folded
// into the error - the polkit/unit diagnostics live there, not in the
// exit code. A context expiry (the restartSubmitTimeout bound or a
// canceled task) is reported as its own failure so a hung dbus can never
// masquerade as a systemd verdict. Test seam: tests inject fake
// systemctl binaries and assert verdict propagation.
func submitRestart(ctx context.Context, cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("等待 systemctl 提交结果超时: %w", ctx.Err())
	}
	if err != nil {
		if summary := strings.TrimSpace(string(out)); summary != "" {
			return fmt.Errorf("%w: %s", err, summary)
		}
		return err
	}
	return nil
}
