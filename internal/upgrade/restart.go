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
	"runtime"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/naming"
)

// ErrRestartUnavailable marks deployments where the automatic restart path
// does not exist at all (non-Linux platform, or Linux without systemctl):
// the console API (POST /api/system/restart) answers 501 for it, while any
// other probe failure (unwritable binary directory, non-root process) is a
// 500 - systemd exists, this process just may not use it.
var ErrRestartUnavailable = errors.New("非 systemd 部署形态，不支持在线重启服务")

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
		return fmt.Errorf("提交服务重启失败: %w（可手动执行 systemctl restart %s 完成重启，升级意图已记录，下次启动系统会自动核对）", err, naming.ServiceName)
	}
	// Deliberately no post-restart tracking: this process is about to be
	// torn down with the unit cgroup. The restart outcome is settled by
	// the self-heal net (T-05) and the UI polling (T-08), never here -
	// task-level success only means "restart submitted" (now strengthened
	// to "the submission was accepted by systemd").
	return nil
}

// defaultRestarter SUBMITS the kingmoatwaf unit restart to systemd and
// observes the submission verdict without waiting for the restart itself.
//
// The original shape - `systemctl restart` + fire-and-forget Start - was
// a trade between two failure modes and lost on both ends:
//
//   - Blocking is self-kill: `systemctl restart kingmoatwaf` is a dbus IPC
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
	cmd := exec.CommandContext(ctx, "systemctl", "--no-block", "restart", naming.ServiceName)
	if err := submitRestart(ctx, cmd); err != nil {
		return fmt.Errorf("systemctl --no-block restart %s: %w", naming.ServiceName, err)
	}
	return nil
}

// submitRestart runs the systemctl submission to completion and reports
// its verdict: exit 0 means the restart job was accepted; any other exit
// fails the submission with the command's combined stdout/stderr folded
// into the error - the polkit/unit diagnostics live there, not in the
// exit code. Two narrow windows are tolerated / reclassified so a real
// submission is never misreported:
//
//   - A SIGTERM exit means systemd's stop phase tore down the unit cgroup
//     (and this client with it) AFTER the job was accepted - reported as
//     success. (A timeout kill uses SIGKILL instead, so the two are
//     distinguishable.)
//   - A SIGKILL exit paired with an expired context is the bounded-wait
//     path (hung dbus): reported as a timeout, never as the raw "signal:
//     killed" error. A context expiry only matters when no verdict was
//     reached; a clean exit-0 submission stays a success.
//
// Test seam: tests inject fake systemctl binaries and assert verdict
// propagation.
func submitRestart(ctx context.Context, cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Unix: systemd's stop phase may tear down the unit cgroup (and
		// this client with it, SIGTERM) after the restart job was accepted
		// - tolerate that as a success. The bounded-wait kill uses SIGKILL
		// ("signal: killed"), so the two are distinguishable. Matched by
		// string because os.ProcessState.Signaled/Signal are unix-only
		// APIs; on Windows this error shape never occurs (production path
		// is GOOS-gated and terminated children report "exit status N").
		if strings.HasPrefix(err.Error(), "signal: terminated") {
			return nil
		}
		if ctx.Err() != nil {
			// Bounded wait expired before a verdict: hung dbus (SIGKILL on
			// Linux) or a terminated client on Windows - report as a timeout
			// instead of the raw "signal: killed" / "exit status 1" error.
			return fmt.Errorf("等待 systemctl 提交结果超时: %w", ctx.Err())
		}
		if summary := strings.TrimSpace(string(out)); summary != "" {
			return fmt.Errorf("%w: %s", err, summary)
		}
		return err
	}
	// err == nil: the verdict is in (job accepted) - a concurrently expired
	// context does not change that fact, so no timeout check here.
	return nil
}

// RestartProbe reports whether a standalone service restart (console API,
// POST /api/system/restart) can be submitted in this deployment, and why
// not when it cannot. The console API maps ErrRestartUnavailable to 501
// (no automatic restart path exists: non-Linux platform or no systemctl)
// and every other failure to 500 (systemd exists, this process just may
// not use it). probeFn (WithProber) overrides the whole probe, mirroring
// the replace stage's seam so tests inject canned verdicts on any host.
func (s *Service) RestartProbe() error {
	if s.probeFn != nil {
		return s.probeFn()
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w（当前平台 %s）", ErrRestartUnavailable, runtime.GOOS)
	}
	return s.probeRestartCapability()
}

// Restart submits a standalone service restart for the console API
// (POST /api/system/restart): capability probe followed by the same
// observed `systemctl --no-block restart` submission the upgrade pipeline
// uses. Deliberately NOT the upgrade restart stage (defaultRestartStage):
// a plain restart carries no new binary, so there is no intent marker to
// require and no self-heal net to arm - that marker check is
// upgrade-specific and would refuse every API-triggered restart. The
// submission is bounded (restartSubmitTimeout) and its verdict observed;
// the caller learns whether the restart was SUBMITTED, never its outcome
// (this process is torn down with the unit cgroup moments later).
func (s *Service) Restart(ctx context.Context) error {
	if err := s.RestartProbe(); err != nil {
		return err
	}
	submit := s.restartSubmitFn
	if submit == nil {
		submit = defaultRestarter
	}
	return submit(ctx)
}
