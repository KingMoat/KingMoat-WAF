// Console port change (settings page): moves the management console to a new
// TCP port at runtime.
//
// Deployment model (systemd all-in-one): the unit reads the console port from
// an EnvironmentFile (CONSOLE_PORT=<port> in <data-dir>/console.env, wired by
// deploy/install.sh) instead of a hardcoded -console-addr value, because
// ProtectSystem=strict keeps the unit file in /etc/systemd/system read-only
// for the service while the data directory stays writable (ReadWritePaths).
// The change flow: validate → rewrite console.env atomically → submit
// `systemctl restart kingmoat` (fire-and-forget) → answer the client
// immediately (the restart tears the process down ~2s later; the new process
// binds the new port). The flow is only offered when it can actually work:
// the EnvironmentFile is wired AND exists AND the process runs under systemd
// (see consolePortChangeable).
package api

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/store"
)

// consoleEnvName is the EnvironmentFile base name inside the data directory.
const consoleEnvName = "console.env"

// defaultRestartDelay gives the HTTP response a head start before systemd
// tears the process down.
const defaultRestartDelay = 2 * time.Second

// defaultPortProbe reports whether the host can still bind a wildcard
// listener on port (nil error = free). Deliberately a real net.Listen probe
// instead of parsing `ss -nHtln`: it is portable (no external tool, same
// behavior on every distro and in tests) and answers the exact question that
// matters - can the restarted service bind the port. Binding privileged
// ports (<1024) requires CAP_NET_BIND_SERVICE, which the deployed unit
// grants via AmbientCapabilities; the probe runs inside the same process
// (and sandbox) the service will listen in, so a pass here is ground truth.
func defaultPortProbe(port int) error {
	ln, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	return ln.Close()
}

// defaultRestart applies the console-port change by SUBMITTING the unit
// restart to systemd, deliberately without waiting for it.
//
// Waiting here is self-kill: `systemctl restart kingmoat` is a dbus IPC call
// to PID 1, and the restart's stop phase SIGTERMs every process in the unit's
// cgroup - the default KillMode=control-group includes this very systemctl
// client. Blocking on it (CombinedOutput/Wait) therefore surfaces
// `signal: terminated` as a spurious error on every successful restart. The
// dbus submission precedes the stop phase (the queued job is what triggers
// the stop), so start-and-forget is safe: the job always ends up queued in
// PID 1, and the torn-down client is reaped by init moments later. Note that
// systemctl IPC is NOT restricted by ProtectSystem=strict (that sandbox
// limits filesystem writes, not IPC) - to be confirmed on the real machine
// (openEuler hardened profile). If real-machine testing ever shows the
// submission losing that race, switch to `systemd-run --on-active=...`
// (transient timer outside the unit's cgroup).
func defaultRestart() error {
	cmd := exec.Command("systemctl", "restart", "kingmoat")
	if err := submitRestart(cmd); err != nil {
		return fmt.Errorf("systemctl restart kingmoat: %w", err)
	}
	return nil
}

// submitRestart starts cmd fire-and-forget: only a failed exec is an error.
// The child is reaped by a background Wait so a failed submission (polkit
// denial, missing unit, dbus error) does not leak a zombie; on success this
// process is torn down with the unit cgroup moments later and the child is
// reaped by init - the goroutine simply never completes in that case. Test
// seam for the must-not-block guarantee.
func submitRestart(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("console port restart client exited with error", "err", err)
		}
	}()
	return nil
}

// consolePortChangeable reports whether the online port-change flow can
// actually work in the current deployment, and (when false) why. All four
// conditions must hold:
//
//  1. the EnvironmentFile path was wired at boot (systemd all-in-one model);
//  2. the EnvironmentFile exists on disk: a binary-replacement upgrade onto
//     an old unit without the EnvironmentFile line would otherwise accept
//     the write while the restart still uses the old unit (port never
//     moves);
//  3. this process was started by systemd: every unit-spawned process has
//     INVOCATION_ID set, a hand-launched binary (development, Windows,
//     manual runs) does not - scheduling `systemctl restart` from it would
//     either fail (polkit denies non-root users managing system units) or
//     restart nothing meaningful;
//  4. the process runs as root: the stock static template (User=kingmoat)
//     and any non-root unit get their `systemctl restart` rejected by the
//     default polkit policy (auth_admin_keep), which would silently fail
//     after the env write (the card must not offer a change that cannot
//     land). Deliberately conservative: an operator who explicitly grants
//     polkit allowances for a non-root unit loses the card (acceptable;
//     documented in deploy/README.md).
func consolePortChangeable(envPath string, euid func() int) (bool, string) {
	if envPath == "" {
		return false, "未接入 systemd 部署（启动参数未提供 EnvironmentFile 路径）"
	}
	if _, err := os.Stat(envPath); err != nil {
		return false, "EnvironmentFile 不存在（当前 unit 未接入 console.env，重启后端口变更不会生效）"
	}
	if os.Getenv("INVOCATION_ID") == "" {
		return false, "非 systemd 启动（手工运行或开发模式），不支持在线重启服务"
	}
	if euid() != 0 {
		return false, "服务以非 root 用户运行（polkit 默认拒绝其管理 unit），不支持在线重启服务"
	}
	return true, ""
}

// handleConsolePortGet returns the console port this process is serving on
// and whether the port-change flow is available (changeable is a real
// deployment probe, not the wired flag; reason explains a false).
func (s *Server) handleConsolePortGet(w http.ResponseWriter, r *http.Request) {
	changeable, reason := consolePortChangeable(s.opts.ConsoleEnvPath, s.opts.euidProbe())
	out := map[string]any{
		"port":       s.opts.ConsolePort,
		"changeable": changeable,
	}
	if !changeable {
		out["reason"] = reason
	}
	writeJSON(w, http.StatusOK, out)
}

// handleConsolePortSet moves the management console to a new port. After all
// validations pass the EnvironmentFile is rewritten atomically and the
// service restart request is submitted (delayed so this response reaches the
// client first); the response is final even though the restart happens later.
func (s *Server) handleConsolePortSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if changeable, reason := consolePortChangeable(s.opts.ConsoleEnvPath, s.opts.euidProbe()); !changeable {
		writeErr(w, http.StatusNotImplemented, simpleError("当前运行模式不支持在线修改管理端口（"+reason+"）"))
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		writeErr(w, http.StatusBadRequest, simpleError("端口需在 1-65535 之间"))
		return
	}
	if s.opts.ConsolePort > 0 && req.Port == s.opts.ConsolePort {
		writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf("新端口与当前管理端口相同（%d）", req.Port)))
		return
	}
	// Data-plane collision: console and reverse-proxy listeners share one
	// process, so the new port must not take a data-plane listen port.
	if _, cfg := s.opts.Center.Current(); cfg != nil {
		if p := listenerPort(cfg.ListenHTTP); p == req.Port {
			writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf("端口 %d 已被数据面 HTTP 监听使用，请换一个端口", req.Port)))
			return
		}
		if p := listenerPort(cfg.ListenHTTPS); p == req.Port {
			writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf("端口 %d 已被数据面 HTTPS 监听使用，请换一个端口", req.Port)))
			return
		}
	}
	probe := s.opts.PortProbe
	if probe == nil {
		probe = defaultPortProbe
	}
	if err := probe(req.Port); err != nil {
		writeErr(w, http.StatusBadRequest, simpleError(fmt.Sprintf("端口 %d 已被宿主机上其他进程监听，请换一个端口（%v）", req.Port, err)))
		return
	}
	if err := writeConsoleEnv(s.opts.ConsoleEnvPath, req.Port); err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("写入 %s 失败：%w", s.opts.ConsoleEnvPath, err))
		return
	}
	delay := s.opts.RestartDelay
	if delay <= 0 {
		delay = defaultRestartDelay
	}
	restart := s.opts.Restart
	if restart == nil {
		restart = defaultRestart
	}
	s.recordChange(r, "console.port_change", strconv.Itoa(req.Port),
		fmt.Sprintf("console port change %d -> %d, restart request submitted to systemd", s.opts.ConsolePort, req.Port))
	time.AfterFunc(delay, func() {
		if err := restart(); err != nil {
			// console.env is already written: a manual `systemctl restart
			// kingmoat` still applies the new port. With the fire-and-forget
			// submit this only fires when the systemctl exec itself failed.
			slog.Error("console port change: restart request submission failed", "port", req.Port, "err", err)
		}
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"port":    req.Port,
		"message": "端口变更中，约 30 秒后请用新地址访问控制台",
	})
}

// writeConsoleEnv atomically rewrites the EnvironmentFile with the new port
// (temp file + rename in the same directory, 0600). The data directory is
// inside the unit's ReadWritePaths, so the write is allowed under
// ProtectSystem=strict; the unit re-reads the file on the scheduled restart.
func writeConsoleEnv(path string, port int) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+consoleEnvName+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(fmt.Sprintf("CONSOLE_PORT=%d\n", port))
	merr := tmp.Chmod(0o600)
	clerr := tmp.Close()
	if werr != nil || merr != nil || clerr != nil {
		_ = os.Remove(name)
		if werr != nil {
			return werr
		}
		if merr != nil {
			return merr
		}
		return clerr
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// listenerPort extracts the TCP port of a listen address ("0.0.0.0:80" and
// ":80" → 80; 0 when unset or unparsable).
func listenerPort(addr string) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 {
		return 0
	}
	return p
}
