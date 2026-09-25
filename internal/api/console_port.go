// Console port change (settings page): moves the management console to a new
// TCP port at runtime.
//
// Deployment model (systemd all-in-one): the unit reads the console port from
// an EnvironmentFile (CONSOLE_PORT=<port> in <data-dir>/console.env, wired by
// deploy/install.sh) instead of a hardcoded -console-addr value, because
// ProtectSystem=strict keeps the unit file in /etc/systemd/system read-only
// for the service while the data directory stays writable (ReadWritePaths).
// The change flow: validate → rewrite console.env atomically → schedule
// `systemctl restart kingmoat` → answer the client immediately (the restart
// tears the process down ~2s later; the new process binds the new port).
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

// defaultRestart applies the console-port change by restarting the unit.
//
// systemctl is a dbus IPC call to PID 1 and is NOT restricted by
// ProtectSystem=strict (that sandbox limits filesystem writes, not IPC) - to
// be confirmed on the real machine (openEuler hardened profile). The restart
// job is submitted to systemd within milliseconds of the exec; the unit's
// own cgroup teardown may kill this client process afterwards, but the job
// already queued in PID 1 proceeds. If real-machine testing ever shows the
// submission losing that race, switch to `systemd-run --on-active=...`
// (transient timer outside the unit's cgroup).
func defaultRestart() error {
	cmd := exec.Command("systemctl", "restart", "kingmoat")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart kingmoat: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// handleConsolePortGet returns the console port this process is serving on
// and whether the port-change flow is available (EnvironmentFile wired).
func (s *Server) handleConsolePortGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"port":       s.opts.ConsolePort,
		"changeable": s.opts.ConsoleEnvPath != "",
	})
}

// handleConsolePortSet moves the management console to a new port. After all
// validations pass the EnvironmentFile is rewritten atomically and the
// service restart is scheduled (delayed so this response reaches the client
// first); the response is final even though the restart happens later.
func (s *Server) handleConsolePortSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	if s.opts.ConsoleEnvPath == "" {
		writeErr(w, http.StatusNotImplemented, simpleError("当前运行模式不支持在线修改管理端口（未接入 systemd EnvironmentFile 部署）"))
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
		fmt.Sprintf("console port change %d -> %d, service restart scheduled", s.opts.ConsolePort, req.Port))
	time.AfterFunc(delay, func() {
		if err := restart(); err != nil {
			// console.env is already written: a manual `systemctl restart
			// kingmoat` still applies the new port.
			slog.Error("console port change: service restart failed", "port", req.Port, "err", err)
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
