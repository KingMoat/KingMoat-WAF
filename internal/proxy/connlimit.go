package proxy

import (
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Shared HTTP server tuning constants (were in the removed per-site listener
// manager; kept for the data-plane listeners and tests).
const (
	tenSec     = 10 * time.Second
	idleTwoMin = 120 * time.Second
	oneMB      = 1 << 20
)

// connLimitPerListenerEnv caps concurrent connections per listener. 0 or a
// negative value disables the cap (default: unlimited, bound by fds only).
const connLimitPerListenerEnv = "KINGMOAT_MAX_CONNS_PER_LISTENER"

func connLimitPerListener() int {
	raw := os.Getenv(connLimitPerListenerEnv)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// NewLimitedListener wraps l with the per-listener connection cap configured
// via KINGMOAT_MAX_CONNS_PER_LISTENER (0 or unset = unlimited).
func NewLimitedListener(l net.Listener) net.Listener {
	return newLimitedListener(l, connLimitPerListener())
}

// limitedListener caps concurrent accepted connections. When the cap is
// reached, new connections are accepted and immediately closed (fast reset
// for the client) instead of piling up in the accept queue — under
// saturation a clean refusal beats a long backlog that hides the problem.
type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitedListener(l net.Listener, maxConns int) net.Listener {
	if maxConns <= 0 {
		return l
	}
	return &limitedListener{Listener: l, sem: make(chan struct{}, maxConns)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	select {
	case l.sem <- struct{}{}:
		return &countingConn{Conn: c, release: func() { <-l.sem }}, nil
	default:
		// At capacity: close immediately so the client sees a reset and a
		// load balancer can retry another node.
		_ = c.Close()
		return nil, errAtCapacity
	}
}

// errAtCapacity is returned by Accept when the connection cap is reached.
// It implements net.Error with Temporary()=true so http.Server retries the
// accept loop (5ms pause) instead of shutting the listener down.
var errAtCapacity = &atCapacityError{}

type atCapacityError struct{}

func (e *atCapacityError) Error() string   { return "proxy: connection limit reached" }
func (e *atCapacityError) Timeout() bool   { return false }
func (e *atCapacityError) Temporary() bool { return true }

type countingConn struct {
	net.Conn
	release func()
	closed  atomic.Bool
}

func (c *countingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}
