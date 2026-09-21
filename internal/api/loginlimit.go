// Login brute-force protection: a per-source-IP sliding window over failed
// authentication attempts. After maxLoginFailures failures inside
// loginWindow the source is locked out for the remainder of the window;
// a successful login clears the record. Basic-auth failures share the same
// counter so password stuffing cannot bypass the JSON login limiter.
package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// Defaults; the effective values come from the console security
	// settings (system settings → 安全设置 → 登录防爆破).
	loginWindow       = 15 * time.Minute
	maxLoginFailures  = 10
	loginRetryAfter   = int(loginWindow / time.Second)
	maxTrackedSources = 8192
)

type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}}
}

// sourceIP extracts the best-effort client identity for rate limiting.
func sourceIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

// locked reports whether the source is currently locked out. max and window
// come from the live console security settings.
func (l *loginLimiter) locked(r *http.Request, max int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(time.Now(), window)
	fs := l.failures[sourceIP(r)]
	return len(fs) >= max
}

// recordFailure notes a failed attempt from this source.
func (l *loginLimiter) recordFailure(r *http.Request, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneLocked(now, window)
	src := sourceIP(r)
	l.failures[src] = append(l.failures[src], now)
}

// recordSuccess clears the source's failure history.
func (l *loginLimiter) recordSuccess(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, sourceIP(r))
}

// pruneLocked drops expired entries and bounds memory under source
// spoofing; caller must hold the lock.
func (l *loginLimiter) pruneLocked(now time.Time, window time.Duration) {
	if len(l.failures) > maxTrackedSources {
		for k, fs := range l.failures {
			if len(fs) == 0 || now.Sub(fs[len(fs)-1]) > window {
				delete(l.failures, k)
			}
		}
	}
	for k, fs := range l.failures {
		kept := fs[:0]
		for _, ts := range fs {
			if now.Sub(ts) < window {
				kept = append(kept, ts)
			}
		}
		if len(kept) == 0 {
			delete(l.failures, k)
			continue
		}
		l.failures[k] = kept
	}
}
