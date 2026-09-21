// Package penalty implements the attack-penalty engine: blocked/challenged
// audit events from one client IP are counted inside a fixed window; crossing
// the configured threshold temporarily bans (deny) or strictly throttles the
// IP. State is in-memory and resets on process restart or config publish
// (documented behaviour). The manager is wired by registering a write hook
// on the audit store, so counting adds no extra scan pass.
package penalty

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

type window struct {
	start time.Time
	count int
}

type penaltyState struct {
	until time.Time
	mode  string // "deny" | "throttle"
}

// Manager keeps per-IP counters and active penalties. Safe for concurrent use.
type Manager struct {
	mu     sync.Mutex
	logger *slog.Logger
	pol    config.PenaltySettings
	counts map[string]*window
	bans   map[string]penaltyState
	now    func() time.Time
}

// New creates the manager from the policy penalty settings (defaults applied).
func New(pol config.PenaltySettings, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		logger: logger,
		pol:    pol,
		counts: make(map[string]*window),
		bans:   make(map[string]penaltyState),
		now:    time.Now,
	}
}

// SetPolicy hot-swaps the settings.
func (m *Manager) SetPolicy(pol config.PenaltySettings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pol = pol
}

// Observe records one audit event; blocked/challenged events count toward
// the threshold. Called synchronously from the audit write hook.
func (m *Manager) Observe(ev logstore.Event) {
	if !m.pol.Enabled {
		return
	}
	if ev.Action != "blocked" && ev.Action != "challenged" {
		return
	}
	ip := ev.ClientIP
	if ip == "" {
		return
	}
	now := m.now()
	win := m.pol.WindowSecOrDefault()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(now)
	w := m.counts[ip]
	if w == nil || now.Sub(w.start) >= time.Duration(win)*time.Second {
		w = &window{start: now}
		m.counts[ip] = w
	}
	w.count++
	if w.count >= m.pol.ThresholdOrDefault() {
		mode := m.pol.ActionOrDefault()
		m.bans[ip] = penaltyState{
			until: now.Add(time.Duration(m.pol.BanSecOrDefault()) * time.Second),
			mode:  mode,
		}
		delete(m.counts, ip)
		m.logger.Warn("penalty: threshold reached, applying penalty",
			"ip", ip, "mode", mode, "seconds", m.pol.BanSecOrDefault(),
			"site", ev.Site, "trace", ev.TraceID)
	}
}

// Check evaluates the current penalty state for the client IP. In deny mode
// every request during the ban is blocked; in throttle mode up to
// ThrottlePerMin requests per minute are allowed and the rest are blocked
// with 429.
func (m *Manager) Check(ip string) (blocked bool, reason string) {
	if !m.pol.Enabled {
		return false, ""
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.bans[ip]
	if !ok {
		return false, ""
	}
	if now.After(st.until) {
		delete(m.bans, ip)
		return false, ""
	}
	if st.mode == "throttle" {
		w := m.counts[ip]
		if w == nil || now.Sub(w.start) >= time.Minute {
			w = &window{start: now}
			m.counts[ip] = w
		}
		w.count++
		if w.count > m.pol.ThrottlePerMinOrDefault() {
			return true, fmt.Sprintf("attack penalty (throttle): exceeded %d requests/min during the penalty window",
				m.pol.ThrottlePerMinOrDefault())
		}
		return false, ""
	}
	remaining := int(st.until.Sub(now).Seconds() + 0.5)
	return true, fmt.Sprintf("attack penalty: client IP temporarily banned for %d more seconds (repeated attacks)", remaining)
}

// gcLocked bounds the maps: expired bans and stale windows are dropped once
// the tracked set grows past the cap. Called with the lock held.
func (m *Manager) gcLocked(now time.Time) {
	if len(m.bans)+len(m.counts) < 4096 {
		return
	}
	for ip, st := range m.bans {
		if now.After(st.until) {
			delete(m.bans, ip)
		}
	}
	for ip, w := range m.counts {
		if now.Sub(w.start) >= 24*time.Hour {
			delete(m.counts, ip)
		}
	}
}