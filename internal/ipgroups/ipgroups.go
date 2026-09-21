// Package ipgroups manages subscribed IP lists (URL or local file) that ACL
// entries reference as "group:<name>". Lists refresh on a fixed interval;
// the last successful snapshot is kept on refresh failures.
package ipgroups

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Provider resolves a group name to its current IP nets.
type Provider interface {
	Lookup(name string) []*net.IPNet
}

// Manager owns all subscribed groups (implements Provider and io.Closer).
type Manager struct {
	mu     sync.RWMutex
	groups map[string][]*net.IPNet
	cfgs   map[string]config.IPGroupSettings
	errs   map[string]string
	stop   chan struct{}
	logger *slog.Logger
}

// NewManager creates the manager and performs an initial synchronous fetch
// for every group (failures leave the group empty and are logged).
func NewManager(cfg *config.Config, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Manager{groups: map[string][]*net.IPNet{}, cfgs: map[string]config.IPGroupSettings{}, errs: map[string]string{}, stop: make(chan struct{}), logger: logger}
	for i := range cfg.IPGroups {
		g := cfg.IPGroups[i]
		m.cfgs[g.Name] = g
		if len(g.Members) > 0 && g.URL == "" && g.File == "" {
			// Manual group: load the inline member list once, no refresh loop.
			nets, perr := ParseList([]byte(strings.Join(g.Members, "\n")))
			if perr != nil {
				m.mu.Lock()
				m.errs[g.Name] = perr.Error()
				m.mu.Unlock()
				m.logger.Warn("ipgroup manual list invalid", "group", g.Name, "err", perr)
				continue
			}
			m.mu.Lock()
			m.groups[g.Name] = nets
			m.mu.Unlock()
			m.logger.Info("ipgroup manual loaded", "group", g.Name, "entries", len(nets))
			continue
		}
		m.refresh(&g)
		if g.URL != "" {
			interval := time.Duration(g.IntervalMin) * time.Minute
			if interval <= 0 {
				interval = 60 * time.Minute
			}
			go m.refreshLoop(&g, interval)
		}
	}
	return m
}

// Lookup implements Provider.
func (m *Manager) Lookup(name string) []*net.IPNet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.groups[name]
}

// Describe returns the subscription metadata and a preview of the entries
// for the console IP-group management UI.
func (m *Manager) Describe() []map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]map[string]any, 0, len(m.cfgs))
	for name, g := range m.cfgs {
		nets := m.groups[name]
		sample := make([]string, 0, len(nets))
		for i, n := range nets {
			if i >= 20 {
				break
			}
			sample = append(sample, n.String())
		}
		item := map[string]any{
			"name": name, "url": g.URL, "file": g.File,
			"interval_min": g.IntervalMin, "entries": len(nets), "sample": sample,
		}
		if len(g.Members) > 0 {
			item["type"] = "manual"
			item["members"] = g.Members
		} else {
			item["type"] = "subscription"
		}
		if e, ok := m.errs[name]; ok {
			item["last_error"] = e
		}
		out = append(out, item)
	}
	return out
}

// RefreshNow re-fetches one group synchronously; returns whether the group
// exists.
func (m *Manager) RefreshNow(name string) bool {
	m.mu.RLock()
	g, ok := m.cfgs[name]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	m.refresh(&g)
	return true
}

// Close stops all refresh loops (implements io.Closer).
func (m *Manager) Close() error {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	return nil
}

func (m *Manager) refreshLoop(g *config.IPGroupSettings, interval time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			m.logger.Error("ipgroup refresh panic recovered", "group", g.Name, "panic", r)
		}
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.refresh(g)
		}
	}
}

func (m *Manager) refresh(g *config.IPGroupSettings) {
	var data []byte
	var err error
	switch {
	case g.File != "":
		data, err = os.ReadFile(g.File)
		if err != nil {
			m.logger.Warn("ipgroup refresh failed", "group", g.Name, "err", err)
			return
		}
	case g.URL != "":
		client := &http.Client{Timeout: 15 * time.Second}
		resp, rerr := client.Get(g.URL)
		if rerr != nil {
			m.logger.Warn("ipgroup refresh failed", "group", g.Name, "err", rerr)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			m.logger.Warn("ipgroup refresh failed", "group", g.Name, "status", resp.StatusCode)
			return
		}
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		data = buf.Bytes()
	default:
		return
	}
	if err != nil {
		m.logger.Warn("ipgroup refresh failed", "group", g.Name, "err", err)
		m.mu.Lock()
		m.errs[g.Name] = err.Error()
		m.mu.Unlock()
		return
	}
	nets, perr := ParseList(data)
	if perr != nil {
		m.logger.Warn("ipgroup refresh: bad list", "group", g.Name, "err", perr)
		m.mu.Lock()
		m.errs[g.Name] = perr.Error()
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	m.groups[g.Name] = nets
	delete(m.errs, g.Name)
	m.mu.Unlock()
	m.logger.Info("ipgroup refreshed", "group", g.Name, "entries", len(nets))
}

// ParseList parses one IP/CIDR per line; comments (#) and blank lines are
// skipped. Malformed lines are an error so bad subscriptions are visible.
func ParseList(data []byte) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if i := strings.Index(s, "#"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		ipnet, err := config.ParseIPNet(s)
		if err != nil {
			return nil, fmt.Errorf("line %d (%q): %w", line, s, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, sc.Err()
}
