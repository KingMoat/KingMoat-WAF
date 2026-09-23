// Package configcenter implements the M2 versioned configuration center:
// publish → validate → append revision → in-process fan-out. Data planes
// observe changes either in-process (all-in-one) or via the API poll
// endpoint (remote mode). Validation failure never takes effect
// (docs/ARCHITECTURE.md §4.3).
package configcenter

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/store"
)

// Center holds the current configuration and its revision history.
type Center struct {
	store  *store.Store
	dbPath string
	logger *slog.Logger

	mu   sync.RWMutex
	rev  int64
	cfg  *config.Config
	subs map[chan int64]struct{}

	// lastApply carries the data-plane outcome of the most recent revision
	// (written by the hot-reload consumer via SetApplyStatus).
	lastApply atomic.Value
}

// DBPath returns the SQLite database file path (for sibling data dirs).
func (c *Center) DBPath() string { return c.dbPath }

// Open initializes the center from SQLite. When the store is empty and a
// seed config is provided, the seed is imported as revision 1.
func Open(dbPath string, seed *config.Config, logger *slog.Logger) (*Center, error) {
	if logger == nil {
		logger = slog.Default()
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	c := &Center{store: st, dbPath: dbPath, logger: logger, subs: make(map[chan int64]struct{})}

	rev, raw, err := st.CurrentRevision()
	if err == nil {
		var cfg config.Config
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			st.Close()
			return nil, fmt.Errorf("configcenter: decode revision %d: %w", rev, err)
		}
		if err := cfg.Validate(); err != nil {
			st.Close()
			return nil, fmt.Errorf("configcenter: stored revision %d invalid: %w", rev, err)
		}
		c.rev, c.cfg = rev, &cfg
		return c, nil
	}
	if seed == nil {
		st.Close()
		return nil, fmt.Errorf("configcenter: %w", err)
	}
	if err := seed.Validate(); err != nil {
		st.Close()
		return nil, fmt.Errorf("configcenter: seed config invalid: %w", err)
	}
	b, _ := json.Marshal(seed)
	rev, err = st.AppendRevision(string(b), "bootstrap", "initial import")
	if err != nil {
		st.Close()
		return nil, err
	}
	c.rev, c.cfg = rev, seed
	logger.Info("configcenter: seed config imported", "revision", rev, "sites", len(seed.Sites))
	return c, nil
}

// ErrNoChanges is returned by Publish when the submitted configuration is
// identical (after normalization) to the active revision; no new revision is
// created and the active revision is returned untouched. Rollback bypasses
// this check on purpose: re-publishing a historical revision always creates
// an explicit point-in-time marker.
var ErrNoChanges = errors.New("configcenter: configuration unchanged")

// Current returns the active revision id and configuration.
func (c *Center) Current() (int64, *config.Config) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rev, c.cfg
}

// Publish validates and persists a new configuration revision, then notifies
// all in-process subscribers. When the submitted config is identical to the
// active one, ErrNoChanges is returned and no revision is appended. On any
// error the current config is untouched.
func (c *Center) Publish(next *config.Config, author, note string) (int64, error) {
	return c.publishInternal(next, author, note, false)
}

func (c *Center) publishInternal(next *config.Config, author, note string, allowNoChanges bool) (int64, error) {
	if next == nil {
		return 0, fmt.Errorf("configcenter: nil config")
	}
	if err := next.Validate(); err != nil {
		return 0, err
	}
	b, err := json.Marshal(next)
	if err != nil {
		return 0, fmt.Errorf("configcenter: encode config: %w", err)
	}
	if !allowNoChanges {
		// Compare against the ACTIVE REVISION'S STORED payload (the source of
		// truth) after normalizing both sides: empty objects/arrays are
		// stripped recursively, because console forms round-trip absent
		// sections as empty containers (e.g. an edited site carries
		// "security":{}) — a difference that changes no behavior must not
		// create a new revision. Comparing the live in-memory object instead
		// would misreport "no changes" when callers mutate the shared config
		// in place before publishing (e.g. policy exception handlers).
		curRev, _ := c.Current()
		if curRev > 0 {
			if raw, gerr := c.store.GetRevision(curRev); gerr == nil {
				var curAny, nextAny any
				if uerr := json.Unmarshal([]byte(raw), &curAny); uerr == nil {
					if nerr := json.Unmarshal(b, &nextAny); nerr == nil {
						cb, merr := json.Marshal(normalizeEmptyContainers(curAny))
						nb, nerr := json.Marshal(normalizeEmptyContainers(nextAny))
						if merr == nil && nerr == nil && bytes.Equal(cb, nb) {
							return curRev, ErrNoChanges
						}
					}
				}
			}
		}
	}
	rev, err := c.store.AppendRevision(string(b), author, note)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.rev = rev
	c.cfg = next
	for ch := range c.subs {
		select {
		case ch <- rev:
		default: // subscriber slow: it will pick the revision up on next read
		}
	}
	c.mu.Unlock()

	c.logger.Info("configcenter: revision published",
		"revision", rev, "sites", len(next.Sites), "author", author, "note", note)
	return rev, nil
}

// PublishSite validates and publishes a single-site change: the site is
// merged into the current configuration (replaced when one of its domains
// already exists, appended otherwise) and the whole document is validated
// before a new revision is stored.
//
// Because the live configuration is always valid, a validation failure can
// only come from the submitted site — other sites' changes are never blocked
// by it, which is the per-site isolation the API surface promises.
func (c *Center) PublishSite(domain string, site config.Site, author, note string) (int64, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return 0, fmt.Errorf("configcenter: domain is required")
	}
	_, cur := c.Current()
	if cur == nil {
		return 0, fmt.Errorf("configcenter: no active configuration")
	}
	next := *cur // shallow copy; Sites slice is rebuilt below
	next.Sites = make([]config.Site, len(cur.Sites))
	copy(next.Sites, cur.Sites)

	match := -1
	for i := range next.Sites {
		for _, d := range next.Sites[i].Domains {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				match = i
				break
			}
		}
		if match >= 0 {
			break
		}
	}
	if match >= 0 {
		next.Sites[match] = site
	} else {
		next.Sites = append(next.Sites, site)
	}
	if note == "" {
		note = "site publish: " + domain
	}
	return c.Publish(&next, author, note)
}

// Subscribe returns a channel receiving new revision ids, plus a cancel func.
func (c *Center) Subscribe() (<-chan int64, func()) {
	ch := make(chan int64, 8)
	c.mu.Lock()
	c.subs[ch] = struct{}{}
	c.mu.Unlock()
	cancel := func() {
		c.mu.Lock()
		delete(c.subs, ch)
		c.mu.Unlock()
	}
	return ch, cancel
}

// Rollback re-publishes the payload of an existing revision as a new revision
// (history is append-only; rollback never rewrites it).
func (c *Center) Rollback(id int64, author string) (int64, error) {
	raw, err := c.store.GetRevision(id)
	if err != nil {
		return 0, err
	}
	var cfg config.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return 0, fmt.Errorf("configcenter: decode revision %d: %w", id, err)
	}
	return c.publishInternal(&cfg, author, fmt.Sprintf("rollback to revision %d", id), true)
}

// ApplyStatus reports the data-plane outcome of one published revision.
type ApplyStatus struct {
	Revision int64  `json:"revision"`
	Status   string `json:"status"` // "applied" | "failed" | "pending"
	Error    string `json:"error,omitempty"`
}

// SetApplyStatus records the data-plane apply outcome for a revision; called
// by the hot-reload consumer right after the plane rebuild returns.
func (c *Center) SetApplyStatus(rev int64, applyErr error) {
	st := ApplyStatus{Revision: rev, Status: "applied"}
	if applyErr != nil {
		st.Status = "failed"
		st.Error = applyErr.Error()
	}
	c.lastApply.Store(st)
}

// ApplyStatus returns the most recent data-plane apply outcome (zero value =
// no consumer reported yet).
func (c *Center) ApplyStatus() ApplyStatus {
	if v, ok := c.lastApply.Load().(ApplyStatus); ok {
		return v
	}
	return ApplyStatus{}
}

// WaitForApply blocks until a consumer reports the apply outcome for rev, or
// the timeout elapses ("pending"). Returns immediately when there are no
// in-process subscribers (remote mode, API-level tests). A newer revision's
// outcome already stored is treated as a completed apply of this one.
func (c *Center) WaitForApply(rev int64, timeout time.Duration) ApplyStatus {
	c.mu.RLock()
	n := len(c.subs)
	c.mu.RUnlock()
	if n == 0 {
		return ApplyStatus{Revision: rev, Status: "pending"}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st := c.ApplyStatus(); st.Revision >= rev {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ApplyStatus{Revision: rev, Status: "pending"}
}

// Store exposes the underlying store (read-only usage by the API layer).
func (c *Center) Store() *store.Store { return c.store }

// Close closes the backing store.
func (c *Center) Close() error { return c.store.Close() }

// normalizeEmptyContainers returns a copy of v with empty maps and empty
// slices removed recursively, so "absent section" and "present but empty
// section" compare equal (they are behaviorally identical for the WAF).
func normalizeEmptyContainers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nv := normalizeEmptyContainers(val)
			if isEmptyContainer(nv) {
				continue
			}
			out[k] = nv
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, normalizeEmptyContainers(val))
		}
		return out
	default:
		return v
	}
}

// isEmptyContainer reports whether v is an empty map or an empty slice.
func isEmptyContainer(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}
