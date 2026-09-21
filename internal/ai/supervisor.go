// Supervisor owns the live AI assistant instance and swaps it atomically
// when the AI configuration changes. The rebuild path (close old → build new →
// start retention) lives in exactly one place and is driven from
// configuration revisions (a past field omission caused nil-func panics).
package ai

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Supervisor serializes rebuilds and hands out the live service reference.
type Supervisor struct {
	// mu guards the fast fields (svc / kek) and is NEVER held across a
	// Close(): Analyzer.Stop waits for a running cron report (minutes in
	// the worst case), so blocking Ref()/KEK() on it would stall every AI
	// entry point during a rebuild.
	mu sync.Mutex
	// rebuildMu serializes Rebuild bodies (config revisions arrive from one
	// subscription loop, but nothing stops overlapping calls) without
	// touching the Ref()/KEK() path.
	rebuildMu sync.Mutex

	svc     *Service
	logger  *slog.Logger
	kekPath string
	kek     []byte
}

// NewSupervisor wires a supervisor; nil logger falls back to slog.Default.
func NewSupervisor(logger *slog.Logger) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Supervisor{logger: logger}
}

// SetKEKPath points the supervisor at the key-encryption key file used to
// decrypt the stored provider API key (api_key_cipher). The assembly must
// set it, otherwise the key
// endpoints report storage unavailable.
func (s *Supervisor) SetKEKPath(path string) {
	s.mu.Lock()
	s.kekPath = path
	s.mu.Unlock()
}

// KEK lazily loads (or creates) the key-encryption key, caching the result.
// Errors are never cached so a transient problem does not permanently
// disable key storage.
func (s *Supervisor) KEK() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kek != nil {
		return s.kek, nil
	}
	if s.kekPath == "" {
		return nil, fmt.Errorf("ai: kek path not configured")
	}
	kek, err := LoadOrCreateKEK(s.kekPath)
	if err != nil {
		return nil, err
	}
	s.kek = kek
	return s.kek, nil
}

// Ref returns the live service (nil = assistant disabled). Safe to call
// concurrently with Rebuild: an in-flight request keeps operating on the
// previous instance until it finishes, exactly like the old all-in-one
// aiHandle swap.
func (s *Supervisor) Ref() *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.svc
}

// ResolveSettings extracts the assistant settings for one active config
// revision. The published config's "ai" section wins; when the section is
// absent the settings file (path) is consulted (all-in-one shared config
// file). kekPath points at the key-encryption
// key file for the stored provider API key (loaded eagerly so Rebuild and
// the key endpoints share one instance; a failure keeps the assistant on
// env-only keys). Returns nil when the assistant stays disabled: no section
// anywhere, an unparsable section (logged), or the file has no ai block.
func ResolveSettings(cfgAI json.RawMessage, path, kekPath string, logger *slog.Logger) *Settings {
	loadKEK := func(st *Settings) {
		if kekPath == "" {
			return
		}
		kek, err := LoadOrCreateKEK(kekPath)
		if err != nil {
			logger.Warn("ai kek load failed, stored keys unavailable (env fallback only)", "err", err)
			return
		}
		st.KEK = kek
	}
	if len(cfgAI) > 0 {
		var st Settings
		if err := json.Unmarshal(cfgAI, &st); err != nil {
			logger.Warn("ai config invalid, assistant disabled", "err", err)
			return nil
		}
		st.ApplyDefaults()
		loadKEK(&st)
		return &st
	}
	loaded, err := LoadSettings(path)
	if err != nil {
		logger.Debug("ai file settings absent", "err", err)
		return nil
	}
	if loaded != nil {
		loadKEK(loaded)
	}
	return loaded
}

// Rebuild swaps the live service: builds the next instance FIRST and only
// then atomically swaps the pointer; the previous instance is closed OUTSIDE
// the mutex so Ref()/KEK() never block on a shutdown (close-old → build-new
// previously held the lock for the whole swap, and Analyzer.Stop waits for a
// running cron report). settings == nil or disabled turns the assistant off.
// A build failure keeps the previous instance alive (fail-open) and logs
// loudly — a broken AI config must not kill a working assistant; the next
// successful rebuild (or an explicit disable) replaces it. emailCfg is the
// active config's SMTP section (email report channel).
func (s *Supervisor) Rebuild(settings *Settings, sources *DataSources, dbPath string, emailCfg config.EmailSettings) {
	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()
	if settings == nil || !settings.Enabled {
		s.mu.Lock()
		old := s.svc
		s.svc = nil
		s.mu.Unlock()
		if old != nil {
			_ = old.Close()
		}
		s.logger.Debug("ai assistant disabled (no enabled ai config)")
		return
	}
	svc, err := NewService(settings, sources, dbPath, settings.KEK, s.logger, emailCfg)
	if err != nil {
		s.mu.Lock()
		old := s.svc
		s.mu.Unlock()
		if old != nil {
			s.logger.Warn("ai assistant rebuild failed, keeping the previous instance", "err", err)
		} else {
			s.logger.Warn("ai assistant rebuild failed, assistant disabled", "err", err)
		}
		return
	}
	s.mu.Lock()
	old := s.svc
	s.svc = svc
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	svc.StartRetention()
	s.logger.Info("ai assistant enabled", "model", svc.ModelName(), "key_source", svc.client.KeySource())
}

// Close stops the live service (process shutdown).
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc != nil {
		_ = s.svc.Close()
		s.svc = nil
	}
}
