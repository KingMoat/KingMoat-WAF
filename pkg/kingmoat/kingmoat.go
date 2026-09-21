// Package kingmoat is the SDK entry point for embedding the KingMoat
// detection pipeline in front of your own Go http.Handler. Daemon mode
// (site routing + reverse proxy) lives in cmd/kingmoat.
package kingmoat

import (
	"log/slog"
	"net/http"

	"github.com/kingmoat/kingmoat/internal/intercept"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Mode controls what happens on a deny verdict.
type Mode string

const (
	// ModeMonitor only records deny verdicts and forwards everything.
	// It is the SDK default so embedding can be enabled safely first.
	ModeMonitor Mode = "monitor"
	// ModeIntercept blocks requests with a deny verdict.
	ModeIntercept Mode = "intercept"
)

// Options configures an embedded engine.
type Options struct {
	Mode   Mode             // default ModeMonitor
	Logger *slog.Logger     // default slog.Default()
	Stages []pipeline.Stage // ordered protection stages
}

// Engine is the embeddable detection engine.
type Engine struct {
	pipe   *pipeline.Pipeline
	block  bool
	logger *slog.Logger
}

// New builds an embedded engine. Stages are the caller's responsibility;
// the daemon binary ships KingMoat's built-in stages.
func New(opts Options) *Engine {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	mode := opts.Mode
	if mode == "" {
		mode = ModeMonitor
	}
	return &Engine{
		pipe:   pipeline.New(opts.Stages...),
		block:  mode == ModeIntercept,
		logger: logger,
	}
}

// Handler wraps next so every request passes the pipeline first.
func (e *Engine) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &pipeline.RequestContext{Request: r}
		v := e.pipe.Inspect(r.Context(), rc)
		if v.Action != pipeline.ActionAllow {
			if e.block {
				e.logger.Warn("request blocked",
					"action", v.Action.String(), "rule", v.Rule, "reason", v.Reason,
					"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				intercept.Deny(w, r, v, "")
				return
			}
			e.logger.Info("monitor mode: deny verdict recorded, forwarding",
				"action", v.Action.String(), "rule", v.Rule, "reason", v.Reason,
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		}
		next.ServeHTTP(w, r)
	})
}
