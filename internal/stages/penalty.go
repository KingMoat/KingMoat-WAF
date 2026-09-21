// Penalty stage: rejects client IPs under an active attack penalty. Runs
// right after ACL so whitelist-trusted clients (already allowed there) are
// never affected by penalty decisions.
package stages

import (
	"context"
	"log/slog"

	"github.com/kingmoat/kingmoat/internal/penalty"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Penalty is the attack-penalty enforcement stage.
type Penalty struct {
	mgr    *penalty.Manager
	logger *slog.Logger
}

// NewPenalty wires the stage to the penalty manager (nil manager = no-op).
func NewPenalty(mgr *penalty.Manager, logger *slog.Logger) *Penalty {
	if logger == nil {
		logger = slog.Default()
	}
	return &Penalty{mgr: mgr, logger: logger}
}

// Name implements pipeline.Stage.
func (p *Penalty) Name() string { return "penalty" }

// Inspect implements pipeline.Stage.
func (p *Penalty) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if p.mgr == nil {
		return pipeline.Allow()
	}
	ip := clientIP(rc.Request)
	if ip == nil {
		return pipeline.Allow()
	}
	blocked, reason := p.mgr.Check(ip.String())
	if !blocked {
		return pipeline.Allow()
	}
	p.logger.Warn("penalty: penalized client blocked",
		"ip", ip, "site", rc.Site.Domain, "trace", rc.Values["trace_id"], "reason", reason)
	return pipeline.Deny("penalty/engine", reason)
}