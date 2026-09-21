package apiasset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Risk kinds exposed by the observe-only engine (R1–R7 from the design).
const (
	RiskSensitiveExposure = "sensitive_exposure" // R1
	RiskUnauthorized      = "unauthorized"       // R2
	RiskBruteForce        = "bruteforce"         // R3 (realtime)
	RiskShadowAPI         = "shadow_api"         // R4 (admin/export heuristics)
	RiskZombieAPI         = "zombie_api"         // R5
	RiskAdminExposure     = "admin_exposure"     // R6
	RiskPlaintextSecret   = "plaintext_secret"   // R7
)

// Risk engine thresholds (v1 heuristics, all observe-only).
const (
	r1MinHits        = 10
	r2MinAnonOK      = 20
	r2MinAuthedRatio = 0.5
	r6MinAdminPublic = 10
	riskBatchLimit   = 500
)

// Engine runs the periodic risk analysis over the asset store and collects
// realtime signals (R3) from the collector. It never mutates proxy state.
type Engine struct {
	store   *Store
	cfg     *RisksConfig
	notify  Notifier
	logger  *slog.Logger
	nowFunc func() time.Time
}

// RisksConfig is the runtime view of config.RisksSettings with defaults
// applied.
type RisksConfig struct {
	ZombieDays int
}

// Notifier delivers new findings (generic webhook).
type Notifier interface {
	NotifyRisk(r *Risk) error
}

// NewEngine builds the risk engine.
func NewEngine(store *Store, cfg *RisksConfig, notify Notifier, logger *slog.Logger) *Engine {
	if cfg == nil {
		cfg = &RisksConfig{}
	}
	if cfg.ZombieDays <= 0 {
		cfg.ZombieDays = 30
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{store: store, cfg: cfg, notify: notify, logger: logger, nowFunc: time.Now}
}

// riskID derives a stable identifier: kind + site + subject.
func riskID(kind, site, subject string) string {
	h := sha256.Sum256([]byte(kind + "|" + site + "|" + subject))
	return kind[:3] + "-" + hex.EncodeToString(h[:6])
}

// RunScan executes one full analysis pass and returns the number of new
// findings. Every rule marks its output with "建议人工复核" — findings are
// hints, not verdicts.
func (e *Engine) RunScan() (int, error) {
	newCount := 0

	// R1 — sensitive data exposure from respfilter hit statistics.
	if hits, err := e.store.HotRespFilterHits(r1MinHits, riskBatchLimit); err == nil {
		for i := range hits {
			r := &hits[i]
			r.ID = riskID(RiskSensitiveExposure, r.Site, r.AssetRef+"|"+r.Evidence["pattern"].(string))
			r.Message += "（建议人工复核）"
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
				e.notifyRisk(r)
			}
		}
	} else {
		e.logger.Error("risk: R1 scan failed", "err", err)
	}

	// R2 — unauthorized access hints: credential-heavy APIs hammered
	// anonymously with success statuses.
	if assets, err := e.store.queryAssetsPaged("api_assets a",
		"a.ignored = 0 AND a.authed_ratio >= ? AND a.anon_ok >= ?",
		[]any{r2MinAuthedRatio, r2MinAnonOK}, 0, riskBatchLimit); err == nil {
		for i := range assets {
			a := &assets[i]
			r := &Risk{
				Kind: RiskUnauthorized, Level: "medium", Site: a.Site,
				AssetRef: a.Method + " " + a.NormPath,
				Message:  "带凭证比例较高的 API 被大量无凭证调用且返回成功（建议人工复核）",
				Evidence: map[string]any{
					"authed_ratio": a.AuthedRatio, "anon_ok": a.AnonOK,
					"hits": a.Hits, "status_dist": a.StatusDist,
				},
			}
			r.ID = riskID(RiskUnauthorized, a.Site, a.Method+"|"+a.NormPath)
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
				e.notifyRisk(r)
			}
		}
	} else {
		e.logger.Error("risk: R2 scan failed", "err", err)
	}

	// R4 — shadow API hint: newly seen admin/export-class endpoints
	// (OpenAPI cross-check lands in a later release).
	if assets, err := e.store.RecentAdminExports(e.nowFunc().Add(-24*time.Hour), riskBatchLimit); err == nil {
		for i := range assets {
			a := &assets[i]
			r := &Risk{
				Kind: RiskShadowAPI, Level: "medium", Site: a.Site,
				AssetRef: a.Method + " " + a.NormPath,
				Message:  "近 24 小时新发现的管理面/导出类 API，请确认是否已声明（建议人工复核）",
				Evidence: map[string]any{"tags": a.Tags, "first_seen": a.FirstSeen, "hits": a.Hits},
			}
			r.ID = riskID(RiskShadowAPI, a.Site, a.Method+"|"+a.NormPath)
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
				e.notifyRisk(r)
			}
		}
	} else {
		e.logger.Error("risk: R4 scan failed", "err", err)
	}

	// R5 — zombie APIs.
	if assets, err := e.store.StaleAssets(e.cfg.ZombieDays, riskBatchLimit); err == nil {
		for i := range assets {
			a := &assets[i]
			r := &Risk{
				Kind: RiskZombieAPI, Level: "low", Site: a.Site,
				AssetRef: a.Method + " " + a.NormPath,
				Message:  fmt.Sprintf("API 已超过 %d 天无流量，建议确认是否下线（建议人工复核）", e.cfg.ZombieDays),
				Evidence: map[string]any{"last_seen": a.LastSeen, "hits": a.Hits},
			}
			r.ID = riskID(RiskZombieAPI, a.Site, a.Method+"|"+a.NormPath)
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
			}
		}
	} else {
		e.logger.Error("risk: R5 scan failed", "err", err)
	}

	// R6 — admin surface exposed to public sources.
	if assets, err := e.store.AdminAssets(riskBatchLimit); err == nil {
		for i := range assets {
			a := &assets[i]
			if a.AdminPublic < r6MinAdminPublic {
				continue
			}
			r := &Risk{
				Kind: RiskAdminExposure, Level: "high", Site: a.Site,
				AssetRef: a.Method + " " + a.NormPath,
				Message:  "管理面类 API 被公网来源高频访问（建议人工复核）",
				Evidence: map[string]any{"admin_public": a.AdminPublic, "public_hits": a.PublicHits},
			}
			r.ID = riskID(RiskAdminExposure, a.Site, a.Method+"|"+a.NormPath)
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
				e.notifyRisk(r)
			}
		}
	} else {
		e.logger.Error("risk: R6 scan failed", "err", err)
	}

	// R7 — plaintext sensitive parameters on non-TLS sites.
	if assets, err := e.store.queryAssetsPaged("api_assets a",
		"a.ignored = 0 AND a.sensitive_json != '{}'", nil, 0, riskBatchLimit); err == nil {
		for i := range assets {
			a := &assets[i]
			if len(a.Sensitive) == 0 {
				continue
			}
			r := &Risk{
				Kind: RiskPlaintextSecret, Level: "high", Site: a.Site,
				AssetRef: a.Method + " " + a.NormPath,
				Message:  "HTTP 明文传输敏感参数名（password/token 等），建议强制 TLS（建议人工复核）",
				Evidence: map[string]any{"params": a.Sensitive},
			}
			r.ID = riskID(RiskPlaintextSecret, a.Site, a.Method+"|"+a.NormPath)
			if created, err := e.store.UpsertRisk(r); err == nil && created {
				newCount++
				e.notifyRisk(r)
			}
		}
	} else {
		e.logger.Error("risk: R7 scan failed", "err", err)
	}

	return newCount, nil
}

// OnBruteForce handles the collector's realtime R3 signal.
func (e *Engine) OnBruteForce(site, path, ip string, count int) {
	r := &Risk{
		Kind: RiskBruteForce, Level: "high", Site: site,
		AssetRef: "POST " + path,
		Message:  "登录类 API 同一来源短窗口内高频失败，疑似爆破（建议人工复核）",
		Evidence: map[string]any{"ip": ip, "threshold": count, "window_sec": 300},
	}
	r.ID = riskID(RiskBruteForce, site, path+"|"+ip)
	if created, err := e.store.UpsertRisk(r); err == nil {
		if created {
			e.notifyRisk(r)
		}
	} else {
		e.logger.Error("risk: R3 upsert failed", "err", err)
	}
}

func (e *Engine) notifyRisk(r *Risk) {
	if e.notify == nil {
		return
	}
	if err := e.notify.NotifyRisk(r); err != nil {
		e.logger.Warn("risk: notify failed", "kind", r.Kind, "err", err)
	}
}

// WebhookNotifier posts new findings to a generic HTTP endpoint.
type WebhookNotifier struct {
	URL    string
	Client *http.Client
	logger *slog.Logger
}

// NewWebhookNotifier builds the notifier; empty URL disables delivery.
func NewWebhookNotifier(url string, logger *slog.Logger) *WebhookNotifier {
	return &WebhookNotifier{URL: url, Client: &http.Client{Timeout: 5 * time.Second}, logger: logger}
}

// NotifyRisk POSTs the finding JSON. Delivery is best-effort: errors are
// logged, never propagated to the risk pipeline.
func (w *WebhookNotifier) NotifyRisk(r *Risk) error {
	if w == nil || w.URL == "" {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"event": "kingmoat_risk",
		"risk":  r,
	})
	if err != nil {
		return err
	}
	resp, err := w.Client.Post(w.URL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
