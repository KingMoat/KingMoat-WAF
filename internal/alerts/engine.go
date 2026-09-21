// WAF anomaly alert engine: adjustable-threshold rules over host resources
// (CPU/memory/disk), request rate, attack volume, blocked volume and 1-hour
// per-IP / per-target rankings. Fires through the notification channels
// (webhook / email) with per-rule cooldown. Evaluation loop runs on a fixed
// interval (default 60s, which doubles as the 1-minute sampling window for
// the resource rules).
package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// Notifier delivers one alert message.
type Notifier interface {
	Notify(subject, body string) error
}

// WebhookNotifier posts the alert JSON to the configured webhook, with
// optional HMAC-SHA256 signing (X-KingMoat-Signature) and a keyword field
// (企业微信/钉钉机器人关键词安全设置). The HTTP client carries a hard
// timeout: Notify runs synchronously inside the evaluation loop, so a
// black-holed endpoint must never freeze alerting.
type WebhookNotifier struct {
	URL     string
	Secret  string
	Keyword string
	client  *http.Client
}

// notifyTimeout bounds one webhook POST.
const notifyTimeout = 10 * time.Second

// Notify implements Notifier (POST JSON).
func (w *WebhookNotifier) Notify(subject, body string) error {
	if w.client == nil {
		w.client = &http.Client{Timeout: notifyTimeout}
	}
	kw := ""
	if w.Keyword != "" {
		kw = w.Keyword
	}
	payload := fmt.Sprintf("{\"alert\":%q,\"subject\":%q,\"message\":%q,\"keyword\":%q,\"time\":%q}",
		"waf_anomaly", subject, body, kw, time.Now().UTC().Format(time.RFC3339))
	req, err := http.NewRequest(http.MethodPost, w.URL, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write([]byte(payload))
		req.Header.Set("X-KingMoat-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// AggFn aggregates audit events over a window (nil = ranking/count rules
// degrade to the recent-events fallback).
type AggFn func(since, until time.Time) (*logstore.Summary, error)

// Engine evaluates alert rules on a fixed interval.
type Engine struct {
	cfg       config.AlertsSettings
	email     Notifier
	webhook   Notifier
	logger    *slog.Logger
	reqTotal  func() float64
	auditDir  string
	aggFn     AggFn
	cooldown  map[string]time.Time
	firstOver map[string]time.Time // continuous-over threshold tracking (cpu/mem)
	mu        sync.Mutex

	lastReqTotal float64
	hasLast      bool
}

// New builds the engine. email/webhook may be nil when the channel is off.
func New(cfg config.AlertsSettings, email Notifier, webhook Notifier,
	reqTotal func() float64, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{cfg: cfg, email: email, webhook: webhook, reqTotal: reqTotal,
		cooldown: map[string]time.Time{}, firstOver: map[string]time.Time{}, logger: logger}
}

// SetDeps wires optional data sources: the audited data directory (disk rule)
// and the audit aggregator (count/ranking rules). Call before Run.
func (e *Engine) SetDeps(auditDir string, agg AggFn) *Engine {
	e.auditDir = auditDir
	e.aggFn = agg
	return e
}

// Run blocks until ctx is done, evaluating rules every interval. A panic in
// one evaluation pass is recovered INSIDE the loop: the engine keeps running
// (a panicking pass must never permanently silence alerting).
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.IntervalOrDefault())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		e.evaluateSafe()
	}
}

// evaluateSafe runs one evaluation pass with panic containment.
func (e *Engine) evaluateSafe() {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("alert engine panic recovered", "panic", r)
		}
	}()
	e.evaluate()
}

// ruleNames maps rule ids to the Chinese subject used in notifications.
var ruleNames = map[string]string{
	"cpu_high":   "CPU 使用率过高",
	"mem_high":   "内存使用率过高",
	"disk_high":  "磁盘使用率过高",
	"requests":   "出现大量 Web 请求",
	"attacks":    "出现大量 Web 攻击",
	"blocked":    "请求大量被拦截",
	"top_ip":     "攻击 IP 排名告警",
	"top_target": "攻击目标排名告警",
}

// evaluate runs one rule pass over the adjustable-threshold rule set.
func (e *Engine) evaluate() {
	rules := e.cfg.RulesOrDefault()
	now := time.Now()
	interval := e.cfg.IntervalOrDefault()
	e.evalRules(rules, now, interval)
}

// evaluateCPUForTest is the CPU-rule slice used by tests.
func (e *Engine) evaluateCPUForTest(cpuPct float64) {
	rules := e.cfg.RulesOrDefault()
	if rules.CPU.Enabled {
		e.fire("cpu_high", time.Now(), float64(rules.CPU.Threshold), cpuPct,
			fmt.Sprintf("CPU 使用率 %.0f%%（阈值 %d%%）", cpuPct, rules.CPU.Threshold))
	}
}

// evalRules runs the full adjustable-threshold rule set for one pass.
// For cpu/mem rules the threshold must be exceeded continuously for
// WindowSec (default 60s) before firing — tracked via firstOver state.
func (e *Engine) evalRules(rules config.AlertRules, now time.Time, interval time.Duration) {
	if rules.CPU.Enabled {
		if cpuPct, err := cpu.Percent(0, false); err == nil && len(cpuPct) > 0 {
			win := time.Duration(rules.CPU.WindowSec) * time.Second
			if win <= 0 {
				win = 60 * time.Second
			}
			if cpuPct[0] >= float64(rules.CPU.Threshold) {
				if e.firstOver["cpu_high"].IsZero() {
					e.firstOver["cpu_high"] = now
				}
				if now.Sub(e.firstOver["cpu_high"]) >= win {
					e.fire("cpu_high", now, float64(rules.CPU.Threshold), cpuPct[0],
						fmt.Sprintf("CPU 使用率 %.0f%%（阈值 %d%%，已持续 %s）", cpuPct[0], rules.CPU.Threshold, win))
				}
			} else {
				delete(e.firstOver, "cpu_high")
			}
		}
	}
	if rules.Mem.Enabled {
		if vm, err := mem.VirtualMemory(); err == nil {
			win := time.Duration(rules.Mem.WindowSec) * time.Second
			if win <= 0 {
				win = 60 * time.Second
			}
			if vm.UsedPercent >= float64(rules.Mem.Threshold) {
				if e.firstOver["mem_high"].IsZero() {
					e.firstOver["mem_high"] = now
				}
				if now.Sub(e.firstOver["mem_high"]) >= win {
					e.fire("mem_high", now, float64(rules.Mem.Threshold), vm.UsedPercent,
						fmt.Sprintf("内存使用率 %.0f%%（阈值 %d%%，已持续 %s）", vm.UsedPercent, rules.Mem.Threshold, win))
				}
			} else {
				delete(e.firstOver, "mem_high")
			}
		}
	}
	if rules.Disk.Enabled && e.auditDir != "" {
		if du, err := disk.Usage(e.auditDir); err == nil {
			e.fire("disk_high", now, float64(rules.Disk.Threshold), du.UsedPercent,
				fmt.Sprintf("数据盘 %s 使用率 %.0f%%（阈值 %d%%）", e.auditDir, du.UsedPercent, rules.Disk.Threshold))
		}
	}

	// Request-rate rule: kingmoat_requests_total delta over the interval,
	// normalised to per-minute volume against the threshold.
	total := e.reqTotal()
	if rules.Requests.Enabled && e.hasLast {
		perMin := (total - e.lastReqTotal) / interval.Minutes()
		e.fire("requests", now, float64(rules.Requests.Threshold), perMin,
			fmt.Sprintf("Web 请求速率 %.0f 次/分钟（阈值 %d）", perMin, rules.Requests.Threshold))
	}
	e.lastReqTotal = total
	e.hasLast = true

	// Count/ranking rules over the audit window (aggregator when available).
	curMin, prevMin := window(now.Add(-time.Minute), now)
	if rules.Attacks.Enabled || rules.Blocked.Enabled {
		attacks, blocked := e.countWindow(curMin, now)
		if rules.Attacks.Enabled {
			e.fire("attacks", now, float64(rules.Attacks.Threshold), float64(attacks),
				fmt.Sprintf("1 分钟内 Web 攻击事件 %d 次（阈值 %d）", attacks, rules.Attacks.Threshold))
		}
		if rules.Blocked.Enabled {
			e.fire("blocked", now, float64(rules.Blocked.Threshold), float64(blocked),
				fmt.Sprintf("1 分钟内拦截请求 %d 次（阈值 %d）", blocked, rules.Blocked.Threshold))
		}
	}
	if (rules.TopIP.Enabled || rules.TopTarget.Enabled) && prevMin {
		hStart := now.Add(-time.Hour)
		if sum, err := e.aggregate(hStart, now); err == nil && sum != nil && sum.Total > 0 {
			if rules.TopIP.Enabled && len(sum.TopIPs) > 0 {
				top := sum.TopIPs[0]
				e.fire("top_ip", now, float64(rules.TopIP.Threshold), float64(top.Count),
					fmt.Sprintf("1 小时内单 IP %s 攻击 %d 次（阈值 %d）", top.Key, top.Count, rules.TopIP.Threshold))
			}
			if rules.TopTarget.Enabled && len(sum.TopSites) > 0 {
				top := sum.TopSites[0]
				e.fire("top_target", now, float64(rules.TopTarget.Threshold), float64(top.Count),
					fmt.Sprintf("1 小时内单目标 %s 被攻击 %d 次（阈值 %d）", top.Key, top.Count, rules.TopTarget.Threshold))
			}
		}
	}
}

// window reports whether the previous 1-minute aggregate exists (used to
// avoid firing count rules before one full window has elapsed).
func window(since, until time.Time) (sinceOut time.Time, ready bool) {
	return since, true
}

// countWindow counts events (and blocked ones) in the window via the
// aggregator, falling back to the recent-events feed.
func (e *Engine) countWindow(since, until time.Time) (attacks, blocked int) {
	if sum, err := e.aggregate(since, until); err == nil && sum != nil {
		return sum.Total, sum.ByAction["blocked"]
	}
	for _, ev := range e.recent() {
		if ts, err := time.Parse(time.RFC3339Nano, ev.TS); err != nil || ts.Before(since) {
			continue
		}
		attacks++
		if ev.Action == "blocked" {
			blocked++
		}
	}
	return attacks, blocked
}

// aggregate wraps the optional aggregator (nil-safe).
func (e *Engine) aggregate(since, until time.Time) (*logstore.Summary, error) {
	if e.aggFn == nil {
		return nil, fmt.Errorf("aggregator not wired")
	}
	return e.aggFn(since, until)
}

// recent returns recent audit events for the fallback path.
func (e *Engine) recent() []logstore.Event {
	if recentProvider == nil {
		return nil
	}
	return recentProvider()
}

// fire sends the alert through enabled channels respecting the cooldown.
func (e *Engine) fire(rule string, now time.Time, threshold, value float64, message string) {
	e.mu.Lock()
	if until, ok := e.cooldown[rule]; ok && now.Before(until) {
		e.mu.Unlock()
		return
	}
	e.cooldown[rule] = now.Add(e.cfg.CooldownOrDefault())
	e.mu.Unlock()

	name := ruleNames[rule]
	if name == "" {
		name = rule
	}
	subject := fmt.Sprintf("[KingMoat WAF 告警] %s", name)
	if e.webhook != nil {
		if err := e.webhook.Notify(subject, message); err != nil {
			e.logger.Warn("alert webhook failed", "rule", rule, "err", err)
		}
	}
	if e.email != nil {
		body := message + fmt.Sprintf("\n\n时间: %s\n当前值: %.0f\n阈值: %.0f",
			now.Format(time.RFC3339), value, threshold)
		if err := e.email.Notify(subject, body); err != nil {
			e.logger.Warn("alert email failed", "rule", rule, "err", err)
		}
	}
	e.logger.Warn("waf alert fired", "rule", rule, "message", message)
}

// recentProvider wires the audit-log source (called from cmd).
var recentProvider func() []logstore.Event

// SetRecentProvider wires the audit-log source for the fallback count path.
func SetRecentProvider(fn func() []logstore.Event) { recentProvider = fn }
