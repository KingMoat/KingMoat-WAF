package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// Analyzer runs the proactive analysis schedules and the traffic-spike
// trigger. Reports are generated through the same read-only agent and
// stored (sanitized) in ai_reports.
type Analyzer struct {
	svc       *Service
	cron      *cron.Cron
	stopOnce  sync.Once
	stopCh    chan struct{}
	mu        sync.Mutex
	lastSpike time.Time
}

// Delivery describes where a generated report is sent. Channel defaults to
// webhook when absent (schedules written before channels existed keep
// working unchanged).
type Delivery struct {
	Channel string // "webhook" | "email"; "" = webhook
	Webhook string // webhook URL (webhook channel)
	Email   string // comma-separated recipients (email channel)
}

func (d Delivery) channel() string {
	if d.Channel == "email" {
		return "email"
	}
	return "webhook"
}

// NewAnalyzer builds the scheduler from settings.
func NewAnalyzer(svc *Service) *Analyzer {
	a := &Analyzer{svc: svc, stopCh: make(chan struct{})}
	a.cron = cron.New()
	for _, sc := range svc.cfg.Analysis.Schedules {
		kind, expr, deliv := sc.Kind, sc.Cron, Delivery{Channel: sc.Channel, Webhook: sc.Webhook, Email: sc.Email}
		window := 24 * time.Hour
		if strings.Contains(kind, "weekly") {
			window = 7 * 24 * time.Hour
		}
		if _, err := a.cron.AddFunc(expr, func() {
			_, err := a.svc.RunReport(kind, "schedule", window, deliv)
			if err != nil {
				a.svc.logger.Error("ai: scheduled report failed", "kind", kind, "err", err)
			}
		}); err != nil {
			a.svc.logger.Error("ai: bad cron expression, schedule skipped", "kind", kind, "cron", expr, "err", err)
		}
	}
	return a
}

// Start begins cron and the spike watcher.
func (a *Analyzer) Start() {
	a.cron.Start()
	if a.svc.cfg.Analysis.Spike.Enabled {
		go a.spikeLoop()
	}
	a.svc.logger.Info("ai: analysis scheduler started",
		"schedules", len(a.svc.cfg.Analysis.Schedules), "spike", a.svc.cfg.Analysis.Spike.Enabled)
}

// Stop halts the scheduler.
func (a *Analyzer) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopCh)
		ctx := a.cron.Stop()
		<-ctx.Done()
	})
}

// spikeLoop compares the last-hour event volume against the 7-day hourly
// baseline (excluding that hour) and fires a report on surge. It throttles
// to one spike report per hour.
func (a *Analyzer) spikeLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
		}
		src := a.svc.tools.src
		if src == nil || src.Logs == nil {
			continue
		}
		now := time.Now()
		hourly, err := src.Logs.Aggregate(now.Add(-time.Hour), now)
		if err != nil || hourly.Total < 50 {
			continue
		}
		base, err := src.Logs.Aggregate(now.Add(-7*24*time.Hour), now.Add(-time.Hour))
		if err != nil || base.Total == 0 {
			continue
		}
		baselinePerHour := float64(base.Total) / (7 * 23)
		if float64(hourly.Total) > baselinePerHour*a.svc.cfg.Analysis.Spike.Multiplier {
			a.mu.Lock()
			ready := time.Since(a.lastSpike) > time.Hour
			if ready {
				a.lastSpike = time.Now()
			}
			a.mu.Unlock()
			if ready {
				a.svc.logger.Warn("ai: attack traffic spike detected",
					"hourly", hourly.Total, "baseline", baselinePerHour)
				if _, err := a.svc.RunReport("attack_spike", "spike", time.Hour, Delivery{}); err != nil {
					a.svc.logger.Error("ai: spike report failed", "err", err)
				}
			}
		}
	}
}

// reportPrompts map kinds to the analysis mission statement.
func reportPrompt(kind string, window time.Duration) string {
	switch kind {
	case "attack_summary_weekly":
		return fmt.Sprintf("请基于近 7 天攻击数据生成周度安全态势报告：整体趋势与环比变化、Top 攻击规则与来源、可疑模式、误报疑似项、下周关注点。")
	case "config_review":
		return "请审查当前 WAF 配置的安全性：过宽的 ACL/白名单、长期处于 monitor 模式未切换 intercept 的站点、限流阈值是否合理、BOT 检测策略与挑战配置的一致性，输出风险清单与调整建议。"
	case "attack_spike":
		return "检测到攻击流量突增。请分析最近 1 小时数据：突增来源（IP/规则/路径）、可能的攻击类型、是否误报（扫描器/业务高峰）、建议的即时处置步骤（人工执行）。"
	default:
		return fmt.Sprintf("请基于近 %s 攻击数据生成每日安全态势报告：概览、Top 攻击规则与来源 IP、目标资产、疑似误报、处置建议。", window)
	}
}

// RunReport generates one report synchronously: aggregate → agent (tools
// enabled, non-streaming internally) → sanitize → store → deliver (webhook
// or email, per the delivery channel; delivery failures never fail the
// report itself).
func (s *Service) RunReport(kind, trigger string, window time.Duration, d Delivery) (int64, error) {
	if p, c, _ := s.store.UsageToday(); s.cfg.Analysis.MaxTokensPerDay > 0 && p+c > int(s.cfg.Analysis.MaxTokensPerDay) {
		return 0, fmt.Errorf("ai: daily token quota exceeded")
	}
	em := NewEntityMap()
	prompt := reportPrompt(kind, window) + "\n\n先调用 get_attack_summary 与必要的 query_audit_logs 工具取数，再输出完整 Markdown 报告。"
	final, usage, err := s.agent.Run(context.Background(), nil, prompt, nil)
	_ = s.store.AddUsage(usage.PromptTokens, usage.CompletionTokens)
	if err != nil {
		return 0, err
	}
	restored := em.Restore(final)
	row := &ReportRow{
		Kind: kind, Trigger: trigger,
		WindowStart:  time.Now().Add(-window).UTC().Format(time.RFC3339),
		WindowEnd:    time.Now().UTC().Format(time.RFC3339),
		Model:        s.client.Model(),
		ContentMD:    restored,
		PromptTokens: usage.PromptTokens, CompletionTokens: usage.CompletionTokens,
		Status: "done",
	}
	id, err := s.store.InsertReport(row)
	if err != nil {
		return 0, err
	}
	s.deliver(kind, d, restored)
	return id, nil
}

// deliver sends the stored report through the configured sink.
func (s *Service) deliver(kind string, d Delivery, reportMD string) {
	switch d.channel() {
	case "email":
		s.deliverEmail(reportTitle(kind), reportMD, d.Email)
	default:
		if d.Webhook != "" {
			if err := postWebhook(d.Webhook, map[string]any{
				"event": "kingmoat_ai_report", "kind": kind, "title": reportTitle(kind),
				"summary_md": truncateRunes(reportMD, 800),
				"created_at": time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				s.logger.Warn("ai: report webhook failed", "err", err)
			}
		}
	}
}

// emailSender is the minimal outbound-mail contract; the production
// implementation wraps internal/alerting.EmailNotifier and is swapped for
// a fake in tests.
type emailSender interface {
	Send(subject, body string) error
}

// deliverEmail sends the report via the active SMTP settings. Recipients
// come from the schedule (comma-separated); empty falls back to the global
// SMTP "to" list. Unconfigured SMTP or no recipients skips delivery with a
// WARN — the report itself stays queryable in the console either way.
func (s *Service) deliverEmail(subject, body, emailList string) {
	cfg := s.emailCfg
	if !cfg.Enabled || cfg.Host == "" || cfg.From == "" {
		s.logger.Warn("ai: report email delivery skipped: SMTP not configured (设置页「告警与通知」)")
		return
	}
	addrs := splitEmailList(emailList)
	if len(addrs) == 0 {
		addrs = cfg.To
	}
	if len(addrs) == 0 {
		s.logger.Warn("ai: report email delivery skipped: no recipients configured")
		return
	}
	cfg.To = addrs
	if err := s.newEmailer(cfg).Send(subject, body); err != nil {
		s.logger.Warn("ai: report email delivery failed", "err", err)
	}
}

func splitEmailList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func reportTitle(kind string) string {
	switch kind {
	case "attack_summary_weekly":
		return "KingMoat WAF 周度攻击态势报告"
	case "config_review":
		return "KingMoat WAF 配置风险复查报告"
	case "attack_spike":
		return "KingMoat WAF 攻击流量突增分析"
	default:
		return "KingMoat WAF 每日攻击态势报告"
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
