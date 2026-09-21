package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kingmoat/kingmoat/internal/logstore"
)

// DataSources is the narrow read-only view the tools are allowed to touch.
// It is the ONLY capability boundary of the assistant: the tool table below
// is hard-coded, cannot be extended via config, and every result passes the
// sanitizer before leaving the process.
type DataSources struct {
	Version string
	// Logs serves audit-event queries (ring + NDJSON history).
	Logs interface {
		Query(q logstore.LogQuery) ([]logstore.Event, error)
		Aggregate(since, until time.Time) (*logstore.Summary, error)
		Recent(n int) []logstore.Event
	}
	// Current returns (revision, config-as-JSON).
	Current func() (int64, json.RawMessage)
	// Revisions returns up to limit revision metadata rows.
	Revisions func(limit int) ([]RevisionInfo, error)
	// Stats returns the today-counters block.
	Stats func() map[string]any
	// Status returns version/revision/site info.
	Status func() map[string]any
}

// RevisionInfo is the provider-agnostic revision metadata.
type RevisionInfo struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Author    string    `json:"author"`
	Note      string    `json:"note"`
}

// ToolSet is the hard-coded read-only tool table.
type ToolSet struct {
	src   *DataSources
	san   *Sanitizer
	tools []ToolDef
}

// NewToolSet builds the registry; every tool result is sanitized through san.
func NewToolSet(src *DataSources, san *Sanitizer) *ToolSet {
	ts := &ToolSet{src: src, san: san}
	ts.tools = []ToolDef{
		{
			Name:        "get_status",
			Description: "获取 KingMoat WAF 运行状态：版本、当前配置 revision、站点数、服务器时间。",
			Parameters:  json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		{
			Name:        "get_active_config",
			Description: "获取当前生效的完整防护配置（已脱敏）：站点、WAF、ACL、限流、BOT 检测等。",
			Parameters:  json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		{
			Name:        "list_config_revisions",
			Description: "列出配置版本历史（最新在前）。",
			Parameters: json.RawMessage(`{"type":"object","properties":{
				"limit":{"type":"integer","description":"返回条数，默认 20，上限 50"}
			},"additionalProperties":false}`),
		},
		{
			Name:        "query_audit_logs",
			Description: "查询攻击审计事件（脱敏后返回）。可按时间窗、动作、规则、站点、来源 IP 过滤。",
			Parameters: json.RawMessage(`{"type":"object","properties":{
				"since":{"type":"string","description":"起始时间 RFC3339，可空"},
				"until":{"type":"string","description":"结束时间 RFC3339，可空"},
				"action":{"type":"string","description":"blocked | monitor | challenged | redirected"},
				"rule":{"type":"string","description":"规则 ID 精确匹配"},
				"site":{"type":"string","description":"站点域名"},
				"src_ip":{"type":"string","description":"来源 IP 前缀匹配"},
				"limit":{"type":"integer","description":"返回条数，默认 100，上限 1000"}
			},"additionalProperties":false}`),
		},
		{
			Name:        "get_attack_summary",
			Description: "获取攻击态势预聚合摘要：Top 规则/来源 IP/路径/站点、动作分布、疑似误报计数。",
			Parameters: json.RawMessage(`{"type":"object","properties":{
				"window":{"type":"string","enum":["1h","24h","7d"],"description":"统计窗口，默认 24h"}
			},"additionalProperties":false}`),
		},
		{
			Name:        "get_stats",
			Description: "获取今日统计：拦截、挑战、观察计数与配置版本。",
			Parameters:  json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
	}
	return ts
}

// Tools exposes the schema list for function calling.
func (ts *ToolSet) Tools() []ToolDef { return ts.tools }

// Execute runs one tool by name with raw JSON arguments and returns the
// sanitized JSON result. Unknown tools are rejected — there is no dynamic
// registration path.
func (ts *ToolSet) Execute(ctx context.Context, name, args string) (string, error) {
	em := NewEntityMap()
	var out any
	var err error
	switch name {
	case "get_status":
		if ts.src == nil || ts.src.Status == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: status source not wired", name)
		}
		out = ts.src.Status()
	case "get_stats":
		if ts.src == nil || ts.src.Stats == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: stats source not wired", name)
		}
		out = ts.src.Stats()
	case "get_active_config":
		if ts.src == nil || ts.src.Current == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: config source not wired", name)
		}
		rev, cfg := ts.src.Current()
		out = map[string]any{"revision": rev, "config": json.RawMessage(cfg)}
	case "list_config_revisions":
		if ts.src == nil || ts.src.Revisions == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: revisions source not wired", name)
		}
		limit := 20
		var req struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal([]byte(args), &req)
		if req.Limit > 0 {
			limit = req.Limit
		}
		if limit > 50 {
			limit = 50
		}
		out, err = ts.src.Revisions(limit)
	case "query_audit_logs":
		var req struct {
			Since  string `json:"since"`
			Until  string `json:"until"`
			Action string `json:"action"`
			Rule   string `json:"rule"`
			Site   string `json:"site"`
			SrcIP  string `json:"src_ip"`
			Limit  int    `json:"limit"`
		}
		if err = json.Unmarshal([]byte(args), &req); err != nil {
			return "", fmt.Errorf("ai: bad arguments: %w", err)
		}
		q := logstore.LogQuery{
			Action: req.Action, Rule: req.Rule, Site: req.Site, SrcIP: req.SrcIP,
			Limit: req.Limit,
		}
		if req.Since != "" {
			if t, perr := time.Parse(time.RFC3339, req.Since); perr == nil {
				q.Since = t
			}
		}
		if req.Until != "" {
			if t, perr := time.Parse(time.RFC3339, req.Until); perr == nil {
				q.Until = t
			}
		}
		if ts.src == nil || ts.src.Logs == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: log source not wired", name)
		}
		var events []logstore.Event
		events, err = ts.src.Logs.Query(q)
		if err == nil {
			out = map[string]any{"count": len(events), "events": events}
		}
	case "get_attack_summary":
		var req struct {
			Window string `json:"window"`
		}
		_ = json.Unmarshal([]byte(args), &req)
		dur := 24 * time.Hour
		switch req.Window {
		case "1h":
			dur = time.Hour
		case "7d":
			dur = 7 * 24 * time.Hour
		}
		if ts.src == nil || ts.src.Logs == nil {
			return "", fmt.Errorf("ai: tool %q unavailable: log source not wired", name)
		}
		var sum *logstore.Summary
		sum, err = ts.src.Logs.Aggregate(time.Now().Add(-dur), time.Now())
		if err == nil {
			out = sum
		}
	default:
		return "", fmt.Errorf("ai: unknown tool %q", name)
	}
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return ts.san.Sanitize(string(b), em), nil
}
