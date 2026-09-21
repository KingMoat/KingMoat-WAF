// Package ai implements the embedded AI assistant: a read-only agent over
// the WAF's own data (config, audit logs, stats), with provider presets,
// dynamic sanitization, scheduled reports and a streamable-HTTP MCP
// endpoint. The assistant never holds write credentials and the tool table
// is hard-coded read-only by construction.
package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Settings is the "ai" top-level section of the config file. Everything
// defaults to disabled; absent sections change nothing.
type Settings struct {
	Enabled  bool             `json:"enabled"`
	Provider ProviderSettings `json:"provider"`
	Sanitize SanitizeSettings `json:"sanitize"`
	Chat     ChatSettings     `json:"chat"`
	Analysis AnalysisSettings `json:"analysis"`
	MCP      MCPSettings      `json:"mcp"`
	// SystemPrompt optionally overrides the built-in analyst charter (console
	// settings → AI). Empty keeps the default read-only charter.
	SystemPrompt string `json:"system_prompt,omitempty"`
	// KEK is the runtime key-encryption key loaded by ResolveSettings from
	// the assembly point's kek path; used to decrypt Provider.APIKeyCipher.
	// Never serialized into any config file or API response.
	KEK []byte `json:"-"`
}

// ProviderSettings selects the LLM endpoint. API keys resolve by priority:
// the KEK-encrypted stored copy (api_key_cipher, with its argon2id hash in
// api_key_hash for integrity) first, then the environment variable.
type ProviderSettings struct {
	Template    string  `json:"template"` // preset id or "custom"
	BaseURL     string  `json:"base_url,omitempty"`
	Model       string  `json:"model,omitempty"`
	APIKeyEnv   string  `json:"api_key_env,omitempty"` // default KINGMOAT_AI_API_KEY (fallback when nothing is stored)
	TimeoutSec  int     `json:"timeout_sec,omitempty"` // default 120
	MaxTokens   int     `json:"max_tokens,omitempty"`  // default 4096
	Temperature float64 `json:"temperature,omitempty"`
	// APIKeyHash is the argon2id encoded hash of the stored API key
	// (internal/passhash), proving a key exists without exposing it.
	APIKeyHash string `json:"api_key_hash,omitempty"`
	// APIKeyCipher is the KEK-sealed API key (AES-256-GCM, base64);
	// decrypted only in memory via ResolveAPIKey.
	APIKeyCipher string `json:"api_key_cipher,omitempty"`
}

// Template is one built-in provider preset.
type Template struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
	Models  string `json:"models"` // hint shown in the console
}

// Templates returns the built-in provider presets (OpenAI-compatible
// protocol only).
func Templates() []Template {
	return []Template{
		{ID: "openai", Name: "OpenAI", BaseURL: "https://api.openai.com/v1", Models: "gpt-4o / gpt-4o-mini"},
		{ID: "deepseek", Name: "DeepSeek 深度求索", BaseURL: "https://api.deepseek.com/v1", Models: "deepseek-chat / deepseek-reasoner"},
		{ID: "qwen", Name: "阿里云百炼 通义千问", BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Models: "qwen-plus / qwen-max"},
		{ID: "glm", Name: "智谱 GLM", BaseURL: "https://open.bigmodel.cn/api/paas/v4", Models: "glm-4 系列"},
		{ID: "kimi", Name: "月之暗面 Kimi", BaseURL: "https://api.moonshot.cn/v1", Models: "kimi 系列"},
		{ID: "doubao", Name: "字节火山方舟 豆包", BaseURL: "https://ark.cn-beijing.volces.com/api/v3", Models: "按方舟接入点 ID"},
		{ID: "openrouter", Name: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", Models: "按需"},
		{ID: "ollama", Name: "Ollama 本地模型", BaseURL: "http://127.0.0.1:11434/v1", Models: "本地模型名"},
		{ID: "vllm", Name: "vLLM 自托管", BaseURL: "http://127.0.0.1:8000/v1", Models: "按部署"},
		{ID: "custom", Name: "自定义 OpenAI 兼容", BaseURL: "", Models: "自定义"},
	}
}

// Resolve returns the effective base URL, model and API key for the
// provider, applying template defaults. Key resolution is delegated to
// ResolveAPIKey (stored cipher skipped without a KEK; env first, then the
// inline fallback for a literal key pasted into api_key_env).
func (p *ProviderSettings) Resolve() (baseURL, model, apiKey string, err error) {
	baseURL, model, err = p.resolveEndpoint()
	if err != nil {
		return "", "", "", err
	}
	apiKey, _ = p.ResolveAPIKey(nil, nil)
	return baseURL, model, apiKey, nil
}

// resolveEndpoint returns the effective base URL and model, applying
// template defaults.
func (p *ProviderSettings) resolveEndpoint() (baseURL, model string, err error) {
	baseURL = strings.TrimRight(p.BaseURL, "/")
	if p.Template != "" && p.Template != "custom" {
		for _, t := range Templates() {
			if t.ID == p.Template {
				if baseURL == "" {
					baseURL = t.BaseURL
				}
				break
			}
		}
	}
	if baseURL == "" {
		return "", "", fmt.Errorf("ai: provider base_url is empty (set template or base_url)")
	}
	model = p.Model
	if model == "" {
		return "", "", fmt.Errorf("ai: provider model is empty")
	}
	return baseURL, model, nil
}

// SanitizeSettings configures the outbound masking pipeline.
type SanitizeSettings struct {
	// Enabled is tri-state: nil (absent) means ON — masking defaults to
	// enabled so configs written before this field existed keep protecting
	// outbound traffic — while an explicit false is honored.
	Enabled        *bool    `json:"enabled,omitempty"`
	MaskPublicIP   bool     `json:"mask_public_ip,omitempty"`
	MaskInternal   bool     `json:"mask_internal_hosts,omitempty"`
	MaskCredential bool     `json:"mask_credentials,omitempty"`
	PayloadMax     int      `json:"payload_max_chars,omitempty"` // default 512
	CustomTerms    []string `json:"custom_terms,omitempty"`      // [ENT] vocabulary
}

// EnabledOrDefault reports whether outbound masking is active: absent
// (nil) means on (privacy by default); an explicit false is honored.
func (s SanitizeSettings) EnabledOrDefault() bool { return s.Enabled == nil || *s.Enabled }

// ChatSettings bounds the chat surface.
type ChatSettings struct {
	HistoryTurns        int `json:"history_turns,omitempty"`         // default 20
	MaxSessions         int `json:"max_sessions,omitempty"`          // default 100
	ContextWindowTokens int `json:"context_window_tokens,omitempty"` // 0 = unlimited; over budget triggers history compression
	KeepRecentTurns     int `json:"keep_recent_turns,omitempty"`     // default 4; turns kept verbatim when compressing
	// HistoryRetentionDays auto-deletes chat sessions older than N days
	// (0 = keep forever). Enforced by a cleanup loop in the service.
	HistoryRetentionDays int `json:"history_retention_days,omitempty"`
}

// Schedule is one active-analysis cron entry.
type Schedule struct {
	Kind    string `json:"kind"` // attack_summary_daily | attack_summary_weekly | config_review
	Cron    string `json:"cron"`
	Webhook string `json:"webhook,omitempty"`
	// Channel selects the delivery sink: "webhook" (also the default when
	// absent, for schedules written before channels existed) or "email".
	Channel string `json:"channel,omitempty"`
	// Email holds the report recipients (comma-separated) for the email
	// channel; empty falls back to the global SMTP "to" list.
	Email string `json:"email,omitempty"`
}

// AnalysisSettings configures proactive reports.
type AnalysisSettings struct {
	Enabled         bool          `json:"enabled"`
	Schedules       []Schedule    `json:"schedules,omitempty"`
	Spike           SpikeSettings `json:"spike,omitempty"`
	MaxTokensPerDay int64         `json:"max_tokens_per_day,omitempty"` // default 200000
}

// SpikeSettings configures the traffic-surge trigger.
type SpikeSettings struct {
	Enabled    bool    `json:"enabled"`
	Window     string  `json:"window,omitempty"`     // default 1h
	Multiplier float64 `json:"multiplier,omitempty"` // default 3.0
}

// MCPSettings configures the MCP endpoint.
type MCPSettings struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"` // default /mcp
}

// LoadSettings extracts the "ai" section from a JSON document (the shared
// config file or a dedicated -ai-config file).
func LoadSettings(path string) (*Settings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ai: read %s: %w", path, err)
	}
	var doc struct {
		AI *Settings `json:"ai"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("ai: parse %s: %w", path, err)
	}
	if doc.AI == nil {
		return nil, nil
	}
	doc.AI.ApplyDefaults()
	return doc.AI, nil
}

// ApplyDefaults fills unset fields with the built-in defaults. It must be
// applied by every settings construction path: file loading (LoadSettings)
// and the embedded-console hot-rebuild path that unmarshals the published
// config — otherwise all-in-one runs with temperature 0 and no max_tokens.
func (s *Settings) ApplyDefaults() {
	if s.Provider.APIKeyEnv == "" {
		s.Provider.APIKeyEnv = "KINGMOAT_AI_API_KEY"
	}
	if s.Chat.HistoryTurns <= 0 {
		s.Chat.HistoryTurns = 20
	}
	if s.Chat.MaxSessions <= 0 {
		s.Chat.MaxSessions = 100
	}
	if s.Chat.KeepRecentTurns <= 0 {
		s.Chat.KeepRecentTurns = 4
	}
	if s.Provider.TimeoutSec <= 0 {
		s.Provider.TimeoutSec = 120
	}
	if s.Provider.MaxTokens <= 0 {
		s.Provider.MaxTokens = 4096
	}
	if s.Provider.Temperature <= 0 {
		s.Provider.Temperature = 0.2
	}
	if s.Sanitize.PayloadMax <= 0 {
		s.Sanitize.PayloadMax = 512
	}
	if s.Analysis.MaxTokensPerDay <= 0 {
		s.Analysis.MaxTokensPerDay = 200000
	}
	// Seed one default daily-report schedule so enabling analysis without a
	// schedule still produces the every-day-08:00 webhook report the UI
	// guides users to refine.
	if s.Analysis.Enabled && len(s.Analysis.Schedules) == 0 {
		s.Analysis.Schedules = []Schedule{{Kind: "attack_summary_daily", Cron: "0 8 * * *", Channel: "webhook"}}
	}
	if s.Analysis.Spike.Multiplier <= 0 {
		s.Analysis.Spike.Multiplier = 3.0
	}
	if s.MCP.Path == "" {
		s.MCP.Path = "/mcp"
	}
}
