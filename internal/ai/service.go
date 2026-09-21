package ai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/kingmoat/kingmoat/internal/alerting"
	"github.com/kingmoat/kingmoat/internal/config"
)

// Service wires the assistant: chat SSE, session/report REST endpoints and
// the analysis scheduler. It is created only when Settings.Enabled.
type Service struct {
	cfg    *Settings
	client *Client
	agent  *Agent
	store  *Store
	san    *Sanitizer
	tools  *ToolSet
	logger *slog.Logger

	anal  *Analyzer
	mu    sync.Mutex
	dirty map[string]bool // sessions with unsaved entity maps
	retentionStop chan struct{} // history prune loop stop (nil = disabled)

	emailCfg   config.EmailSettings                    // active config SMTP section (value copy, hot-rebuilt with the config)
	newEmailer func(cfg config.EmailSettings) emailSender // delivery sink factory; swappable in tests
}

// NewService assembles the assistant; settings must be enabled and the
// provider resolvable. sources is the read-only data boundary. kek decrypts
// the stored provider API key (nil = env-var keys only). emailCfg is the
// active config's SMTP section used by the email report channel.
func NewService(cfg *Settings, sources *DataSources, aiDBPath string, kek []byte, logger *slog.Logger, emailCfg config.EmailSettings) (*Service, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("ai: service disabled")
	}
	client, err := NewClientWithKEK(&cfg.Provider, kek, logger)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(aiDBPath)
	if err != nil {
		return nil, err
	}
	san := NewSanitizer(cfg.Sanitize, func() []string {
		if sources.Status == nil {
			return nil
		}
		if hosts, ok := sources.Status()["site_domains"].([]string); ok {
			return hosts
		}
		return nil
	})
	tools := NewToolSet(sources, san)
	s := &Service{
		cfg:    cfg,
		client: client,
		agent:  NewAgent(client, tools),
		store:  store,
		san:    san,
		tools:  tools,
		logger: logger,
		dirty:  map[string]bool{},
		emailCfg: emailCfg,
		newEmailer: func(cfg config.EmailSettings) emailSender { return alerting.NewEmailNotifier(cfg) },
	}
	s.agent.SetSystemPrompt(cfg.SystemPrompt)
	if cfg.Analysis.Enabled {
		s.anal = NewAnalyzer(s)
		s.anal.Start()
	}
	return s, nil
}

// Close stops the scheduler and closes the store.
func (s *Service) Close() error {
	if s.retentionStop != nil {
		select {
		case <-s.retentionStop:
		default:
			close(s.retentionStop)
		}
	}
	if s.anal != nil {
		s.anal.Stop()
	}
	return s.store.Close()
}

// StartRetention launches the background history-prune loop (bounded to the
// service lifetime; stopped by Close). No-op when retention is disabled.
func (s *Service) StartRetention() {
	days := s.cfg.Chat.HistoryRetentionDays
	if days <= 0 {
		return
	}
	s.retentionStop = make(chan struct{})
	go func() {
		s.store.DeleteSessionsOlderThan(days)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.retentionStop:
				return
			case <-ticker.C:
				s.store.DeleteSessionsOlderThan(days)
			}
		}
	}()
}

// Config exposes a console-safe view (no secrets).
func (s *Service) Config() map[string]any {
	return map[string]any{
		"enabled":       true,
		"template":      s.cfg.Provider.Template,
		"model":         s.client.Model(),
		"api_key_set":   s.client.APIKeySet(),
		"key_source":    s.client.KeySource(),
		"temperature":   s.cfg.Provider.Temperature,
		"timeout_sec":   s.cfg.Provider.TimeoutSec,
		"system_prompt": s.cfg.SystemPrompt,
		"mcp_enabled":   s.cfg.MCP.Enabled,
		"mcp_path":      s.cfg.MCP.Path,
		"analysis":      s.cfg.Analysis.Enabled,
		"sanitize":      s.cfg.Sanitize.EnabledOrDefault(),
		"usage":         usageView(s.store),
	}
}

// MCPEnabled reports whether the MCP endpoint should be mounted.
func (s *Service) MCPEnabled() bool { return s.cfg.MCP.Enabled }

// MCPPath returns the configured MCP route path.
func (s *Service) MCPPath() string { return s.cfg.MCP.Path }

// ListSessions proxies session listing (console API). An empty owner
// returns every session (admin view); a named owner returns only their own.
func (s *Service) ListSessions(limit int, owner string) ([]SessionRow, error) {
	return s.store.ListSessions(limit, owner)
}

// SessionOwner proxies the ownership lookup used for per-user isolation.
func (s *Service) SessionOwner(id string) (string, error) { return s.store.SessionOwner(id) }

// SessionMessages proxies restored history (console API); stored content is
// sanitized, entity maps restore it for display.
func (s *Service) SessionMessages(id string) ([]map[string]any, error) {
	rows, err := s.store.SessionMessages(id, 500)
	if err != nil {
		return nil, err
	}
	em, err := s.store.LoadEntities(id)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if r.Role != "user" && r.Role != "assistant" {
			continue
		}
		out = append(out, map[string]any{
			"id": r.ID, "role": r.Role, "content": em.Restore(r.Content),
			"created_at": r.CreatedAt,
		})
	}
	return out, nil
}

// DeleteSession proxies session deletion (console API).
func (s *Service) DeleteSession(id string) error { return s.store.DeleteSession(id) }

// ListReports proxies report listing (console API).
func (s *Service) ListReports(limit int) ([]ReportRow, error) { return s.store.ListReports(limit) }

// GetReport proxies one report readback (console API).
func (s *Service) GetReport(id int64) (*ReportRow, error) { return s.store.GetReport(id) }

func usageView(st *Store) map[string]int {
	p, c, r := st.UsageToday()
	return map[string]int{"prompt_tokens": p, "completion_tokens": c, "requests": r}
}

// chatRequest is the POST /api/ai/chat body.
type chatRequest struct {
	SessionID    string   `json:"session_id"`
	Message      string   `json:"message"`
	Images       []string `json:"images,omitempty"` // data URLs (png/jpeg/webp/gif), max 4 x 4 MiB
	ContextEvent json.RawMessage `json:"context_event,omitempty"`
}

const (
	maxImagesPerTurn  = 4
	maxImageBytes     = 4 << 20 // 4 MiB per decoded image
	chatBodyLimit     = 32 << 20 // room for base64 image payloads
)

var reImageDataURL = regexp.MustCompile(`^data:image/(png|jpeg|jpg|webp|gif);base64,([A-Za-z0-9+/=]+)$`)

// validateImages checks count, format and decoded size of user-supplied
// images; returns the normalized data-URL slice.
func validateImages(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxImagesPerTurn {
		return nil, fmt.Errorf("ai: too many images (max %d)", maxImagesPerTurn)
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		m := reImageDataURL.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			return nil, fmt.Errorf("ai: image must be a base64 data URL (png/jpeg/webp/gif)")
		}
		b, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil {
			return nil, fmt.Errorf("ai: image base64 decode failed")
		}
		if len(b) > maxImageBytes {
			return nil, fmt.Errorf("ai: image too large (max %d MiB)", maxImageBytes>>20)
		}
		out = append(out, strings.TrimSpace(raw))
	}
	return out, nil
}

// HandleChat serves POST /api/ai/chat as an SSE stream. owner is the
// authenticated console user the session belongs to (empty when auth is
// disabled).
func (s *Service) HandleChat(w http.ResponseWriter, r *http.Request, owner string) {
	r.Body = http.MaxBytesReader(w, r.Body, chatBodyLimit)
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if req.Message == "" {
		http.Error(w, `{"error":"message required"}`, http.StatusBadRequest)
		return
	}
	if _, p, c := s.store.UsageToday(); s.cfg.Analysis.MaxTokensPerDay > 0 && p+c > int(s.cfg.Analysis.MaxTokensPerDay) {
		http.Error(w, `{"error":"daily token quota exceeded"}`, http.StatusTooManyRequests)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")

	emit := func(ev StreamEvent) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, b)
		flusher.Flush()
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = "s-" + uuid.NewString()[:13]
	}
	if err := s.store.CreateSession(sessionID, titleOf(req.Message), owner); err != nil {
		s.emitErr(emit, err)
		return
	}

	imgs, verr := validateImages(req.Images)
	if verr != nil {
		s.emitErr(emit, verr)
		return
	}

	// Session-scoped sanitizer map: fresh load from storage so placeholders
	// stay stable across turns.
	em, err := s.store.LoadEntities(sessionID)
	if err != nil {
		s.emitErr(emit, err)
		return
	}

	// Build the user turn: optional audit-event context (sanitized) + message.
	userMsg := req.Message
	if len(req.ContextEvent) > 0 {
		ctxText := s.san.Sanitize(string(req.ContextEvent), em)
		userMsg = "请分析以下攻击审计事件（JSON，已脱敏）：\n```json\n" + ctxText + "\n```\n\n" + req.Message
	}

	// Context-window management BEFORE persisting the new turn: compress or
	// clear stale history so the conversation can continue within the model
	// context (compression failure falls back to clearing).
	history := s.historyFor(sessionID)
	s.manageContext(r.Context(), sessionID, &history, Message{Role: "user", Content: userMsg, Images: imgs})

	// Persist the raw user message (text + image placeholder; image bytes
	// are single-turn and not stored). Assistant output is stored in its
	// sanitized form alongside the entity map.
	stored := req.Message
	if len(imgs) > 0 {
		stored += fmt.Sprintf("\n[图片x%d]", len(imgs))
	}
	if err := s.store.AppendMessage(sessionID, Message{Role: "user", Content: stored}); err != nil {
		s.emitErr(emit, err)
		return
	}

	final, usage, err := s.agent.RunTurn(r.Context(), history, Message{Role: "user", Content: userMsg, Images: imgs}, emit)
	if err != nil {
		s.store.AddUsage(usage.PromptTokens, usage.CompletionTokens)
		s.emitErr(emit, err)
		return
	}
	_ = s.store.AddUsage(usage.PromptTokens, usage.CompletionTokens)
	_ = s.store.SaveEntities(sessionID, em)
	_ = s.store.AppendMessage(sessionID, Message{Role: "assistant", Content: final})
	_ = s.store.TouchSession(sessionID)

	// Final frame carries restored text and the session id.
	restored := em.Restore(final)
	donePayload, _ := json.Marshal(map[string]any{
		"session_id": sessionID,
		"text":       restored,
		"usage":      usage,
	})
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", donePayload)
	flusher.Flush()
}

func (s *Service) emitErr(emit func(StreamEvent), err error) {
	if emit != nil {
		emit(StreamEvent{Type: "error", Text: err.Error()})
	}
}

// historyFor builds the LLM history from stored turns (sanitized form);
// compressed-summary rows (role=system) are part of the conversation.
func (s *Service) historyFor(sessionID string) []Message {
	rows, err := s.store.SessionMessages(sessionID, s.cfg.Chat.HistoryTurns*2+2)
	if err != nil {
		return nil
	}
	var out []Message
	for _, r := range rows {
		switch r.Role {
		case "user", "assistant", "system":
			out = append(out, Message{Role: r.Role, Content: r.Content})
		}
	}
	return out
}

const compressSystemPrompt = "你是会话压缩器。把用户提供的对话历史压缩为要点摘要：保留关键事实、数据、结论与未决问题，去掉寒暄与重复。直接输出摘要正文，不要任何评论或开场白。"

// estimateTokens gives a deliberately conservative prompt-size estimate:
// CJK text is ~1 token per rune, so rune count over-estimates English and
// keeps us on the safe side. Images cost a flat allowance each.
func estimateTokens(text string) int { return utf8.RuneCountInString(text) }

const visionTokenAllowance = 1000

// manageContext keeps the prompt within the configured context window:
// over budget it compresses older turns into an LLM-written summary; if the
// compression call itself fails (upstream unavailable) it clears the stored
// history outright so the current conversation continues.
func (s *Service) manageContext(ctx context.Context, sessionID string, history *[]Message, userTurn Message) {
	limit := s.cfg.Chat.ContextWindowTokens
	if limit <= 0 || history == nil {
		return
	}
	used := estimateTokens(s.agent.SystemPrompt()) + estimateTokens(userTurn.Content) + len(userTurn.Images)*visionTokenAllowance + s.cfg.Provider.MaxTokens
	for _, m := range *history {
		used += estimateTokens(m.Content)
	}
	if used <= limit {
		return
	}
	rows, err := s.store.SessionMessages(sessionID, 100000)
	if err != nil || len(rows) == 0 {
		return
	}
	keepN := s.cfg.Chat.KeepRecentTurns * 2
	if keepN < 2 {
		keepN = 2
	}
	if keepN >= len(rows) {
		// Nothing compressible left: clear so the live turn still fits.
		if cerr := s.store.ClearHistory(sessionID); cerr == nil {
			*history = nil
			s.logger.Info("ai: context over budget, history cleared", "session", sessionID)
		}
		return
	}
	old := rows[:len(rows)-keepN]
	keep := rows[len(rows)-keepN:]

	var sb strings.Builder
	sb.WriteString("请压缩以下对话历史：\n")
	for _, r := range old {
		if r.Role == "user" || r.Role == "assistant" {
			fmt.Fprintf(&sb, "%s: %s\n", r.Role, r.Content)
		}
	}
	summary, cerr := s.client.Chat(ctx, []Message{
		{Role: "system", Content: compressSystemPrompt},
		{Role: "user", Content: sb.String()},
	}, nil, false, nil)
	if summary != nil {
		_ = s.store.AddUsage(summary.Usage.PromptTokens, summary.Usage.CompletionTokens)
	}
	var summaryText string
	if summary != nil {
		summaryText = summary.Message.Content
	}
	if cerr != nil || strings.TrimSpace(summaryText) == "" {
		// 上游不可用：直接清除历史，保证会话可继续。
		if derr := s.store.ClearHistory(sessionID); derr == nil {
			*history = nil
			s.logger.Warn("ai: context compression failed, history cleared", "session", sessionID, "err", cerr)
		}
		return
	}
	if rerr := s.store.ReplaceHistory(sessionID, summaryText, keep); rerr == nil {
		nh := make([]Message, 0, len(keep)+1)
		nh = append(nh, Message{Role: "system", Content: summaryText})
		for _, r := range keep {
			nh = append(nh, Message{Role: r.Role, Content: r.Content})
		}
		*history = nh
		s.logger.Info("ai: history compressed", "session", sessionID, "old", len(old), "kept", len(keep))
	}
}

func titleOf(msg string) string {
	r := []rune(msg)
	if len(r) > 30 {
		return string(r[:30]) + "…"
	}
	return string(r)
}
