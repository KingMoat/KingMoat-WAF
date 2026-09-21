package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Message is the OpenAI-compatible chat message (subset used by the agent).
type Message struct {
	Role       string     `json:"role"` // system | user | assistant | tool
	Content    string     `json:"content,omitempty"`
	Images     []string   `json:"images,omitempty"` // data URLs, single user turn only (not persisted)
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is one assistant tool invocation (arguments kept as raw JSON).
type ToolCall struct {
	// Index is the streaming delta ordinal (absent in non-streaming mode).
	Index    int          `json:"index,omitempty"`
	ID       string       `json:"id"`
	Type     string       `json:"type"` // always "function"
	Function ToolCallFunc `json:"function"`
}

// ToolCallFunc carries the function name and raw JSON arguments.
type ToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDef is a function-calling tool schema.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

func (t ToolDef) wire() map[string]any {
	return map[string]any{"type": "function", "function": map[string]any{
		"name": t.Name, "description": t.Description, "parameters": t.Parameters,
	}}
}

// Usage accumulates token accounting.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// Client is an OpenAI-compatible chat-completions client (streaming and
// plain). It speaks /chat/completions only — no SDK dependency.
type Client struct {
	// endpoint is the FULL chat-completions URL derived from the configured
	// base_url by completionsEndpoint (never the raw user input).
	endpoint    string
	apiKey      string
	keySource   string
	model       string
	maxTokens   int
	temperature float64
	http        *http.Client
}

// completionsEndpoint derives the chat-completions URL from the configured
// base_url. Consoles receive wildly different shapes, and gateways 404 on the
// wrong path (a bare https://host posted to /chat/completions is the classic
// "llm status 404: 404 page not found"), so normalize by PATH SHAPE:
//   scheme://host                     → scheme://host/v1/chat/completions
//   scheme://host/v1                  → scheme://host/v1/chat/completions
//   scheme://host/v1/chat/completions → used verbatim
//   scheme://host/anything-else       → scheme://host/anything-else/chat/completions
//   (template defaults like /api/paas/v4 or /api/v3 land in the last case)
func completionsEndpoint(base string) string {
	b := strings.TrimRight(base, "/")
	if b == "" {
		return b
	}
	u, err := url.Parse(b)
	if err != nil || u.Scheme == "" || u.Host == "" {
		// Not a parseable absolute URL: keep the legacy append behavior and
		// let the HTTP client surface the failure.
		return b + "/chat/completions"
	}
	switch {
	case u.Path == "" || u.Path == "/":
		return b + "/v1/chat/completions"
	case strings.HasSuffix(u.Path, "/chat/completions"):
		return b
	default:
		return b + "/chat/completions"
	}
}

// NewClient builds the provider client from resolved settings (env-var key
// source only; the stored-cipher path needs a KEK — use NewClientWithKEK).
func NewClient(p *ProviderSettings) (*Client, error) {
	return NewClientWithKEK(p, nil, nil)
}

// NewClientWithKEK builds the provider client resolving the API key by
// priority: stored cipher (decrypted with kek) > env > none. The resolved
// source is kept for the console diagnostic (key_source), never the key.
func NewClientWithKEK(p *ProviderSettings, kek []byte, logger *slog.Logger) (*Client, error) {
	baseURL, model, err := p.resolveEndpoint()
	if err != nil {
		return nil, err
	}
	apiKey, source := p.ResolveAPIKey(kek, logger)
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Client{
		endpoint:    completionsEndpoint(baseURL),
		apiKey:      apiKey,
		keySource:   source,
		model:       model,
		maxTokens:   p.MaxTokens,
		temperature: p.Temperature,
		http:        &http.Client{Timeout: timeout},
	}, nil
}

// Model returns the configured model id.
func (c *Client) Model() string { return c.model }

// APIKeySet reports whether an API key was resolved (from the stored cipher
// or the configured environment variable). It never exposes the key itself
// — the console uses it to tell "assistant enabled but the server has no
// key" apart from a broken provider endpoint.
func (c *Client) APIKeySet() bool { return c.apiKey != "" }

// KeySource returns where the API key came from: "stored", "env" or "none".
func (c *Client) KeySource() string {
	if c.keySource == "" {
		return KeySourceNone
	}
	return c.keySource
}

// ModelName proxies the model id for the service consumers.
func (s *Service) ModelName() string { return s.client.Model() }

type chatAPIRequest struct {
	Model       string       `json:"model"`
	Messages    []wireMessage `json:"messages"`
	Tools       []map[string]any `json:"tools,omitempty"`
	Stream      bool         `json:"stream"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Temperature float64      `json:"temperature"`
}

// wireMessage is the wire form of a Message: text-only messages keep the
// plain string content; messages carrying images use the multimodal
// content-part array (OpenAI-compatible image_url parts).
type wireMessage struct {
	Role       string     `json:"role"`
	Content    any        `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type wireContentPart struct {
	Type     string  `json:"type"`
	Text     string  `json:"text,omitempty"`
	ImageURL *wireURL `json:"image_url,omitempty"`
}

type wireURL struct {
	URL string `json:"url"`
}

func toWireMessages(msgs []Message) []wireMessage {
	out := make([]wireMessage, 0, len(msgs))
	for _, m := range msgs {
		wm := wireMessage{Role: m.Role, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID, Name: m.Name}
		if len(m.Images) == 0 {
			wm.Content = m.Content
		} else {
			parts := make([]wireContentPart, 0, len(m.Images)+1)
			if m.Content != "" {
				parts = append(parts, wireContentPart{Type: "text", Text: m.Content})
			}
			for _, u := range m.Images {
				parts = append(parts, wireContentPart{Type: "image_url", ImageURL: &wireURL{URL: u}})
			}
			wm.Content = parts
		}
		out = append(out, wm)
	}
	return out
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		Delta        Message `json:"delta"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// ChatResult carries the final assistant message plus token usage.
type ChatResult struct {
	Message Message
	Usage   Usage
}

// Chat performs one completion round. When stream=true the text deltas are
// forwarded to onDelta and tool-call fragments are aggregated server-side.
func (c *Client) Chat(ctx context.Context, messages []Message, tools []ToolDef, stream bool, onDelta func(string)) (*ChatResult, error) {
	reqBody := chatAPIRequest{
		Model: c.model, Messages: toWireMessages(messages), Stream: stream,
		MaxTokens: c.maxTokens, Temperature: c.temperature,
	}
	for _, t := range tools {
		reqBody.Tools = append(reqBody.Tools, t.wire())
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ai: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai: llm request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("ai: llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	if !stream {
		var out chatResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("ai: decode response: %w", err)
		}
		if out.Error != nil {
			return nil, fmt.Errorf("ai: llm error: %s", out.Error.Message)
		}
		if len(out.Choices) == 0 {
			return nil, fmt.Errorf("ai: llm returned no choices")
		}
		return &ChatResult{Message: out.Choices[0].Message, Usage: out.Usage}, nil
	}

	// SSE stream: aggregate deltas into one assistant message.
	result := &ChatResult{}
	var content strings.Builder
	type tcAgg struct{ id, name, args strings.Builder }
	aggs := map[int]*tcAgg{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk chatResponse
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		result.Usage.PromptTokens += chunk.Usage.PromptTokens
		result.Usage.CompletionTokens += chunk.Usage.CompletionTokens
		if len(chunk.Choices) == 0 {
			continue
		}
		delta := chunk.Choices[0].Delta
		if delta.Content != "" {
			content.WriteString(delta.Content)
			if onDelta != nil {
				onDelta(delta.Content)
			}
		}
		for i, tc := range delta.ToolCalls {
			idx := tc.Index
			if idx == 0 && len(delta.ToolCalls) > 1 {
				idx = i // non-indexing providers: fall back to position
			}
			agg := aggs[idx]
			if agg == nil {
				agg = &tcAgg{}
				aggs[idx] = agg
			}
			if tc.ID != "" {
				agg.id.WriteString(tc.ID)
			}
			if tc.Function.Name != "" {
				agg.name.WriteString(tc.Function.Name)
			}
			agg.args.WriteString(tc.Function.Arguments)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ai: stream read: %w", err)
	}
	result.Message.Role = "assistant"
	result.Message.Content = content.String()
	for i := 0; i < len(aggs); i++ {
		agg := aggs[i]
		if agg == nil {
			continue
		}
		result.Message.ToolCalls = append(result.Message.ToolCalls, ToolCall{
			ID: agg.id.String(), Type: "function",
			Function: ToolCallFunc{Name: agg.name.String(), Arguments: agg.args.String()},
		})
	}
	if result.Message.Content == "" && len(result.Message.ToolCalls) == 0 {
		return nil, fmt.Errorf("ai: llm stream ended without content")
	}
	return result, nil
}
