package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

func TestSanitizeStableMappingAndRestore(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(true), MaskInternal: true, MaskCredential: true},
		func() []string { return []string{"waf.corp.internal", "site.example.cn"} })
	em := NewEntityMap()

	in := `攻击来自 10.0.99.217，目标是 site.example.cn，邮箱 a@b.com，password=hunter2secret，JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig123456`
	out1 := s.Sanitize(in, em)
	out2 := s.Sanitize(in, em)
	if out1 != out2 {
		t.Fatalf("mapping not stable:\n%s\n%s", out1, out2)
	}
	if strings.Contains(out1, "10.0.99.217") || strings.Contains(out1, "site.example.cn") ||
		strings.Contains(out1, "a@b.com") || strings.Contains(out1, "hunter2secret") {
		t.Fatalf("sensitive data leaked: %s", out1)
	}
	if !strings.Contains(out1, "[NET-1]") || !strings.Contains(out1, "[INF-1]") ||
		!strings.Contains(out1, "[USR-1]") || !strings.Contains(out1, "[SEC-1]") {
		t.Fatalf("placeholders missing: %s", out1)
	}
	restored := em.Restore(out1)
	if restored != in {
		t.Fatalf("restore mismatch:\n got %s\nwant %s", restored, in)
	}
}

// sbool is a test helper for the tri-state SanitizeSettings.Enabled.
func sbool(b bool) *bool { return &b }

func TestSanitizePublicIPKeptByDefault(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(true)}, nil)
	em := NewEntityMap()
	out := s.Sanitize("attacker 203.0.113.7 scanned", em)
	if !strings.Contains(out, "203.0.113.7") {
		t.Fatalf("public IP should be kept by default: %s", out)
	}
	s2 := NewSanitizer(SanitizeSettings{Enabled: sbool(true), MaskPublicIP: true}, nil)
	out2 := s2.Sanitize("attacker 203.0.113.7 scanned", em)
	if strings.Contains(out2, "203.0.113.7") {
		t.Fatalf("public IP should be masked when enabled: %s", out2)
	}
}

func TestSanitizeCustomTerms(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(true), CustomTerms: []string{"AcmeCorp"}}, nil)
	em := NewEntityMap()
	out := s.Sanitize("acmecorp API 被扫描", em)
	if strings.Contains(strings.ToLower(out), "acmecorp") || !strings.Contains(out, "[ENT-1]") {
		t.Fatalf("custom term not masked: %s", out)
	}
	if em.Restore(out) != "AcmeCorp API 被扫描" {
		t.Fatalf("restore failed: %s", em.Restore(out))
	}
}

type fakeLogs struct{ evs []logstore.Event }

func (f *fakeLogs) Query(q logstore.LogQuery) ([]logstore.Event, error) { return f.evs, nil }
func (f *fakeLogs) Aggregate(since, until time.Time) (*logstore.Summary, error) {
	return &logstore.Summary{Total: len(f.evs), ByAction: map[string]int{"blocked": len(f.evs)}}, nil
}
func (f *fakeLogs) Recent(n int) []logstore.Event { return f.evs }

func testSources() *DataSources {
	return &DataSources{
		Version: "test",
		Logs: &fakeLogs{evs: []logstore.Event{{
			TS: "2026-09-15T10:00:00+08:00", Site: "site.example.cn", ClientIP: "10.0.99.217",
			Action: "blocked", Rule: "coraza/rule-942100", Path: "/login",
		}}},
		Current: func() (int64, json.RawMessage) {
			return 3, json.RawMessage(`{"listen_http":":8080","sites":[{"domains":["site.example.cn"]}]}`)
		},
		Revisions: func(limit int) ([]RevisionInfo, error) {
			return []RevisionInfo{{ID: 3, Author: "admin", Note: "test"}}, nil
		},
		Stats:  func() map[string]any { return map[string]any{"blocked_today": 1} },
		Status: func() map[string]any { return map[string]any{"version": "test", "sites": 1} },
	}
}

func TestToolsNilSourcesReturnErrorNotPanic(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(false)}, nil)
	ts := NewToolSet(&DataSources{Version: "test"}, s)
	for _, name := range []string{"get_status", "get_stats", "get_active_config", "list_config_revisions", "query_audit_logs", "get_attack_summary"} {
		if _, err := ts.Execute(context.Background(), name, `{}`); err == nil {
			t.Errorf("tool %s with unwired source must return error, got nil", name)
		}
	}
}

func TestToolsExecuteSanitizedOutput(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(true), MaskInternal: true}, func() []string {
		return []string{"site.example.cn"}
	})
	ts := NewToolSet(testSources(), s)

	out, err := ts.Execute(context.Background(), "query_audit_logs", `{"limit":10}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "site.example.cn") || strings.Contains(out, "10.0.99.217") {
		t.Fatalf("tool output leaked sensitive values: %s", out)
	}

	if _, err := ts.Execute(context.Background(), "drop_tables", `{}`); err == nil {
		t.Fatal("unknown tool must be rejected")
	}
	if _, err := ts.Execute(context.Background(), "publish_config", `{}`); err == nil {
		t.Fatal("no write tool may exist")
	}
	for _, name := range []string{"get_status", "get_stats", "get_active_config", "list_config_revisions", "get_attack_summary"} {
		if _, err := ts.Execute(context.Background(), name, `{}`); err != nil {
			t.Errorf("tool %s failed: %v", name, err)
		}
	}
}

// mockLLM serves an OpenAI-compatible SSE endpoint: round 1 returns a tool
// call for get_stats, round 2 echoes the tool result in the final answer.
func mockLLM(t *testing.T, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		var req chatAPIRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		writeChunk := func(delta map[string]any) {
			choice := map[string]any{"delta": delta}
			chunk := map[string]any{"choices": []any{choice}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5}}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			f.Flush()
		}
		if *calls == 1 {
			tc := map[string]any{"index": 0, "id": "c1", "type": "function",
				"function": map[string]any{"name": "get_stats", "arguments": "{}"}}
			writeChunk(map[string]any{"tool_calls": []any{tc}})
		} else {
			toolResult := ""
			for _, m := range req.Messages {
				if m.Role == "tool" {
					toolResult, _ = m.Content.(string)
				}
			}
			writeChunk(map[string]any{"role": "assistant", "content": "分析完成：" + toolResult})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
}

func TestAgentToolLoopAndQuota(t *testing.T) {
	calls := 0
	srv := mockLLM(t, &calls)
	defer srv.Close()

	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	client, err := NewClient(&cfg.Provider)
	if err != nil {
		t.Fatal(err)
	}
	san := NewSanitizer(SanitizeSettings{Enabled: sbool(true)}, nil)
	agent := NewAgent(client, NewToolSet(testSources(), san))

	var sawTool StreamEvent
	final, usage, err := agent.Run(context.Background(), nil, "看看今天的拦截统计", func(ev StreamEvent) {
		if ev.Type == "tool" {
			sawTool = ev
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("llm calls = %d, want 2", calls)
	}
	if sawTool.Tool != "get_stats" {
		t.Fatalf("tool event = %+v", sawTool)
	}
	if !strings.Contains(final, "分析完成") || !strings.Contains(final, "blocked_today") {
		t.Fatalf("final text missing tool data: %s", final)
	}
	if usage.PromptTokens != 20 || usage.CompletionTokens != 10 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestAgentStreamRoundTripsAssistantRole(t *testing.T) {
	var reqs []chatAPIRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatAPIRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reqs = append(reqs, req)
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		writeChunk := func(delta map[string]any) {
			chunk := map[string]any{"choices": []any{map[string]any{"delta": delta}}}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			f.Flush()
		}
		if len(reqs) == 1 {
			tc := map[string]any{"index": 0, "id": "c1", "type": "function",
				"function": map[string]any{"name": "get_status", "arguments": "{}"}}
			writeChunk(map[string]any{"tool_calls": []any{tc}})
		} else {
			writeChunk(map[string]any{"content": "done"})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	client, err := NewClient(&cfg.Provider)
	if err != nil {
		t.Fatal(err)
	}
	agent := NewAgent(client, NewToolSet(testSources(), NewSanitizer(SanitizeSettings{Enabled: sbool(true)}, nil)))
	if _, _, err := agent.Run(context.Background(), nil, "状态", nil); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("llm calls = %d, want 2", len(reqs))
	}
	for _, m := range reqs[1].Messages {
		if len(m.ToolCalls) > 0 && m.Role != "assistant" {
			t.Fatalf("streamed assistant tool-call turn round-tripped with role %q, want assistant", m.Role)
		}
	}
}

func TestApplyDefaultsCoverAllInOneUnmarshalPath(t *testing.T) {
	s := &Settings{}
	if err := json.Unmarshal([]byte(`{"enabled":true,"provider":{"template":"custom","base_url":"https://x/v1","model":"m","api_key_env":"K"}}`), s); err != nil {
		t.Fatal(err)
	}
	s.ApplyDefaults()
	if s.Provider.MaxTokens != 4096 || s.Provider.Temperature != 0.2 || s.Provider.TimeoutSec != 120 {
		t.Fatalf("provider defaults not applied: %+v", s.Provider)
	}
	if s.Chat.HistoryTurns != 20 || s.Chat.MaxSessions != 100 || s.Sanitize.PayloadMax != 512 || s.Analysis.MaxTokensPerDay != 200000 || s.MCP.Path != "/mcp" {
		t.Fatalf("section defaults not applied: %+v", s)
	}
}

func TestStoreSessionOwnership(t *testing.T) {
	st, err := OpenStore(t.TempDir() + "/ai.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateSession("s-a", "a", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("s-b", "b", "bob"); err != nil {
		t.Fatal(err)
	}
	own, err := st.SessionOwner("s-a")
	if err != nil || own != "alice" {
		t.Fatalf("owner = %q, %v", own, err)
	}
	all, err := st.ListSessions(10, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("admin list = %d, %v", len(all), err)
	}
	onlyA, err := st.ListSessions(10, "alice")
	if err != nil || len(onlyA) != 1 || onlyA[0].ID != "s-a" {
		t.Fatalf("alice list = %+v, %v", onlyA, err)
	}
}

func TestContextCompressionFallbackClearsHistory(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req chatAPIRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if calls == 1 {
			// compression call fails (upstream unavailable)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"error":{"message":"down"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": "已清空历史，继续"}}}}
		b, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", b)
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	cfg.Chat = ChatSettings{ContextWindowTokens: 120, KeepRecentTurns: 2}
	cfg.ApplyDefaults()
	svc, err := NewService(cfg, testSources(), t.TempDir()+"/ai.db", nil, slog.Default(), config.EmailSettings{})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	for i := 0; i < 6; i++ {
		_ = svc.store.AppendMessage("sx", Message{Role: "user", Content: "历史消息paddingpaddingpaddingpadding"})
		_ = svc.store.AppendMessage("sx", Message{Role: "assistant", Content: "历史回复paddingpaddingpaddingpadding"})
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.HandleChat(w, r, "alice")
	}))
	defer ts.Close()
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{"session_id":"sx","message":"继续聊"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	rows, _ := svc.store.SessionMessages("sx", 100)
	for _, r := range rows {
		if strings.Contains(r.Content, "历史消息") {
			t.Fatalf("old history survived compression fallback: %+v", r)
		}
	}
	if len(rows) < 2 {
		t.Fatalf("session should still continue, rows = %d", len(rows))
	}
}

func TestContextCompressionSummarizesOldTurns(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req chatAPIRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			f := w.(http.Flusher)
			chunk := map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": "ok"}}}}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fmt.Fprint(w, "data: [DONE]\n\n")
			f.Flush()
			return
		}
		// non-stream = compression call
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"摘要：此前讨论了站点配置"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer srv.Close()

	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	cfg.Chat = ChatSettings{ContextWindowTokens: 120, KeepRecentTurns: 2}
	cfg.ApplyDefaults()
	svc, err := NewService(cfg, testSources(), t.TempDir()+"/ai.db", nil, slog.Default(), config.EmailSettings{})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	for i := 0; i < 6; i++ {
		_ = svc.store.AppendMessage("sy", Message{Role: "user", Content: "历史消息paddingpaddingpaddingpadding"})
		_ = svc.store.AppendMessage("sy", Message{Role: "assistant", Content: "历史回复paddingpaddingpaddingpadding"})
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.HandleChat(w, r, "alice")
	}))
	defer ts.Close()
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{"session_id":"sy","message":"继续"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	rows, _ := svc.store.SessionMessages("sy", 100)
	if len(rows) == 0 || rows[0].Role != "system" || !strings.Contains(rows[0].Content, "摘要") {
		t.Fatalf("summary row missing: %+v", rows)
	}
	kept, fresh := 0, false
	for _, r := range rows {
		if r.Role != "user" && r.Role != "assistant" {
			continue
		}
		if strings.Contains(r.Content, "历史") {
			kept++
		} else if r.Role == "user" && r.Content == "继续" {
			fresh = true
		}
	}
	if kept != 4 { // KeepRecentTurns*2
		t.Fatalf("kept turns = %d, want 4", kept)
	}
	if !fresh {
		t.Fatalf("new turn missing after compression: %+v", rows)
	}
}

func TestVisionWireFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatAPIRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		parts, _ := json.Marshal(req.Messages[len(req.Messages)-1].Content)
		partsStr, _ := json.Marshal(string(parts))
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}],"usage":{}}`, partsStr)
	}))
	defer srv.Close()
	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	cfg.ApplyDefaults()
	client, err := NewClient(&cfg.Provider)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Chat(context.Background(), []Message{{
		Role: "user", Content: "这张图里有什么",
		Images: []string{"data:image/png;base64,iVBORw0KGgo="},
	}}, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parts []map[string]any
	if err := json.Unmarshal([]byte(res.Message.Content), &parts); err != nil {
		t.Fatalf("content not a part array: %v (%s)", err, res.Message.Content)
	}
	if len(parts) != 2 || parts[0]["type"] != "text" || parts[1]["type"] != "image_url" {
		t.Fatalf("parts = %+v", parts)
	}
	imgPart := parts[1]["image_url"].(map[string]any)
	if imgPart["url"] != "data:image/png;base64,iVBORw0KGgo=" {
		t.Fatalf("image url lost: %+v", imgPart)
	}
}

func TestStoreSessionsReportsQuota(t *testing.T) {
	st, err := OpenStore(t.TempDir() + "/ai.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateSession("s1", "标题", "alice"); err != nil {
		t.Fatal(err)
	}
	_ = st.AppendMessage("s1", Message{Role: "user", Content: "问题"})
	_ = st.AppendMessage("s1", Message{Role: "assistant", Content: "[NET-1] 有攻击"})
	em := NewEntityMap()
	em.add("NET", "10.0.0.1")
	_ = st.SaveEntities("s1", em)

	msgs, err := st.SessionMessages("s1", 20)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("messages = %d, %v", len(msgs), err)
	}
	em2, err := st.LoadEntities("s1")
	if err != nil {
		t.Fatal(err)
	}
	if em2.Restore("[NET-1] 有攻击") != "10.0.0.1 有攻击" {
		t.Fatalf("entity restore failed: %s", em2.Restore("[NET-1] 有攻击"))
	}

	id, err := st.InsertReport(&ReportRow{Kind: "attack_summary_daily", ContentMD: "报告", Status: "done"})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := st.GetReport(id)
	if err != nil || rep.ContentMD != "报告" {
		t.Fatalf("report readback = %+v, %v", rep, err)
	}

	for i := 0; i < 3; i++ {
		_ = st.AddUsage(10, 5)
	}
	p, c, r := st.UsageToday()
	if p != 30 || c != 15 || r != 3 {
		t.Fatalf("usage = %d/%d/%d", p, c, r)
	}

	sessions, _ := st.ListSessions(10, "")
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("sessions = %+v", sessions)
	}
}
