package ai

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the ai.db persistence layer: chat sessions, sanitized messages,
// placeholder mappings, reports and daily usage quotas.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS ai_sessions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_calls_json TEXT NOT NULL DEFAULT '',
    tool_call_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_session ON ai_messages(session_id, id);
CREATE TABLE IF NOT EXISTS ai_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    placeholder TEXT NOT NULL,
    original TEXT NOT NULL,
    category TEXT NOT NULL,
    UNIQUE(session_id, placeholder)
);
CREATE TABLE IF NOT EXISTS ai_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    trigger TEXT NOT NULL DEFAULT '',
    window_start TEXT NOT NULL DEFAULT '',
    window_end TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    content_md TEXT NOT NULL DEFAULT '',
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'done',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_usage (
    day TEXT PRIMARY KEY,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0
);
`

// Open opens (and initializes) the AI database.
func OpenStore(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ai: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("ai: init schema: %w", err)
	}
	if err := migrateStore(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("ai: migrate schema: %w", err)
	}
	return &Store{db: db}, nil
}

// migrateStore brings pre-owner databases up to the current schema.
func migrateStore(db *sql.DB) error {
	rows, err := db.Query(`pragma table_info(ai_sessions)`)
	if err != nil {
		return err
	}
	hasOwner := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "owner" {
			hasOwner = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if !hasOwner {
		if _, err := db.Exec(`ALTER TABLE ai_sessions ADD COLUMN owner TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func nowAI() string { return time.Now().UTC().Format(time.RFC3339) }

// CreateSession registers a chat session owned by the console user.
func (s *Store) CreateSession(id, title, owner string) error {
	_, err := s.db.Exec(`INSERT INTO ai_sessions (id, title, owner, created_at, updated_at) VALUES(?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at`, id, title, owner, nowAI(), nowAI())
	return err
}

// TouchSession bumps updated_at.
func (s *Store) TouchSession(id string) error {
	_, err := s.db.Exec(`UPDATE ai_sessions SET updated_at=? WHERE id=?`, nowAI(), id)
	return err
}

// SessionRow is one chat session header.
type SessionRow struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Owner     string    `json:"owner,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListSessions returns recent sessions (newest first). An empty owner
// returns every session (admin view); a named owner returns only their own.
func (s *Store) ListSessions(limit int, owner string) ([]SessionRow, error) {
	q := `SELECT id, title, owner, created_at, updated_at FROM ai_sessions`
	args := []any{}
	if owner != "" {
		q += ` WHERE owner=?`
		args = append(args, owner)
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		var created, updated string
		if err := rows.Scan(&r.ID, &r.Title, &r.Owner, &created, &updated); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionOwner returns the owning console user of one session.
func (s *Store) SessionOwner(id string) (string, error) {
	var owner string
	err := s.db.QueryRow(`SELECT owner FROM ai_sessions WHERE id=?`, id).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("ai: session %s not found", id)
	}
	return owner, err
}

// DeleteSession removes a session with its messages and entities.
func (s *Store) DeleteSession(id string) error {
	for _, q := range []string{
		`DELETE FROM ai_messages WHERE session_id=?`,
		`DELETE FROM ai_entities WHERE session_id=?`,
		`DELETE FROM ai_sessions WHERE id=?`,
	} {
		if _, err := s.db.Exec(q, id); err != nil {
			return err
		}
	}
	return nil
}

// DeleteSessionsOlderThan prunes sessions (with their messages and entity
// maps) whose last update is older than N days. Returns the deleted count.
func (s *Store) DeleteSessionsOlderThan(days int) (int64, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	var ids []string
	rows, err := s.db.Query(`SELECT id FROM ai_sessions WHERE updated_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	var n int64
	for _, id := range ids {
		if err := s.DeleteSession(id); err == nil {
			n++
		}
	}
	return n, nil
}

// AppendMessage persists one message (content in sanitized storage form).
func (s *Store) AppendMessage(sessionID string, m Message) error {
	tc := ""
	if len(m.ToolCalls) > 0 {
		b, err := json.Marshal(m.ToolCalls)
		if err != nil {
			return err
		}
		tc = string(b)
	}
	_, err := s.db.Exec(`INSERT INTO ai_messages (session_id, role, content, tool_calls_json, tool_call_id, created_at)
        VALUES(?,?,?,?,?,?)`, sessionID, m.Role, m.Content, tc, m.ToolCallID, nowAI())
	return err
}

// ReplaceHistory atomically swaps the stored history for a compressed form:
// an optional summary row (role=system) followed by the retained verbatim
// turns. Used by context-window management.
func (s *Store) ReplaceHistory(sessionID, summary string, keep []MessageRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ai_messages WHERE session_id=?`, sessionID); err != nil {
		tx.Rollback()
		return err
	}
	insert := func(role, content, created string) error {
		_, err := tx.Exec(`INSERT INTO ai_messages (session_id, role, content, created_at) VALUES(?,?,?,?)`,
			sessionID, role, content, created)
		return err
	}
	if summary != "" {
		if err := insert("system", summary, nowAI()); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, r := range keep {
		if r.Role != "user" && r.Role != "assistant" {
			continue
		}
		if err := insert(r.Role, r.Content, r.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ClearHistory removes every stored message of the session (the session
// itself survives so the conversation can continue).
func (s *Store) ClearHistory(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM ai_messages WHERE session_id=?`, sessionID)
	return err
}

// MessageRow is one stored message.
type MessageRow struct {
	ID        int64      `json:"id"`
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// SessionMessages returns the conversation history (oldest first), bounded
// to the last limit messages.
func (s *Store) SessionMessages(sessionID string, limit int) ([]MessageRow, error) {
	rows, err := s.db.Query(`SELECT id, role, content, tool_calls_json, created_at FROM
        (SELECT id, role, content, tool_calls_json, created_at FROM ai_messages
         WHERE session_id=? ORDER BY id DESC LIMIT ?) ORDER BY id ASC`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MessageRow
	for rows.Next() {
		var r MessageRow
		var tcJSON, created string
		if err := rows.Scan(&r.ID, &r.Role, &r.Content, &tcJSON, &created); err != nil {
			return nil, err
		}
		if tcJSON != "" {
			_ = json.Unmarshal([]byte(tcJSON), &r.ToolCalls)
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertEntity records a placeholder mapping for the session.
func (s *Store) UpsertEntity(sessionID, placeholder, original, category string) error {
	_, err := s.db.Exec(`INSERT INTO ai_entities (session_id, placeholder, original, category) VALUES(?,?,?,?)
        ON CONFLICT(session_id, placeholder) DO NOTHING`, sessionID, placeholder, original, category)
	return err
}

// LoadEntities rebuilds the session's restore map.
func (s *Store) LoadEntities(sessionID string) (*EntityMap, error) {
	rows, err := s.db.Query(`SELECT placeholder, original FROM ai_entities WHERE session_id=?`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	em := NewEntityMap()
	for rows.Next() {
		var ph, original string
		if err := rows.Scan(&ph, &original); err != nil {
			return nil, err
		}
		em.byPH[ph] = original
	}
	return em, rows.Err()
}

// SaveEntities persists all mappings captured during one turn.
func (s *Store) SaveEntities(sessionID string, em *EntityMap) error {
	if em == nil {
		return nil
	}
	em.mu.Lock()
	defer em.mu.Unlock()
	for ph, original := range em.byPH {
		category := "NET"
		if len(ph) >= 5 && ph[0] == '[' {
			category = ph[1:4]
		}
		if err := s.UpsertEntity(sessionID, ph, original, category); err != nil {
			return err
		}
	}
	return nil
}

// ReportRow is one generated analysis report.
type ReportRow struct {
	ID               int64     `json:"id"`
	Kind             string    `json:"kind"`
	Trigger          string    `json:"trigger"`
	WindowStart      string    `json:"window_start"`
	WindowEnd        string    `json:"window_end"`
	Model            string    `json:"model"`
	ContentMD        string    `json:"content_md"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	Status           string    `json:"status"`
	Error            string    `json:"error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// InsertReport stores a report and returns its id.
func (s *Store) InsertReport(r *ReportRow) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO ai_reports
        (kind, trigger, window_start, window_end, model, content_md, prompt_tokens, completion_tokens, status, error, created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.Kind, r.Trigger, r.WindowStart, r.WindowEnd, r.Model, r.ContentMD,
		r.PromptTokens, r.CompletionTokens, r.Status, r.Error, nowAI())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListReports returns recent reports (headers include content).
func (s *Store) ListReports(limit int) ([]ReportRow, error) {
	rows, err := s.db.Query(`SELECT id, kind, trigger, window_start, window_end, model, content_md,
        prompt_tokens, completion_tokens, status, error, created_at
        FROM ai_reports ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReports(rows)
}

// GetReport fetches one report.
func (s *Store) GetReport(id int64) (*ReportRow, error) {
	rows, err := s.db.Query(`SELECT id, kind, trigger, window_start, window_end, model, content_md,
        prompt_tokens, completion_tokens, status, error, created_at
        FROM ai_reports WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rs, err := scanReports(rows)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("ai: report %d not found", id)
	}
	return &rs[0], nil
}

func scanReports(rows *sql.Rows) ([]ReportRow, error) {
	var out []ReportRow
	for rows.Next() {
		var r ReportRow
		var created string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Trigger, &r.WindowStart, &r.WindowEnd, &r.Model,
			&r.ContentMD, &r.PromptTokens, &r.CompletionTokens, &r.Status, &r.Error, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddUsage accumulates token usage for the (UTC) day.
func (s *Store) AddUsage(prompt, completion int) error {
	day := time.Now().UTC().Format("2006-01-02")
	_, err := s.db.Exec(`INSERT INTO ai_usage (day, prompt_tokens, completion_tokens, requests) VALUES(?,?,?,1)
        ON CONFLICT(day) DO UPDATE SET
            prompt_tokens = prompt_tokens + ?,
            completion_tokens = completion_tokens + ?,
            requests = requests + 1`, day, prompt, completion, prompt, completion)
	return err
}

// UsageToday returns the accumulated usage for the current UTC day.
func (s *Store) UsageToday() (prompt, completion, requests int) {
	day := time.Now().UTC().Format("2006-01-02")
	row := s.db.QueryRow(`SELECT prompt_tokens, completion_tokens, requests FROM ai_usage WHERE day=?`, day)
	var p, c, r int
	_ = row.Scan(&p, &c, &r)
	return p, c, r
}
