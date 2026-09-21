// Package store provides the M2 control-plane persistence: a versioned
// configuration store on SQLite (modernc pure-Go driver, no CGO).
// The current configuration is always the highest revision; publishing
// appends a new revision (docs/ARCHITECTURE.md §4.2).
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when the store has no revisions yet.
var ErrNotFound = errors.New("store: no revisions found")

// RevisionMeta describes one configuration revision (without the payload).
type RevisionMeta struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Author    string    `json:"author"`
	Note      string    `json:"note"`
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    author     TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    config     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revisions_created ON revisions(created_at);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    api_key_id         TEXT NOT NULL DEFAULT '',
    api_key_hash       TEXT NOT NULL DEFAULT '',
    api_key_created_at TEXT NOT NULL DEFAULT '',
    api_key_last_used  TEXT NOT NULL DEFAULT '',
    totp_secret   TEXT NOT NULL DEFAULT '',
    totp_pending  TEXT NOT NULL DEFAULT '',
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    must_change   INTEGER NOT NULL DEFAULT 0,
    password_history TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT ''
);
`

// Open opens (and initializes) the configuration database.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // sqlite: serialize writers, avoid busy locks
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: init schema: %w", err)
	}
	if _, err := db.Exec(auditSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: init audit schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrations adds columns introduced after v0.4 to databases created by
// older builds. Fresh databases already contain them via the schema; the
// resulting duplicate-column errors are expected and ignored.
var migrations = []string{
	`ALTER TABLE users ADD COLUMN api_key_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN api_key_hash TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN api_key_created_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN api_key_last_used TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN totp_pending TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN password_changed_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN password_history TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`,
}

func migrate(db *sql.DB) error {
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return nil
}

// AppendRevision validates the JSON payload and appends a new revision,
// returning its id.
func (s *Store) AppendRevision(configJSON, author, note string) (int64, error) {
	if !json.Valid([]byte(configJSON)) {
		return 0, fmt.Errorf("store: invalid config json")
	}
	res, err := s.db.Exec(
		`INSERT INTO revisions(created_at, author, note, config) VALUES(?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), author, note, configJSON)
	if err != nil {
		return 0, fmt.Errorf("store: append revision: %w", err)
	}
	return res.LastInsertId()
}

// CurrentRevision returns the id and JSON payload of the newest revision.
func (s *Store) CurrentRevision() (int64, string, error) {
	row := s.db.QueryRow(`SELECT id, config FROM revisions ORDER BY id DESC LIMIT 1`)
	var id int64
	var cfg string
	if err := row.Scan(&id, &cfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrNotFound
		}
		return 0, "", fmt.Errorf("store: current revision: %w", err)
	}
	return id, cfg, nil
}

// GetRevision returns the JSON payload of a specific revision.
func (s *Store) GetRevision(id int64) (string, error) {
	row := s.db.QueryRow(`SELECT config FROM revisions WHERE id = ?`, id)
	var cfg string
	if err := row.Scan(&cfg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("store: get revision %d: %w", id, err)
	}
	return cfg, nil
}

// ListRevisions returns metadata for the newest `limit` revisions.
func (s *Store) ListRevisions(limit int) ([]RevisionMeta, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, created_at, author, note FROM revisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list revisions: %w", err)
	}
	defer rows.Close()
	var out []RevisionMeta
	for rows.Next() {
		var m RevisionMeta
		var created string
		if err := rows.Scan(&m.ID, &created, &m.Author, &m.Note); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			m.CreatedAt = t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }
