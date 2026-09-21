// Console management change audit: every user/credential/MFA mutation is
// recorded (actor, action, target, detail) for the 变更记录 view.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// ChangeLog is one recorded management operation. Detail never contains
// secrets (passwords, keys, TOTP seeds).
type ChangeLog struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role,omitempty"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

const auditSchema = `
CREATE TABLE IF NOT EXISTS change_logs (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     TEXT NOT NULL,
	actor  TEXT NOT NULL,
	role   TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_change_logs_ts ON change_logs(ts DESC);
`

// RecordChange appends one audit entry.
func (s *Store) RecordChange(actor, role, action, target, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO change_logs(ts, actor, role, action, target, detail) VALUES(?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), actor, role, action, target, detail)
	if err != nil {
		return fmt.Errorf("store: record change: %w", err)
	}
	return nil
}

// ListChangeLogs returns the newest audit entries (bounded).
func (s *Store) ListChangeLogs(limit int) ([]ChangeLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, actor, role, action, target, detail FROM change_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list change logs: %w", err)
	}
	defer rows.Close()
	var out []ChangeLog
	for rows.Next() {
		var c ChangeLog
		var ts string
		if err := rows.Scan(&c.ID, &ts, &c.Actor, &c.Role, &c.Action, &c.Target, &c.Detail); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			c.TS = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
