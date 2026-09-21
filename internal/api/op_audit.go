// Operation audit: records who did what (publish/rollback/user-mgmt) to
// the console's structured audit log, separate from WAF attack events.
package api

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// OpAuditEntry is one management-plane operation record.
type OpAuditEntry struct {
	TS     string `json:"ts"`
	User   string `json:"user"`
	Action string `json:"action"` // publish|rollback|user_create|user_update|user_delete|login
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// opAuditLogger persists operation audit entries as JSONL (append-only).
type opAuditLogger struct {
	mu  sync.Mutex
	dir string
}

func newOpAuditLogger(dir string) *opAuditLogger {
	os.MkdirAll(dir, 0o750)
	return &opAuditLogger{dir: dir}
}

func (a *opAuditLogger) record(e OpAuditEntry) {
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.dir+"/op-audit.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// opAudit is the server-level instance (wired in New).
var opAudit *opAuditLogger

func (s *Server) auditOp(user, action, detail, ip string) {
	if opAudit != nil {
		opAudit.record(OpAuditEntry{User: user, Action: action, Detail: detail, IP: ip})
	}
}
