package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestUpdateUserPasswordHistory covers the reuse-prevention bookkeeping:
// with history enabled the replaced hash is recorded (newest first) and
// trimmed to N; with history disabled nothing is recorded.
func TestUpdateUserPasswordHistory(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.CreateUser("alice", "hash-A", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	// history disabled → no records
	if err := s.UpdateUserPassword("alice", "hash-B", 0); err != nil {
		t.Fatal(err)
	}
	if got := s.PasswordHistory("alice"); len(got) != 0 {
		t.Fatalf("history with policy off = %v, want empty", got)
	}
	// history enabled → old hash recorded, trimmed to N
	if err := s.UpdateUserPassword("alice", "hash-C", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserPassword("alice", "hash-D", 2); err != nil {
		t.Fatal(err)
	}
	hist := s.PasswordHistory("alice")
	if len(hist) != 2 || hist[0] != "hash-C" || hist[1] != "hash-B" {
		t.Fatalf("history = %v, want [hash-C hash-B]", hist)
	}
	// active hash is the newest and must NOT appear inside the history list
	cur := ""
	if err := s.db.QueryRow(`SELECT password_hash FROM users WHERE username='alice'`).Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur != "hash-D" {
		t.Fatalf("current hash = %q, want hash-D", cur)
	}
	for _, h := range hist {
		if strings.EqualFold(h, cur) {
			t.Fatalf("history must not contain the active hash: %v", hist)
		}
	}
}
