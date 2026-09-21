package ipgroups

import (
	"os"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestParseList(t *testing.T) {
	data := []byte("# comment\n10.0.0.0/8\n\n192.168.1.1\n  # another\n2001:db8::/32\n")
	nets, err := ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("want 3 nets, got %d", len(nets))
	}
}

func TestParseListBadLine(t *testing.T) {
	_, err := ParseList([]byte("10.0.0.0/8\nnot-a-cidr\n"))
	if err == nil {
		t.Fatal("bad line must error")
	}
}

func TestManagerRefreshFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/list.txt"
	if err := os.WriteFile(p, []byte("10.0.0.0/8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(&config.Config{
		IPGroups: []config.IPGroupSettings{{Name: "test", File: p}},
	}, nil)
	defer m.Close()

	nets := m.Lookup("test")
	if len(nets) != 1 {
		t.Fatalf("want 1 net, got %d", len(nets))
	}
	// unknown group returns empty
	if len(m.Lookup("nope")) != 0 {
		t.Fatal("unknown group must be empty")
	}
}
