package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestsBaseMergeAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics-state.json")

	// Seed a base as if a previous run had persisted 100 forwarded requests.
	if err := os.WriteFile(path, []byte(`{"forwarded":100,"blocked":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadRequestsBase(path)

	m := SnapshotRequests()
	if m["forwarded"] < 100 || m["blocked"] < 7 {
		t.Fatalf("base not merged: %+v", m)
	}

	// Persist loop writes base+live to the state file.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go StartRequestsPersist(ctx, path, 50*time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]int64
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted["forwarded"] < 100 || persisted["blocked"] < 7 {
		t.Fatalf("persisted state lost counters: %+v", persisted)
	}

	// Reload in a "new process": the base carries forward.
	LoadRequestsBase(path)
	m2 := SnapshotRequests()
	if m2["forwarded"] < persisted["forwarded"] {
		t.Fatalf("reload dropped counters: %+v", m2)
	}
}

func TestLoadRequestsBaseMissingFile(t *testing.T) {
	LoadRequestsBase(filepath.Join(t.TempDir(), "absent.json")) // must not panic
	m := SnapshotRequests()
	_ = m // fresh start: no base, live counters only
}
