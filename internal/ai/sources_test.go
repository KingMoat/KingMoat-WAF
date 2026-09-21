package ai

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// TestNewCenterSourcesWiresEveryField is the assembly-parity anchor: after
// the shared builder runs, EVERY exported field of DataSources must be wired
// (non-zero). If a new field is added to DataSources but not to
// NewCenterSources, this test fails instead of production tools reporting
// "source not wired" (the Logs field was once missed on the standalone
// server exactly this way).
func TestNewCenterSourcesWiresEveryField(t *testing.T) {
	dir := t.TempDir()
	seed := &config.Config{ListenHTTP: ":8080", Sites: []config.Site{}}
	center, err := configcenter.Open(dir+"/cc.db", seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()

	logs, err := logstore.NewSQLiteStore(dir+"/audit.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	logs.Write(&logstore.Event{TS: time.Now().UTC().Format(time.RFC3339Nano), Action: "blocked", Rule: "crs/942100", ClientIP: "8.8.8.8"})
	_ = logs.Flush(5 * time.Second)

	src := NewCenterSources(center, logs, "test-ver", func() map[string]any {
		return map[string]any{"revision": int64(1)}
	})

	v := reflect.ValueOf(*src)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		fv := v.Field(i)
		if fv.IsZero() {
			t.Fatalf("DataSources.%s is not wired by NewCenterSources (assembly-parity violation)", typ.Field(i).Name)
		}
	}

	// Functional spot checks on the shared closures.
	rev, raw := src.Current()
	if rev < 1 || len(raw) == 0 {
		t.Fatalf("Current = %d, %d bytes", rev, len(raw))
	}
	revs, rerr := src.Revisions(5)
	if rerr != nil || len(revs) < 1 {
		t.Fatalf("Revisions = %d rows, err %v", len(revs), rerr)
	}
	if evs := src.Logs.Recent(5); len(evs) != 1 {
		t.Fatalf("Logs.Recent = %d events, want 1", len(evs))
	}
	if q, qerr := src.Logs.Query(logstore.LogQuery{Limit: 5}); qerr != nil || len(q) != 1 {
		t.Fatalf("Logs.Query = %d events, err %v", len(q), qerr)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("Current payload invalid: %v", err)
	}
	if _, ok := probe["listen_http"]; !ok {
		t.Fatalf("Current payload missing config fields: %s", string(raw))
	}
}
