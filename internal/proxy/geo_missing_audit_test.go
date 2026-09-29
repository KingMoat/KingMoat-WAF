package proxy

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// engineMissingStage is a synthetic stand-in for the geo stage in its
// engine-missing state: it flags the request exactly as stages.Geo does
// (rc.Values["geo_engine_missing"]) and allows — alerting only.
type engineMissingStage struct{}

func (engineMissingStage) Name() string { return "geo" }
func (engineMissingStage) Inspect(_ context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	rc.Values["geo_engine_missing"] = true
	return pipeline.Allow()
}

// TestGeoEngineMissingAuditEvent pins the proxy consumption of the geo side
// channel: a flagged allow must leave exactly one non-blocking monitor
// audit event carrying the geo/engine_missing rule identifier — the
// observable trail for a geo fail-open (production saw zero-trace
// penetration when geo went silent after a hot-reload failure).
func TestGeoEngineMissingAuditEvent(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	store := &captureStore{}
	h, err := New(proxyConfig(trimScheme(up.URL)), pipeline.New(engineMissingStage{}), store, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (the flag must not block)", rec.Code)
	}
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1: %+v", len(events), events)
	}
	if events[0].Rule != "geo/engine_missing" {
		t.Fatalf("rule = %q, want geo/engine_missing", events[0].Rule)
	}
	if events[0].Action != "monitor" {
		t.Fatalf("action = %q, want monitor (non-blocking)", events[0].Action)
	}
	if events[0].Site != "example.com" {
		t.Fatalf("site = %q, want example.com", events[0].Site)
	}
}

// TestGeoEngineMissingAuditNotWrittenWithoutFlag is the negative half: an
// ordinary allow must not write the engine-missing event (no audit noise
// for requests the geo stage did not flag).
func TestGeoEngineMissingAuditNotWrittenWithoutFlag(t *testing.T) {
	up := v3up(t, "ok")
	defer up.Close()

	store := &captureStore{}
	h, err := New(proxyConfig(trimScheme(up.URL)), pipeline.New(fixedStage{name: "plain", v: pipeline.Allow()}), store, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://example.com/", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if events := store.snapshot(); len(events) != 0 {
		t.Fatalf("unflagged allow must not write audit events, got %+v", events)
	}
}
