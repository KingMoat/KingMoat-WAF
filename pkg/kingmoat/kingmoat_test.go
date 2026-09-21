package kingmoat

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/pipeline"
)

type denyStage struct{}

func (denyStage) Name() string { return "test/deny" }
func (denyStage) Inspect(_ context.Context, _ *pipeline.RequestContext) pipeline.Verdict {
	return pipeline.Deny("test/deny", "blocked by test")
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDefaultMonitorForwardsOnDeny(t *testing.T) {
	e := New(Options{
		Logger: quietLogger(),
		Stages: []pipeline.Stage{denyStage{}},
	})
	called := false
	h := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.local/", nil))
	if !called {
		t.Fatal("monitor mode must forward despite deny verdict")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestInterceptBlocksOnDeny(t *testing.T) {
	e := New(Options{
		Mode:   ModeIntercept,
		Logger: quietLogger(),
		Stages: []pipeline.Stage{denyStage{}},
	})
	called := false
	h := e.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.local/", nil))
	if called {
		t.Fatal("intercept mode must not reach the wrapped handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	// Reason must not leak to the client.
	if strings.Contains(rec.Body.String(), "blocked by test") {
		t.Fatal("block page must not leak the internal reason")
	}
}
