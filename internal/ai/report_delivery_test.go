package ai

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/robfig/cron/v3"
)

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newReportTestService builds a live Service against a mock LLM; sanitize
// nil keeps the tri-state absent (default-on path).
func newReportTestService(t *testing.T, sanitize *bool, emailCfg config.EmailSettings) (*Service, func()) {
	t.Helper()
	calls := 0
	srv := mockLLM(t, &calls)
	cfg := &Settings{Enabled: true}
	cfg.Provider = ProviderSettings{Template: "custom", BaseURL: srv.URL, Model: "mock"}
	cfg.ApplyDefaults()
	if sanitize != nil {
		cfg.Sanitize.Enabled = sanitize
	}
	svc, err := NewService(cfg, testSources(), t.TempDir()+"/ai.db", nil, quietTestLogger(), emailCfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc, srv.Close
}

type capturedEmail struct {
	calls   int
	subject string
	body    string
	to      []string
}

func (f *capturedEmail) Send(subject, body string) error {
	f.subject, f.body = subject, body
	return nil
}

func TestSanitizeSettingsTriState(t *testing.T) {
	if !(SanitizeSettings{}).EnabledOrDefault() {
		t.Fatal("absent enabled must default to true")
	}
	if !(SanitizeSettings{Enabled: sbool(true)}).EnabledOrDefault() {
		t.Fatal("explicit true must stay true")
	}
	if (SanitizeSettings{Enabled: sbool(false)}).EnabledOrDefault() {
		t.Fatal("explicit false must be honored")
	}
}

func TestSanitizerDisabledBypassesCredentialMasking(t *testing.T) {
	s := NewSanitizer(SanitizeSettings{Enabled: sbool(false), MaskCredential: true}, nil)
	if s.Enabled() {
		t.Fatal("explicitly disabled sanitizer must report disabled")
	}
	em := NewEntityMap()
	in := "error trace: password=hunter2secret at 10.0.0.5"
	if out := s.Sanitize(in, em); out != in {
		t.Fatalf("disabled sanitizer must pass through untouched, got %s", out)
	}
}

func TestConfigExposesEffectiveSanitize(t *testing.T) {
	svc, closeSrv := newReportTestService(t, nil, config.EmailSettings{})
	defer closeSrv()
	defer svc.Close()
	if v, _ := svc.Config()["sanitize"].(bool); !v {
		t.Fatalf("absent sanitize must surface as true, got %v", svc.Config()["sanitize"])
	}
	svc2, closeSrv2 := newReportTestService(t, sbool(false), config.EmailSettings{})
	defer closeSrv2()
	defer svc2.Close()
	if v, _ := svc2.Config()["sanitize"].(bool); v {
		t.Fatalf("explicit false must surface as false, got %v", svc2.Config()["sanitize"])
	}
}

func TestAnalysisDefaultsSeedSchedule(t *testing.T) {
	s := &Settings{Analysis: AnalysisSettings{Enabled: true}}
	s.ApplyDefaults()
	if len(s.Analysis.Schedules) != 1 {
		t.Fatalf("seed schedule count = %d, want 1", len(s.Analysis.Schedules))
	}
	seed := s.Analysis.Schedules[0]
	if seed.Kind != "attack_summary_daily" || seed.Cron != "0 8 * * *" || seed.Channel != "webhook" {
		t.Fatalf("seed schedule = %+v", seed)
	}

	custom := &Settings{Analysis: AnalysisSettings{Enabled: true, Schedules: []Schedule{{Kind: "config_review", Cron: "0 9 * * 1"}}}}
	custom.ApplyDefaults()
	if len(custom.Analysis.Schedules) != 1 || custom.Analysis.Schedules[0].Kind != "config_review" {
		t.Fatalf("existing schedules must not be overwritten: %+v", custom.Analysis.Schedules)
	}

	off := &Settings{}
	off.ApplyDefaults()
	if len(off.Analysis.Schedules) != 0 {
		t.Fatalf("disabled analysis must not seed schedules: %+v", off.Analysis.Schedules)
	}
}

// TestScheduleCronAcceptedByParser covers every cron shape the console
// builds from the time picker + weekday checkboxes (all days, ranges,
// single day, comma lists) and one malformed control.
func TestScheduleCronAcceptedByParser(t *testing.T) {
	valid := []string{
		"0 8 * * *",     // all days selected → *
		"30 21 * * 1-5", // Mon–Fri range
		"0 9 * * 0",     // single day (Sunday)
		"15 7 * * 1,3,5", // comma list
		"59 23 * * 6",   // single day (Saturday)
	}
	for _, expr := range valid {
		c := cron.New()
		if _, err := c.AddFunc(expr, func() {}); err != nil {
			t.Errorf("cron %q must parse: %v", expr, err)
		}
	}
	c := cron.New()
	if _, err := c.AddFunc("0 8 * *", func() {}); err == nil {
		t.Error("malformed 4-field cron must be rejected")
	}
}

func TestSplitEmailList(t *testing.T) {
	got := splitEmailList(" a@x.com , b@y.com,,c@z.com ")
	want := []string{"a@x.com", "b@y.com", "c@z.com"}
	if len(got) != len(want) {
		t.Fatalf("split = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("split = %v, want %v", got, want)
		}
	}
	if len(splitEmailList("")) != 0 {
		t.Fatal("empty list must split to none")
	}
}

func TestRunReportDeliveryDispatch(t *testing.T) {
	newSvc := func(t *testing.T, emailCfg config.EmailSettings) (*Service, *capturedEmail, func()) {
		svc, closeSrv := newReportTestService(t, nil, emailCfg)
		fe := &capturedEmail{}
		svc.newEmailer = func(cfg config.EmailSettings) emailSender {
			fe.calls++
			fe.to = cfg.To
			return fe
		}
		return svc, fe, closeSrv
	}

	t.Run("email channel uses schedule recipients", func(t *testing.T) {
		svc, fe, closeSrv := newSvc(t, config.EmailSettings{Enabled: true, Host: "smtp.test", Port: 465, From: "waf@test", To: []string{"ops@test"}})
		defer closeSrv()
		defer svc.Close()
		id, err := svc.RunReport("attack_summary_daily", "test", 24*time.Hour, Delivery{Channel: "email", Email: "a@x.com, b@y.com"})
		if err != nil {
			t.Fatal(err)
		}
		if fe.calls != 1 {
			t.Fatalf("email sender calls = %d, want 1", fe.calls)
		}
		if len(fe.to) != 2 || fe.to[0] != "a@x.com" || fe.to[1] != "b@y.com" {
			t.Fatalf("recipients = %v, want schedule addresses", fe.to)
		}
		if !strings.Contains(fe.subject, "每日") {
			t.Fatalf("subject = %q", fe.subject)
		}
		rep, err := svc.GetReport(id)
		if err != nil || rep.Status != "done" {
			t.Fatalf("report not stored: id=%d err=%v", id, err)
		}
	})

	t.Run("email channel falls back to global to-list", func(t *testing.T) {
		svc, fe, closeSrv := newSvc(t, config.EmailSettings{Enabled: true, Host: "smtp.test", Port: 465, From: "waf@test", To: []string{"ops@test"}})
		defer closeSrv()
		defer svc.Close()
		if _, err := svc.RunReport("attack_summary_daily", "test", 24*time.Hour, Delivery{Channel: "email"}); err != nil {
			t.Fatal(err)
		}
		if fe.calls != 1 || len(fe.to) != 1 || fe.to[0] != "ops@test" {
			t.Fatalf("fallback recipients = %v calls=%d", fe.to, fe.calls)
		}
	})

	t.Run("unconfigured SMTP skips delivery but keeps report", func(t *testing.T) {
		svc, fe, closeSrv := newSvc(t, config.EmailSettings{})
		defer closeSrv()
		defer svc.Close()
		id, err := svc.RunReport("attack_summary_daily", "test", 24*time.Hour, Delivery{Channel: "email", Email: "a@x.com"})
		if err != nil {
			t.Fatal(err)
		}
		if fe.calls != 0 {
			t.Fatalf("unconfigured SMTP must not invoke sender, calls=%d", fe.calls)
		}
		if rep, rerr := svc.GetReport(id); rerr != nil || rep.Status != "done" {
			t.Fatalf("report must still be stored: err=%v", rerr)
		}
	})

	t.Run("webhook channel does not touch email", func(t *testing.T) {
		svc, fe, closeSrv := newSvc(t, config.EmailSettings{Enabled: true, Host: "smtp.test", Port: 465, From: "waf@test", To: []string{"ops@test"}})
		defer closeSrv()
		defer svc.Close()
		wh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer wh.Close()
		if _, err := svc.RunReport("attack_summary_daily", "test", 24*time.Hour, Delivery{Channel: "webhook", Webhook: wh.URL}); err != nil {
			t.Fatal(err)
		}
		if fe.calls != 0 {
			t.Fatalf("webhook channel must not invoke email sender, calls=%d", fe.calls)
		}
	})
}
