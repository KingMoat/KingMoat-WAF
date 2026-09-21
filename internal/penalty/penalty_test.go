package penalty

import (
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

func TestPenaltyThresholdBan(t *testing.T) {
	now := time.Now()
	m := New(config.PenaltySettings{
		Enabled: true, WindowSec: 600, Threshold: 3, BanSec: 60, Action: "deny",
	}, nil)
	m.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		m.Observe(logstore.Event{Action: "blocked", ClientIP: "1.2.3.4", Site: "a.local"})
	}
	blocked, reason := m.Check("1.2.3.4")
	if !blocked {
		t.Fatal("expected IP to be banned after threshold")
	}
	if !strings.Contains(reason, "temporarily banned") {
		t.Fatalf("unexpected reason: %q", reason)
	}
	if b, _ := m.Check("5.6.7.8"); b {
		t.Fatal("unrelated IP must not be banned")
	}
	m.Observe(logstore.Event{Action: "monitor", ClientIP: "9.9.9.9"}) // not counted
	if b, _ := m.Check("9.9.9.9"); b {
		t.Fatal("monitor events must not trigger penalties")
	}
	now = now.Add(2 * time.Minute)
	if b, _ := m.Check("1.2.3.4"); b {
		t.Fatal("ban should expire after BanSec")
	}
}

func TestPenaltyDisabled(t *testing.T) {
	m := New(config.PenaltySettings{}, nil)
	for i := 0; i < 100; i++ {
		m.Observe(logstore.Event{Action: "blocked", ClientIP: "1.2.3.4"})
	}
	if b, _ := m.Check("1.2.3.4"); b {
		t.Fatal("disabled engine must not ban")
	}
}

func TestPenaltyThrottle(t *testing.T) {
	now := time.Now()
	m := New(config.PenaltySettings{
		Enabled: true, WindowSec: 600, Threshold: 1, BanSec: 600,
		Action: "throttle", ThrottlePerMin: 2,
	}, nil)
	m.now = func() time.Time { return now }

	m.Observe(logstore.Event{Action: "blocked", ClientIP: "1.2.3.4"})
	if b, _ := m.Check("1.2.3.4"); b {
		t.Fatal("first throttled request should pass")
	}
	if b, _ := m.Check("1.2.3.4"); b {
		t.Fatal("second throttled request should pass")
	}
	blocked, reason := m.Check("1.2.3.4")
	if !blocked {
		t.Fatal("third request within the minute should be blocked")
	}
	if !strings.Contains(reason, "throttle") {
		t.Fatalf("unexpected reason: %q", reason)
	}
	now = now.Add(61 * time.Second)
	if b, _ := m.Check("1.2.3.4"); b {
		t.Fatal("allowance should reset next minute")
	}
}