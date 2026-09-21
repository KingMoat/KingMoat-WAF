package stages

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func botDetectCfg(actions map[string]string, bypass bool) *config.Config {
	return &config.Config{
		ListenHTTP: ":8080",
		Sites: []config.Site{{
			Domains:  []string{"t.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:9001"}}},
			Security: &config.SecuritySettings{
				BotCheck:  &config.BotSettings{Secret: "test-secret"},
				BotDetect: &config.BotDetectSettings{Enabled: true, Actions: actions, GoodBotBypassChallenge: bypass},
			},
		}},
	}
}

func newBotRC(t *testing.T, ua string) *pipeline.RequestContext {
	t.Helper()
	r := httptest.NewRequest("POST", "http://t.local/api/login", nil)
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept-Language", "zh-CN")
	r.Header.Set("Accept", "application/json")
	r.RemoteAddr = "203.0.113.7:4444"
	return &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: "t.local"},
		Values:  map[string]any{},
	}
}

func TestBotDetectObserveDefault(t *testing.T) {
	bd, err := NewBotDetect(botDetectCfg(nil, false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := newBotRC(t, "python-requests/2.31")
	v := bd.Inspect(context.Background(), rc)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("observe default must allow, got %v", v.Action)
	}
	class, name, score := BotLabels(rc)
	if class != "bad" || name != "python-requests" || score <= 0 {
		t.Fatalf("labels = %q/%q/%d", class, name, score)
	}
}

func TestBotDetectDenyBad(t *testing.T) {
	bd, err := NewBotDetect(botDetectCfg(map[string]string{"bad": "deny"}, false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := newBotRC(t, "sqlmap/1.5")
	v := bd.Inspect(context.Background(), rc)
	if v.Action != pipeline.ActionDeny || v.Status != http.StatusForbidden {
		t.Fatalf("deny action = %+v", v)
	}
}

func TestBotDetectGoodBotChallengeBypass(t *testing.T) {
	cfg := botDetectCfg(nil, true)
	bot, err := NewBotChallenge(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := NewBotDetect(cfg, bot, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A verified good bot passes without any challenge.
	rc := newBotRC(t, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if v := bd.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
		t.Fatalf("good bot detect = %v", v.Action)
	}
	if v := bot.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
		t.Fatalf("good bot must bypass the JS challenge, got %v", v.Action)
	}

	// An unknown client still gets the challenge verdict with a signed token.
	rc2 := newBotRC(t, "Mozilla/5.0 Chrome/120.0")
	if v := bd.Inspect(context.Background(), rc2); v.Action != pipeline.ActionAllow {
		t.Fatalf("unknown observe = %v", v.Action)
	}
	v := bot.Inspect(context.Background(), rc2)
	if v.Action != pipeline.ActionChallenge {
		t.Fatalf("unknown client must be challenged, got %v", v.Action)
	}
	if _, ok := rc2.Values["challenge_token"].(string); !ok {
		t.Fatal("challenge token missing")
	}
}

func TestBotDetectChallengeAction(t *testing.T) {
	cfg := botDetectCfg(map[string]string{"bad": "challenge"}, false)
	bot, err := NewBotChallenge(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := NewBotDetect(cfg, bot, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := newBotRC(t, "curl/8.0")
	v := bd.Inspect(context.Background(), rc)
	if v.Action != pipeline.ActionChallenge || v.Rule != "botdetect/challenge" {
		t.Fatalf("challenge action = %+v", v)
	}
	if _, ok := rc.Values["challenge_cookie"]; !ok {
		t.Fatal("challenge cookie missing from rc.Values")
	}
}

func TestBotDetectChallengeDegradesWithoutSigner(t *testing.T) {
	bd, err := NewBotDetect(botDetectCfg(map[string]string{"bad": "challenge"}, false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := newBotRC(t, "curl/8.0")
	if v := bd.Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
		t.Fatalf("challenge must degrade to observe without a signer, got %v", v.Action)
	}
}
