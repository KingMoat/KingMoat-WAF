package stages

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/botlib"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/metrics"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// Bot detection score components (v0.1 fixed weights, kept readable).
const (
	botScoreBaseGood    = 10
	botScoreBaseUnknown = 30
	botScoreBaseBad     = 70
	botScoreRateBurst   = 15
	botScoreMissingAccL = 5
	botScoreMissingAcc  = 5
)

// valuesBotClass etc. are the RequestContext keys consumed downstream
// (challenge bypass, audit events, asset collector).
const (
	valuesBotClass = "bot_class"
	valuesBotName  = "bot_name"
	valuesBotScore = "bot_score"
)

// BotDetect classifies every request (UA table + fingerprint + rate signal)
// and applies the per-class site action. The verdict is observe-first:
// allow/observe never changes the request outcome, deny blocks, challenge
// hands the client to the JS-challenge flow with a signed token.
type BotDetect struct {
	byDomain map[string]*botDetectSite
	bot      *BotChallenge // shared challenge signer (may be nil under captcha)
	logger   *slog.Logger
}

type botDetectSite struct {
	actions map[botlib.Class]string
	quota   int
	window  time.Duration
	counter *botlib.RateCounter
}

// NewBotDetect builds the stage; sites without bot_detect config are skipped.
// bot may be nil when the slider captcha replaces the JS challenge; the
// "challenge" action then degrades to observe for those sites.
func NewBotDetect(cfg *config.Config, bot *BotChallenge, logger *slog.Logger) (*BotDetect, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := make(map[string]*botDetectSite)
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.BotDetect == nil || !s.Security.BotDetect.Enabled {
			continue
		}
		bd := s.Security.BotDetect
		actions := map[botlib.Class]string{
			botlib.ClassGood:    "observe",
			botlib.ClassUnknown: "observe",
			botlib.ClassBad:     "observe",
		}
		for class, act := range bd.Actions {
			switch strings.ToLower(class) {
			case "good":
				actions[botlib.ClassGood] = strings.ToLower(act)
			case "unknown":
				actions[botlib.ClassUnknown] = strings.ToLower(act)
			case "bad":
				actions[botlib.ClassBad] = strings.ToLower(act)
			}
		}
		// Without a JS-challenge signer, challenge degrades to observe.
		if bot == nil {
			for class, act := range actions {
				if act == "challenge" {
					actions[class] = "observe"
				}
			}
		}
		quota, window := bd.RateThreshold.Defaults()
		site := &botDetectSite{
			actions: actions,
			quota:   quota,
			window:  window,
			counter: botlib.NewRateCounter(quota, window),
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = site
		}
	}
	return &BotDetect{byDomain: byDomain, bot: bot, logger: logger}, nil
}

// Name implements pipeline.Stage.
func (b *BotDetect) Name() string { return "botdetect" }

// Inspect implements pipeline.Stage. It always records the classification in
// rc.Values and returns allow/observe/deny/challenge per the site policy.
func (b *BotDetect) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true {
		return pipeline.Allow()
	}
	site := b.byDomain[strings.ToLower(rc.Site.Domain)]
	if site == nil {
		return pipeline.Allow()
	}

	r := rc.Request
	res := botlib.Match(r.UserAgent())
	fp := botlib.Fingerprint(clientIP(r).String(), r.UserAgent(), r)
	over := site.counter.Over(fp)
	score := botScore(res.Class, over, r)

	rc.Values[valuesBotClass] = string(res.Class)
	rc.Values[valuesBotName] = res.Name
	rc.Values[valuesBotScore] = score

	metrics.BotRequestsTotal.Inc(rc.Site.Domain, string(res.Class))

	switch site.actions[res.Class] {
	case "allow":
		return pipeline.Allow()
	case "deny":
		metrics.BotDeniedTotal.Inc(rc.Site.Domain)
		return pipeline.Deny("botdetect/"+string(res.Class),
			"bot detection: "+res.Name+" (score "+strconv.Itoa(score)+")")
	case "challenge":
		if b.bot != nil {
			cookie, token, ok := b.bot.challengeFor(rc.Site.Domain, r)
			if ok {
				metrics.BotChallengedTotal.Inc(rc.Site.Domain)
				rc.Values["challenge_cookie"] = cookie
				rc.Values["challenge_token"] = token
				return pipeline.Verdict{
					Action: pipeline.ActionChallenge,
					Status: http.StatusOK,
					Rule:   "botdetect/challenge",
					Reason: "bot detection: challenge " + res.Name,
				}
			}
		}
		return pipeline.Allow()
	default: // observe
		if over {
			b.logger.Debug("botdetect: rate burst observed",
				"site", rc.Site.Domain, "class", res.Class, "name", res.Name)
		}
		return pipeline.Allow()
	}
}

// botScore combines the class baseline with behavioral anomalies.
func botScore(class botlib.Class, rateBurst bool, r *http.Request) int {
	base := botScoreBaseUnknown
	switch class {
	case botlib.ClassGood:
		base = botScoreBaseGood
	case botlib.ClassBad:
		base = botScoreBaseBad
	}
	score := base
	if rateBurst {
		score += botScoreRateBurst
	}
	if r.Header.Get("Accept-Language") == "" {
		score += botScoreMissingAccL
	}
	if r.Header.Get("Accept") == "" {
		score += botScoreMissingAcc
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Labels reads the classification back out of a RequestContext (helper for
// the proxy event builder).
func BotLabels(rc *pipeline.RequestContext) (class, name string, score int) {
	if rc == nil || rc.Values == nil {
		return "", "", 0
	}
	class, _ = rc.Values[valuesBotClass].(string)
	name, _ = rc.Values[valuesBotName].(string)
	score, _ = rc.Values[valuesBotScore].(int)
	return class, name, score
}
