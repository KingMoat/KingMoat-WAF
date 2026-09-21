package stages

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// BotChallenge implements the JS-challenge bot check: browsers execute the
// embedded script, store a signed cookie and reload; clients that cannot
// execute JS keep hitting the challenge. The cookie carries a timestamp
// signed with HMAC-SHA256 over (timestamp|client IP).
type BotChallenge struct {
	byDomain map[string]*botSite
	bypass   map[string]bool // domain → verified good bots skip the challenge
	logger   *slog.Logger
}

type botSite struct {
	secret []byte
	cookie string
	ttl    time.Duration
}

// NewBotChallenge builds the stage; sites without bot config are skipped.
// An empty secret gets a random per-boot value (restarts invalidate cookies).
func NewBotChallenge(cfg *config.Config, logger *slog.Logger) (*BotChallenge, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := make(map[string]*botSite)
	bypass := map[string]bool{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.BotCheck == nil {
			continue
		}
		bs := s.Security.BotCheck
		secret := bs.Secret
		if secret == "" {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return nil, fmt.Errorf("bot: generate secret: %w", err)
			}
			secret = hex.EncodeToString(raw)
			logger.Warn("bot: secret not configured, using random per-boot secret",
				"site", strings.Join(s.Domains, ","))
		}
		ttl := time.Duration(bs.TTLMin) * time.Minute
		if ttl <= 0 {
			ttl = time.Hour
		}
		cookie := bs.CookieName
		if cookie == "" {
			cookie = "km_challenge"
		}
		site := &botSite{secret: []byte(secret), cookie: cookie, ttl: ttl}
		for _, d := range s.Domains {
			domain := strings.ToLower(strings.TrimSpace(d))
			byDomain[domain] = site
			if s.Security.BotDetect != nil && s.Security.BotDetect.GoodBotBypassChallenge {
				bypass[domain] = true
			}
		}
	}
	return &BotChallenge{byDomain: byDomain, bypass: bypass, logger: logger}, nil
}

// Name implements pipeline.Stage.
func (b *BotChallenge) Name() string { return "bot" }

// Inspect implements pipeline.Stage.
func (b *BotChallenge) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if rc.Values["trusted"] == true {
		return pipeline.Allow()
	}
	if class, _ := rc.Values["bot_class"].(string); class == "good" && b.bypass[strings.ToLower(rc.Site.Domain)] {
		return pipeline.Allow()
	}
	site := b.byDomain[strings.ToLower(rc.Site.Domain)]
	if site == nil {
		return pipeline.Allow()
	}

	c, err := rc.Request.Cookie(site.cookie)
	if err == nil && site.valid(c.Value, clientIP(rc.Request)) {
		return pipeline.Allow()
	}

	token := site.sign(time.Now(), clientIP(rc.Request))
	rc.Values["challenge_cookie"] = site.cookie
	rc.Values["challenge_token"] = token
	return pipeline.Verdict{
		Action: pipeline.ActionChallenge,
		Status: http.StatusOK, // challenge pages are served with 200 so browsers run the JS
		Rule:   "bot/challenge",
		Reason: "client must pass the JS challenge",
	}
}

// challengeFor signs a challenge for the botdetect stage ("challenge" action
// on a detected bot). ok=false when the domain has no JS-challenge config.
func (b *BotChallenge) challengeFor(domain string, r *http.Request) (cookie, token string, ok bool) {
	site := b.byDomain[strings.ToLower(domain)]
	if site == nil {
		return "", "", false
	}
	return site.cookie, site.sign(time.Now(), clientIP(r)), true
}

// sign returns hex(ts) + "." + hex(hmac(secret, ts|ip)).
func (s *botSite) sign(ts time.Time, ip net.IP) string {
	tsHex := strconv.FormatInt(ts.Unix(), 16)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(tsHex))
	mac.Write([]byte("|"))
	if ip != nil {
		mac.Write(ip.To16())
	}
	return tsHex + "." + hex.EncodeToString(mac.Sum(nil))
}

// valid checks the signature and the freshness window.
func (s *botSite) valid(token string, ip net.IP) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > s.ttl {
		return false
	}
	expected := s.sign(time.Unix(ts, 0), ip)
	return hmac.Equal([]byte(expected), []byte(token))
}
