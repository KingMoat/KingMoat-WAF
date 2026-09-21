package stages

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// CaptchaVerifyPath is the fixed endpoint the slider challenge posts to.
const CaptchaVerifyPath = "/.well-known/km-captcha/verify"

// Captcha is the slider human-verification stage. Unverified clients get a
// self-contained SVG slider page; a successful drag within tolerance issues
// an HMAC-signed pass cookie. When enabled it replaces the JS bot challenge.
type Captcha struct {
	byDomain map[string]*captchaSite
	logger   *slog.Logger
}

type captchaSite struct {
	secret []byte
	cookie string
	ttl    time.Duration
	tol    int
}

// NewCaptcha builds the stage; sites without captcha.enabled are skipped.
func NewCaptcha(cfg *config.Config, logger *slog.Logger) (*Captcha, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := map[string]*captchaSite{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.Captcha == nil || !s.Security.Captcha.Enabled {
			continue
		}
		cs := s.Security.Captcha
		secret := []byte(cs.Secret)
		if len(secret) == 0 {
			secret = make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return nil, fmt.Errorf("captcha: generate secret: %w", err)
			}
		}
		site := &captchaSite{
			secret: secret,
			cookie: cs.CookieName,
			ttl:    time.Duration(cs.TTLMin) * time.Minute,
			tol:    cs.Tolerance,
		}
		if site.cookie == "" {
			site.cookie = "km_captcha"
		}
		if site.ttl <= 0 {
			site.ttl = 60 * time.Minute
		}
		if site.tol <= 0 {
			site.tol = 8
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = site
		}
	}
	return &Captcha{byDomain: byDomain, logger: logger}, nil
}

// Name implements pipeline.Stage.
func (c *Captcha) Name() string { return "captcha" }

// Inspect implements pipeline.Stage: pass-cookie holders proceed, everyone
// else receives the slider challenge. The verify endpoint itself is handled
// by the proxy via HandleVerify (stages have no ResponseWriter).
func (c *Captcha) Inspect(ctx context.Context, rc *pipeline.RequestContext) pipeline.Verdict {
	if trusted, _ := rc.Values["trusted"].(bool); trusted {
		return pipeline.Allow()
	}
	site, ok := c.byDomain[strings.ToLower(rc.Site.Domain)]
	if !ok {
		return pipeline.Allow()
	}
	r := rc.Request

	if ck, err := r.Cookie(site.cookie); err == nil && c.validPass(site, ck.Value) {
		return pipeline.Allow()
	}

	gap, token := c.newChallenge(site)
	rc.Values["challenge_cookie"] = site.cookie
	rc.Values["challenge_kind"] = "slider"
	rc.Values["challenge_html"] = sliderPage(renderSVG(gap), token, r.URL.RequestURI())
	return pipeline.Verdict{Action: pipeline.ActionChallenge, Status: http.StatusOK, Rule: "captcha/slider", Reason: "human verification required"}
}

// HandleVerify serves the verify endpoint. It returns false when the request
// is not for the verify path (the proxy continues normal processing).
func (c *Captcha) HandleVerify(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != CaptchaVerifyPath {
		return false
	}
	site, ok := c.byDomain[strings.ToLower(hostOf(r.Host))]
	if !ok {
		http.NotFound(w, r)
		return true
	}
	q := r.URL.Query()
	back := q.Get("back")
	if back == "" || !strings.HasPrefix(back, "/") {
		back = "/"
	}
	if !c.validAttempt(site, q.Get("token"), atoiSafe(q.Get("x"))) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"ok":false}`)
		return true
	}
	exp := time.Now().Add(site.ttl).Unix()
	val := hexI(exp) + "." + hex.EncodeToString(site.sign("pass|"+strconv.FormatInt(exp, 10)))
	http.SetCookie(w, &http.Cookie{
		Name:     site.cookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(site.ttl.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `{"ok":true}`)
	return true
}

// Handles reports whether the site behind this host has the stage enabled.
func (c *Captcha) Handles(host string) bool {
	_, ok := c.byDomain[strings.ToLower(hostOf(host))]
	return ok
}

func (c *Captcha) validAttempt(site *captchaSite, token string, x int) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || x < 0 {
		return false
	}
	gap, ok := hexVal(parts[0])
	exp, ok2 := hexVal(parts[1])
	if !ok || !ok2 {
		return false
	}
	sig, err := hex.DecodeString(parts[2])
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := site.sign(fmt.Sprintf("chal|%d|%d", gap, exp))
	if !hmac.Equal(sig, want) {
		return false
	}
	diff := x - int(gap)
	if diff < 0 {
		diff = -diff
	}
	return diff <= site.tol
}

func (c *Captcha) newChallenge(site *captchaSite) (int, string) {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	gap := 60 + int(rnd[0])%200 // 60..259 within a 320px track
	exp := time.Now().Add(5 * time.Minute).Unix()
	token := hexI(int64(gap)) + "." + hexI(exp) + "." +
		hex.EncodeToString(site.sign("chal|"+strconv.Itoa(gap)+"|"+strconv.FormatInt(exp, 10)))
	return gap, token
}

func (c *Captcha) validPass(site *captchaSite, val string) bool {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return false
	}
	exp, ok := hexVal(parts[0])
	if !ok || time.Now().Unix() > exp {
		return false
	}
	got, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want := site.sign("pass|" + strconv.FormatInt(exp, 10))
	return hmac.Equal(got, want)
}

func (s *captchaSite) sign(payload string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func hexVal(s string) (int64, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) > 8 || len(b) == 0 {
		return 0, false
	}
	var v int64
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v, true
}

func hexI(v int64) string { return strconv.FormatInt(v, 16) }

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func hostOf(host string) string { return strings.ToLower(strings.TrimSpace(host)) }
