package stages

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// --- semantic ---

func TestSemanticBlocksSQLi(t *testing.T) {
	sem := NewSemantic(secCfg(&config.SecuritySettings{
		Semantic: &config.SemanticSettings{Enabled: true},
	}), quiet())
	_, v := run(t, sem, "1.2.3.4:1", `http://t.local/?id=1%27%20union%20select%20password%20from%20users--`, nil)
	if v.Action != pipeline.ActionDeny || v.Rule != "semantic/sqli" {
		t.Fatalf("SQLi not blocked by semantic layer: %+v", v)
	}
}

func TestSemanticAllowsBenign(t *testing.T) {
	sem := NewSemantic(secCfg(&config.SecuritySettings{
		Semantic: &config.SemanticSettings{Enabled: true},
	}), quiet())
	for _, url := range []string{
		"http://t.local/products?id=123&page=2",
		"http://t.local/api/users/42",
		"http://t.local/search?q=hello+world",
	} {
		if _, v := run(t, sem, "1.2.3.4:1", url, nil); v.Action != pipeline.ActionAllow {
			t.Fatalf("benign request blocked: %s → %+v", url, v)
		}
	}
}

func TestSemanticSkipsDisabled(t *testing.T) {
	sem := NewSemantic(secCfg(nil), quiet())
	_, v := run(t, sem, "1.2.3.4:1", `http://t.local/?id=1%27%20union%20select%20*%20from%20t`, nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("disabled semantic stage must allow: %+v", v)
	}
}

// --- site auth ---

func TestSiteAuthAuthorize(t *testing.T) {
	sa, err := NewSiteAuth(secCfg(&config.SecuritySettings{
		Auth: &config.AuthSettings{
			Users: []config.AuthUser{{Username: "ops", Password: "secret123"}},
		},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}

	ok := func(user, pass string) bool {
		r := httptest.NewRequest("GET", "http://t.local/", nil)
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		return sa.Authorize(r)
	}
	if !ok("ops", "secret123") {
		t.Fatal("valid credentials rejected")
	}
	if ok("ops", "wrong") {
		t.Fatal("wrong password accepted")
	}
	if ok("nobody", "secret123") {
		t.Fatal("unknown user accepted")
	}
	if ok("", "") {
		t.Fatal("missing credentials accepted")
	}

	// 401 challenge carries the realm.
	rec := httptest.NewRecorder()
	sa.Challenge(rec, httptest.NewRequest("GET", "http://t.local/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("challenge status = %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Restricted") {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

// --- captcha ---

func TestCaptchaChallengeAndVerify(t *testing.T) {
	cap, err := NewCaptcha(secCfg(&config.SecuritySettings{
		Captcha: &config.CaptchaSettings{Enabled: true, Secret: "test-secret", Tolerance: 8},
	}), quiet())
	if err != nil {
		t.Fatal(err)
	}

	// 1. first request → slider challenge page
	rc, v := run(t, cap, "5.5.5.5:9", "http://t.local/private", nil)
	if v.Action != pipeline.ActionChallenge {
		t.Fatalf("no challenge issued: %+v", v)
	}
	pageHTML, _ := rc.Values["challenge_html"].(string)
	if !strings.Contains(pageHTML, "km-bg") || !strings.Contains(pageHTML, "km-captcha/verify") {
		t.Fatal("challenge page missing slider markup")
	}

	// 2. verify with the exact gap position parsed from the token
	ti := strings.Index(pageHTML, "token=")
	if ti < 0 {
		t.Fatal("token not found in challenge page")
	}
	rest := pageHTML[ti+len("token="):]
	token := rest[:strings.IndexAny(rest, "&\"'")]
	gap, ok := hexVal(strings.Split(token, ".")[0])
	if !ok {
		t.Fatalf("bad token %q", token)
	}

	// wrong position → rejected
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", CaptchaVerifyPath+"?token="+token+"&x=1&back=/private", nil)
	r.Host = "t.local"
	if !cap.HandleVerify(rec, r) || rec.Code != http.StatusForbidden {
		t.Fatalf("wrong drag accepted: code=%d", rec.Code)
	}

	// exact position → pass cookie
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", CaptchaVerifyPath+"?token="+token+"&x="+itoa(int(gap))+"&back=/private", nil)
	r2.Host = "t.local"
	if !cap.HandleVerify(rec2, r2) || rec2.Code != http.StatusOK {
		t.Fatalf("correct drag rejected: code=%d", rec2.Code)
	}
	cookies := rec2.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value == "" {
		t.Fatal("no pass cookie issued")
	}

	// 3. holder of the pass cookie is allowed through
	r3 := httptest.NewRequest("GET", "http://t.local/private", nil)
	r3.AddCookie(cookies[0])
	rc3 := &pipeline.RequestContext{
		Request: r3,
		Site:    pipeline.SiteView{Domain: "t.local"},
		Values:  map[string]any{},
	}
	if v := cap.Inspect(nil, rc3); v.Action != pipeline.ActionAllow {
		t.Fatalf("pass cookie not honored: %+v", v)
	}
}

func TestCaptchaVerifyUnknownSite(t *testing.T) {
	cap, _ := NewCaptcha(secCfg(&config.SecuritySettings{
		Captcha: &config.CaptchaSettings{Enabled: true, Secret: "s"},
	}), quiet())
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", CaptchaVerifyPath, nil)
	r.Host = "other.local"
	if !cap.HandleVerify(rec, r) || rec.Code != http.StatusNotFound {
		t.Fatalf("unknown site verify: code=%d", rec.Code)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
