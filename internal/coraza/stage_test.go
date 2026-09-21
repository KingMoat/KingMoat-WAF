package coraza

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

var (
	stageOnce sync.Once
	testStage *Stage
	stageErr  error
)

func getStage(t *testing.T) *Stage {
	t.Helper()
	stageOnce.Do(func() {
		cfg := &config.Config{
			ListenHTTP: ":0",
			Sites: []config.Site{
				{Domains: []string{"test.local"}, WAF: &config.WAFSettings{}},
				{Domains: []string{"off.local"}, WAF: &config.WAFSettings{Enabled: boolPtr(false)}},
			},
		}
		testStage, stageErr = New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	if stageErr != nil {
		t.Fatalf("build stage: %v", stageErr)
	}
	return testStage
}

func boolPtr(b bool) *bool { return &b }

func runReq(t *testing.T, domain, method, target string, body []byte, contentType string) pipeline.Verdict {
	t.Helper()
	st := getStage(t)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: domain},
		Values:  map[string]any{},
		Body:    body,
	}
	return st.Inspect(context.Background(), rc)
}

func TestAllowsBenignRequest(t *testing.T) {
	v := runReq(t, "test.local", "GET", "http://test.local/products?id=1&page=2", nil, "")
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("benign request denied: %+v", v)
	}
}

func TestAllowsBenignJSONPost(t *testing.T) {
	v := runReq(t, "test.local", "POST", "http://test.local/api/orders",
		[]byte(`{"item":"widget","qty":3}`), "application/json")
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("benign JSON POST denied: %+v", v)
	}
}

func TestBlocksSQLiInQuery(t *testing.T) {
	v := runReq(t, "test.local", "GET",
		"http://test.local/products?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", nil, "")
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("SQLi in query not denied: %+v", v)
	}
	if v.Rule == "" {
		t.Fatal("denied verdict must carry a rule identifier")
	}
}

func TestBlocksSQLiInFormBody(t *testing.T) {
	v := runReq(t, "test.local", "POST", "http://test.local/login",
		[]byte("username=admin' OR '1'='1'--&password=x"), "application/x-www-form-urlencoded")
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("SQLi in body not denied: %+v", v)
	}
}

func TestBlocksXSSInBody(t *testing.T) {
	v := runReq(t, "test.local", "POST", "http://test.local/comment",
		[]byte("comment=<script>alert(1)</script>"), "application/x-www-form-urlencoded")
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("XSS in body not denied: %+v", v)
	}
}

func TestBlocksPathTraversal(t *testing.T) {
	v := runReq(t, "test.local", "GET",
		"http://test.local/download?file=../../../../etc/passwd", nil, "")
	if v.Action != pipeline.ActionDeny {
		t.Fatalf("path traversal not denied: %+v", v)
	}
}

func TestDisabledSitePassesThrough(t *testing.T) {
	v := runReq(t, "off.local", "GET",
		"http://off.local/products?id=1%20UNION%20SELECT%20password%20FROM%20users", nil, "")
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("WAF-disabled site must forward: %+v", v)
	}
}

func TestUnknownSitePassesThrough(t *testing.T) {
	// A site that never configured WAF routing (defensive: no nil map hit).
	v := runReq(t, "not-configured.local", "GET", "http://not-configured.local/", nil, "")
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("unknown domain must pass: %+v", v)
	}
}
