package stages

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

func excCfg(exceptions []config.Exception) *config.Config {
	return &config.Config{
		Policy: &config.Policy{Exceptions: exceptions},
		Sites: []config.Site{{
			Domains: []string{"t.local"},
			Security: &config.SecuritySettings{Semantic: &config.SemanticSettings{Enabled: true}},
		}},
	}
}

func TestExceptionRuleWhitelistSuppressesSemantic(t *testing.T) {
	x := NewExceptions(excCfg([]config.Exception{
		{Site: "t.local", Path: "/api/search", Prefix: true, RuleID: "semantic/sqli", Comment: "璇姤"},
	}))
	_, v := run(t, x, "1.2.3.4:1", "http://t.local/api/search?q=1%27%20or%20%271%27=%271", nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("exception stage must allow: %+v", v)
	}

	// semantic honors the exception when the exceptions stage runs first
	// (same pipeline order as production).
	cfg := excCfg([]config.Exception{
		{Site: "t.local", Path: "/api/search", Prefix: true, RuleID: "semantic/sqli"},
	})
	runPipeline := func(url string) pipeline.Verdict {
		r := httptest.NewRequest("GET", url, nil)
		rc := &pipeline.RequestContext{Request: r, Site: pipeline.SiteView{Domain: "t.local"}, Values: map[string]any{}}
		if v := NewExceptions(cfg).Inspect(context.Background(), rc); v.Action != pipeline.ActionAllow {
			return v
		}
		return NewSemantic(cfg, quiet()).Inspect(context.Background(), rc)
	}
	if v := runPipeline("http://t.local/api/search?q=1%27%20or%20%271%27=%271"); v.Action != pipeline.ActionAllow {
		t.Fatalf("exception did not suppress semantic rule: %+v", v)
	}
	// other paths still blocked
	if v := runPipeline("http://t.local/other?id=1%27%20or%20%271%27=%271"); v.Action != pipeline.ActionDeny {
		t.Fatalf("non-exception path must still block: %+v", v)
	}
}

func TestExceptionWholePathMarksTrusted(t *testing.T) {
	x := NewExceptions(excCfg([]config.Exception{
		{Site: "t.local", Path: "/internal-api", RuleID: "", Comment: "鍐呯綉鎺ュ彛"},
	}))
	rc, v := run(t, x, "1.2.3.4:1", "http://t.local/internal-api", nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("whole-path exception must allow: %+v", v)
	}
	if rc.Values["trusted"] != true {
		t.Fatal("whole-path exception must mark request trusted")
	}
}

func TestExceptionOtherSiteNotAffected(t *testing.T) {
	x := NewExceptions(excCfg([]config.Exception{
		{Site: "other.local", Path: "/", RuleID: "", Comment: ""},
	}))
	rc, v := run(t, x, "1.2.3.4:1", "http://t.local/anything", nil)
	if v.Action != pipeline.ActionAllow {
		t.Fatalf("exception must allow: %+v", v)
	}
	if rc.Values["trusted"] == true {
		t.Fatal("other site's exception must not mark trusted")
	}
}
