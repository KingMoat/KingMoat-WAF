package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/logstore"
)

// TestGeoStatsEmbeddedFallback verifies that without any configured mmdb the
// geo endpoint falls back to the embedded DB-IP database and classifies a
// blocked public IP.
func TestGeoStatsEmbeddedFallback(t *testing.T) {
	if !geoip.Available() {
		t.Skip("embedded geoip unavailable in test environment")
	}
	dir := t.TempDir()
	st, err := logstore.NewSQLiteStore(filepath.Join(dir, "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Write(&logstore.Event{
		TS: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
		Action: "blocked", Rule: "crs/942100",
		ClientIP: "8.8.8.8", AttackType: "SQL注入",
	})
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s := New(Options{SkipBootstrap: true, Center: mustCenter(t), Logs: st, Auth: NewAuth("")})

	rec := httptest.NewRecorder()
	s.handleGeoStats(rec, httptest.NewRequest("GET", "/api/stats/geo?limit=10", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out struct {
		GeoAvailable bool `json:"geo_available"`
		Items        []struct {
			Country string `json:"country"`
			Count   int    `json:"count"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.GeoAvailable {
		t.Fatalf("embedded fallback did not report geo_available")
	}
	if len(out.Items) == 0 || out.Items[0].Country != "US" {
		t.Fatalf("8.8.8.8 should resolve to US, got %+v", out.Items)
	}
}

// TestGeoStatsIntranetBucketAndTopIPs verifies that intranet attackers are
// merged into a single 本地局域网 bucket (instead of being dropped by the
// mmdb lookup) and that top_ips ranks attacker IPs across both intranet and
// public origins with proper country labels.
func TestGeoStatsIntranetBucketAndTopIPs(t *testing.T) {
	dir := t.TempDir()
	st, err := logstore.NewSQLiteStore(filepath.Join(dir, "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	events := []logstore.Event{
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "8.8.8.8"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "8.8.8.8"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "8.8.4.4"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "192.168.1.10"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "192.168.1.10"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "192.168.1.10"},
		{TS: ts, Action: "blocked", Rule: "crs/942100", ClientIP: "10.0.0.5"},
	}
	for i := range events {
		st.Write(&events[i])
	}
	if err := st.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s := New(Options{SkipBootstrap: true, Center: mustCenter(t), Logs: st, Auth: NewAuth("")})

	rec := httptest.NewRecorder()
	s.handleGeoStats(rec, httptest.NewRequest("GET", "/api/stats/geo?limit=10&hours=24", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out struct {
		GeoAvailable bool `json:"geo_available"`
		Total        int  `json:"total"`
		Items        []struct {
			Country string `json:"country"`
			Count   int    `json:"count"`
		} `json:"items"`
		TopIPs []struct {
			IP      string `json:"ip"`
			Count   int    `json:"count"`
			Country string `json:"country"`
		} `json:"top_ips"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 7 {
		t.Fatalf("total = %d, want 7 (intranet events must still count)", out.Total)
	}
	local, us := 0, 0
	for _, it := range out.Items {
		switch it.Country {
		case "本地局域网":
			local = it.Count
		case "US":
			us += it.Count
		}
	}
	if local != 4 {
		t.Fatalf("intranet bucket = %d, want 4 (192.168.1.10 x3 + 10.0.0.5)", local)
	}
	if us != 3 {
		t.Fatalf("US bucket = %d, want 3 (8.8.8.8 x2 + 8.8.4.4)", us)
	}
	if len(out.TopIPs) == 0 || out.TopIPs[0].IP != "192.168.1.10" || out.TopIPs[0].Count != 3 || out.TopIPs[0].Country != "本地局域网" {
		t.Fatalf("top_ips[0] wrong: %+v", out.TopIPs)
	}
	found := map[string]string{}
	for _, ip := range out.TopIPs {
		found[ip.IP] = ip.Country
	}
	if found["10.0.0.5"] != "本地局域网" {
		t.Fatalf("10.0.0.5 should be 本地局域网, got %q", found["10.0.0.5"])
	}
	if found["8.8.8.8"] != "US" {
		t.Fatalf("8.8.8.8 should be US, got %q", found["8.8.8.8"])
	}
	if len(out.TopIPs) > 5 {
		t.Fatalf("top_ips must cap at 5, got %d", len(out.TopIPs))
	}
}

// TestAttackTypeEnrichment verifies the read-path back-fill for events
// written by older builds (attack_type stored empty).
func TestAttackTypeEnrichment(t *testing.T) {
	evs := []logstore.Event{
		{Rule: "penalty/engine"},
		{Rule: "router/no_site"},
		{Rule: "coraza/rule-949110"},
		{Rule: "matcher/test-rule-1"},
		{Rule: "", AttackType: "保持"},
	}
	out := enrichAttackType(evs)
	want := []string{"攻击惩罚", "扫描探测", "综合评分", "自定义规则", "保持"}
	for i, w := range want {
		if out[i].AttackType != w {
			t.Fatalf("ev[%d] rule=%q: got %q want %q", i, out[i].Rule, out[i].AttackType, w)
		}
	}
}
