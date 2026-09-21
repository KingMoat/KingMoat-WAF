package api

import "testing"

// TestEngineVersionsEnginelessFallback guards the ldflags fallback path:
// when debug.ReadBuildInfo() has no coraza/CRS module info, the
// ldflags-injected go.mod versions must keep
// the engine/rule version card populated.
func TestEngineVersionsEnginelessFallback(t *testing.T) {
	oldC, oldR := engineCorazaVersion, engineCRSVersion
	defer func() { engineCorazaVersion, engineCRSVersion = oldC, oldR }()
	engineCorazaVersion = "v3.7.0"
	engineCRSVersion = "v4.25.0"

	out := engineVersions()
	if out["coraza"] == "" || out["crs"] == "" {
		t.Fatalf("engine/rule version missing on engine-less build: %+v", out)
	}
	if out["coraza"] != "v3.7.0" || out["crs"] != "v4.25.0" {
		t.Fatalf("injected versions not honored: %+v", out)
	}
	if out["coraza_release"] != "2026-04" || out["crs_release"] != "2026-03" {
		t.Fatalf("upstream release months wrong: %+v", out)
	}
	if out["geoip"] == "" || out["go"] == "" {
		t.Fatalf("geoip/go info lost: %+v", out)
	}
}
