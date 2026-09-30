package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/stages"
)

// leakTestUpstream starts the minimal upstream the test configs forward to.
func leakTestUpstream(t *testing.T) string {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	return strings.TrimPrefix(up.URL, "http://")
}

// copyTestMMDB copies the repo's embedded country database into a fresh temp
// file so a custom geo db_path opens a REAL closable handle (the empty-path
// embedded singleton is intentionally never closed by Geo.Close).
func copyTestMMDB(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "geoip", "dbip-country-lite.mmdb"))
	if err != nil {
		t.Fatalf("read embedded mmdb fixture: %v", err)
	}
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("write mmdb copy: %v", err)
	}
	return p
}

// sweeperAlive reports whether any RateLimit sweeper goroutine is running.
func sweeperAlive() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "RateLimit).sweeper")
}

// assertSweeperGone fails while a RateLimit sweeper goroutine is still alive:
// the sweeper only exits via RateLimit.Close, so a live sweeper after a
// failed buildState means the rl handle leaked.
func assertSweeperGone(t *testing.T, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !sweeperAlive() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: RateLimit sweeper goroutine still alive — buildState leaked the rl handle", what)
}

// assertMMDBUnlocked fails while the mmdb file cannot be deleted: on Windows
// a mapped (open) mmdb handle blocks deletion, so deletability proves the
// geo handle was closed by the failed build (skipped on other GOOSes, where
// the rl goroutine probe carries the leak proof).
func assertMMDBUnlocked(t *testing.T, path, what string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := os.Remove(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: geo mmdb %s still locked — buildState leaked the geo handle", what, path)
}

// leakTestCfg builds a config whose site carries RateLimit (starts the
// sweeper goroutine) and a custom geo db (opens a closable mmdb handle).
func leakTestCfg(upstream, mmdbPath string) *config.Config {
	cfg := reloadTestCfg(upstream, true)
	cfg.Sites[0].Security.Geo = &config.GeoSettings{
		Enabled:   true,
		DBPath:    mmdbPath,
		Blacklist: []string{"ZZ"}, // never matches: keeps NewGeo behavior deterministic
	}
	return cfg
}

// TestBuildStateFailureClosesStagedHandles is the C10 regression: every
// mid-build failure after geo/rl were built must run state.close() so no
// handle leaks. Two failure shapes are covered — the direct-return branches
// (respFilter) and the state.close() branches (matcher) — plus the success
// path registration completeness.
func TestBuildStateFailureClosesStagedHandles(t *testing.T) {
	up := leakTestUpstream(t)
	logger := testLogger()

	// Success path: geo and rl must be registered as closers the moment they
	// are built, and closing the state really stops the rl sweeper.
	mmdb := copyTestMMDB(t)
	groups := ipgroups.NewManager(leakTestCfg(up, mmdb), logger)
	defer groups.Close()
	st, err := buildState(leakTestCfg(up, mmdb), 1, groups, nil, logger, nil)
	if err != nil {
		t.Fatalf("clean buildState failed: %v", err)
	}
	var hasGeo, hasRL bool
	for _, c := range st.closers {
		switch c.(type) {
		case *stages.Geo:
			hasGeo = true
		case *stages.RateLimit:
			hasRL = true
		}
	}
	if !hasGeo || !hasRL {
		t.Fatalf("success-path closers must contain geo and rl (geo=%v rl=%v)", hasGeo, hasRL)
	}
	if !sweeperAlive() {
		t.Fatal("precondition broken: rate-limited site did not start the sweeper goroutine (probe would be vacuous)")
	}
	st.close() // idempotent for rl; releases the success-path handles
	assertSweeperGone(t, "success-path state.close()")

	// Failure shape 1: respFilter preset error — a direct-return branch.
	mmdb = copyTestMMDB(t)
	cfg := leakTestCfg(up, mmdb)
	cfg.Sites[0].Security.RespFilter = &config.RespFilterSettings{
		Enabled: true,
		Presets: []string{"no-such-preset"},
	}
	groups2 := ipgroups.NewManager(cfg, logger)
	defer groups2.Close()
	if _, err := buildState(cfg, 2, groups2, nil, logger, nil); err == nil {
		t.Fatal("unknown respfilter preset must fail the build")
	}
	assertSweeperGone(t, "respFilter-failure path")
	assertMMDBUnlocked(t, mmdb, "respFilter-failure path")

	// Failure shape 2: matcher regex compile error — a state.close() branch.
	mmdb = copyTestMMDB(t)
	cfg = leakTestCfg(up, mmdb)
	cfg.Policy = &config.Policy{Matchers: []config.MatcherRule{{
		Name:    "bad-regex",
		Enabled: true,
		Action:  "deny",
		Conditions: []config.MatcherCondition{{
			Field: "path",
			Op:    config.OpRegex,
			Value: "(unbalanced",
		}},
	}}}
	groups3 := ipgroups.NewManager(cfg, logger)
	defer groups3.Close()
	if _, err := buildState(cfg, 3, groups3, nil, logger, nil); err == nil {
		t.Fatal("invalid matcher regex must fail the build")
	}
	assertSweeperGone(t, "matcher-failure path")
	assertMMDBUnlocked(t, mmdb, "matcher-failure path")
}
