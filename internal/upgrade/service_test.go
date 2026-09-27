package upgrade

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/semver"
)

// testFeed is a canned releases feed with the platform assets for every
// supported target so Check/Start behave identically on any test host.
func testFeed() []Release {
	return []Release{
		{TagName: "release-2026", Draft: false, Body: "not semver"},
		{TagName: "v0.7.8-beta", Body: "older release"},
		{TagName: "v0.7.10-beta", Body: "newest release", Assets: []Asset{
			{Name: "kingmoat_v0.7.10-beta_linux_amd64.tar.gz", BrowserDownloadURL: "https://gitee.com/a/b/releases/download/v0.7.10-beta/kingmoat_v0.7.10-beta_linux_amd64.tar.gz"},
			{Name: "kingmoat_v0.7.10-beta_linux_arm64.tar.gz", BrowserDownloadURL: "https://gitee.com/a/b/kingmoat_v0.7.10-beta_linux_arm64.tar.gz"},
			{Name: "kingmoat_v0.7.10-beta_windows_amd64.zip", BrowserDownloadURL: "https://gitee.com/a/b/kingmoat_v0.7.10-beta_windows_amd64.zip"},
			{Name: "checksums.txt", BrowserDownloadURL: "https://gitee.com/a/b/checksums.txt"},
			{Name: "v0.7.10-beta.tar.gz", BrowserDownloadURL: "https://gitee.com/a/b/v0.7.10-beta.tar.gz"}, // Gitee source archive: must never match
		}},
		{TagName: "v0.7.9-beta", Draft: false},
		{TagName: "v99.0.0", Draft: true}, // draft: filtered
	}
}

// okHooks returns instantly-succeeding stage hooks that record the states
// they observed, so tests can assert the state-machine traversal.
type recorder struct {
	mu     sync.Mutex
	states []string
}

func (r *recorder) record(state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, state)
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}

func successHooks(rec *recorder) []Option {
	return []Option{
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) {
			rec.record(TaskDownloading)
			return "/fake/archive.tar.gz", nil
		}),
		WithVerifier(func(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
			rec.record(TaskVerifying)
			return "/fake/artifact", nil
		}),
		WithReplacer(func(ctx context.Context, t *Task) error { rec.record(TaskReplacing); return nil }),
		WithRestarter(func(ctx context.Context, t *Task) error { rec.record(TaskRestarting); return nil }),
	}
}

// waitTask polls the task until it reaches want (bounded).
func waitTask(t *testing.T, s *Service, id, want string) Task {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if task, ok := s.Task(id); ok && task.State == want {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s in time", id, want)
	return Task{}
}

// TestLatestReleaseSorting covers the local semver sort over the untrusted
// feed order: prerelease ordering (v0.7.10-beta > v0.7.9-beta), draft
// filtering, and skipping tags that are not valid semver.
func TestLatestReleaseSorting(t *testing.T) {
	best, err := latestRelease(testFeed())
	if err != nil {
		t.Fatal(err)
	}
	if best.TagName != "v0.7.10-beta" {
		t.Fatalf("latest = %s, want v0.7.10-beta", best.TagName)
	}
	// A release beats its own prerelease under semver ordering.
	r, err := latestRelease([]Release{
		{TagName: "v1.0.0-beta"}, {TagName: "v1.0.0"},
	})
	if err != nil || r.TagName != "v1.0.0" {
		t.Fatalf("latest = %s, %v; want v1.0.0", r.TagName, err)
	}
	if _, err := latestRelease([]Release{{TagName: "not-a-version"}, {Draft: true, TagName: "v9.9.9"}}); err == nil {
		t.Fatal("latestRelease without usable tags = nil error, want error")
	}
}

// TestNormalizeVersion covers the semver comparability shim.
func TestNormalizeVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v0.7.8-beta", "v0.7.8-beta"}, // released format: unchanged
		{"0.7.8", "v0.7.8"},            // defensive v-prefix
		{"V1.2.3", "v1.2.3"},           // uppercase prefix lowered
		{" v0.7.8-beta ", "v0.7.8-beta"},
		{"dev", "vdev"}, // invalid; callers must reject via semver.IsValid
	}
	for _, tc := range cases {
		if got := normalizeVersion(tc.in); got != tc.want {
			t.Fatalf("normalizeVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if semver.IsValid(normalizeVersion("dev")) {
		t.Fatal("normalizeVersion(dev) must not parse as semver")
	}
}

// TestCheckUpdateAvailable covers the synchronous comparison outcomes.
func TestCheckUpdateAvailable(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) { return testFeed(), nil }))
	res, err := s.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpdateAvailable || res.LatestVersion != "v0.7.10-beta" || res.CurrentVersion != "v0.7.8-beta" {
		t.Fatalf("check = %+v, want update available to v0.7.10-beta", res)
	}
	if res.Notes != "newest release" {
		t.Fatalf("notes = %q", res.Notes)
	}
	if res.AssetsURL == "" || !strings.Contains(res.AssetsURL, "kingmoat_v0.7.10-beta_") {
		t.Fatalf("assets URL = %q, want the platform kingmoat asset (never the Gitee source archive)", res.AssetsURL)
	}

	// Up to date: no upgrade suggested.
	s2 := NewService("v0.7.10-beta", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) { return testFeed(), nil }))
	res2, err := s2.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res2.UpdateAvailable {
		t.Fatalf("check at latest = %+v, want UpdateAvailable=false", res2)
	}

	// Newer than the feed (rolled back feed): no upgrade suggested.
	s3 := NewService("v0.8.0-beta", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) { return testFeed(), nil }))
	res3, err := s3.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res3.UpdateAvailable {
		t.Fatalf("check ahead of feed = %+v, want UpdateAvailable=false", res3)
	}
}

// TestCheckInvalidCurrentVersion covers the dev-build refusal.
func TestCheckInvalidCurrentVersion(t *testing.T) {
	s := NewService("dev", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) { return testFeed(), nil }))
	if _, err := s.Check(context.Background()); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("check with dev build = %v, want ErrInvalidCurrent", err)
	}
	if _, err := s.Start(""); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("start with dev build = %v, want ErrInvalidCurrent", err)
	}
}

// TestCheckNotesTruncation bounds the notes excerpt at 500 runes.
func TestCheckNotesTruncation(t *testing.T) {
	long := strings.Repeat("字", 600)
	s := NewService("v0.7.8-beta", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) {
			return []Release{{TagName: "v0.7.9-beta", Body: long}}, nil
		}))
	res, err := s.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(res.Notes)); got != maxNotesRunes+1 { // +1 = ellipsis
		t.Fatalf("notes runes = %d, want %d", got, maxNotesRunes+1)
	}
	if !strings.HasSuffix(res.Notes, "…") {
		t.Fatalf("notes = %q, want ellipsis suffix", res.Notes)
	}

	short := strings.Repeat("字", 500)
	s2 := NewService("v0.7.8-beta", t.TempDir(), WithChecker(
		func(ctx context.Context) ([]Release, error) {
			return []Release{{TagName: "v0.7.9-beta", Body: short}}, nil
		}))
	res2, err := s2.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Notes != short {
		t.Fatal("notes within the limit must pass through unchanged")
	}
}

// TestFetchReleasesHTTP exercises the real feed transport against an
// httptest server: unsorted JSON is served, sorting happens locally; error
// statuses and malformed payloads fail the fetch.
func TestFetchReleasesHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") != "20" {
			t.Errorf("per_page = %q, want 20", r.URL.Query().Get("per_page"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"tag_name":"v0.7.9-beta"},{"tag_name":"v0.7.10-beta"},{"tag_name":"v0.7.8-beta"}]`)
	}))
	defer srv.Close()

	s := NewService("v0.7.8-beta", t.TempDir(), WithAPIBase(srv.URL))
	releases, err := s.fetchReleases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	best, err := latestRelease(releases)
	if err != nil {
		t.Fatal(err)
	}
	if best.TagName != "v0.7.10-beta" {
		t.Fatalf("latest over HTTP = %s, want v0.7.10-beta", best.TagName)
	}

	// HTTP error status.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusForbidden)
	}))
	defer errSrv.Close()
	sErr := NewService("v0.7.8-beta", t.TempDir(), WithAPIBase(errSrv.URL))
	if _, err := sErr.fetchReleases(context.Background()); err == nil {
		t.Fatal("fetch from a failing endpoint = nil error, want error")
	}

	// Malformed payload.
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>not json</html>")
	}))
	defer badSrv.Close()
	sBad := NewService("v0.7.8-beta", t.TempDir(), WithAPIBase(badSrv.URL))
	if _, err := sBad.fetchReleases(context.Background()); err == nil {
		t.Fatal("fetch of a non-JSON payload = nil error, want error")
	}
}

// TestStartStateMachine walks the full pipeline with succeeding stage
// hooks: detecting → downloading → verifying → replacing → restarting →
// success, with the artifact directory recorded for the replace card.
func TestStartStateMachine(t *testing.T) {
	rec := &recorder{}
	s := NewService("v0.7.8-beta", t.TempDir(), successHooks(rec)...)

	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	if task.CurrentVersion != "v0.7.8-beta" {
		t.Fatalf("task current version = %q", task.CurrentVersion)
	}
	done := waitTask(t, s, task.ID, TaskSuccess)
	if done.Error != "" {
		t.Fatalf("successful task carries error %q", done.Error)
	}
	want := []string{TaskDownloading, TaskVerifying, TaskReplacing, TaskRestarting}
	if got := rec.seen(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stage order = %v, want %v", got, want)
	}
	// Empty target resolves to the newest feed release.
	if done.TargetVersion != "v0.7.10-beta" {
		t.Fatalf("target = %q, want v0.7.10-beta", done.TargetVersion)
	}
	s.mu.Lock()
	dir := s.byID[task.ID].artifactDir
	s.mu.Unlock()
	if dir != "/fake/artifact" {
		t.Fatalf("artifactDir = %q, want /fake/artifact", dir)
	}
}

// TestStartExplicitTarget covers explicit-version starts: a valid newer tag
// proceeds, an older one and an unknown one fail the task.
func TestStartExplicitTarget(t *testing.T) {
	rec := &recorder{}
	s := NewService("v0.7.8-beta", t.TempDir(), successHooks(rec)...)

	task, err := s.Start("v0.7.10-beta")
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, s, task.ID, TaskSuccess)

	// Valid semver but not on the feed → task failed; the failure arms the
	// cooldown, so the remaining refusal scenario gets its own service.
	missing, err := s.Start("v5.0.0-beta")
	if err != nil {
		t.Fatal(err)
	}
	failed2 := waitTask(t, s, missing.ID, TaskFailed)
	if !strings.Contains(failed2.Error, "不在发布列表中") {
		t.Fatalf("unknown-target error = %q", failed2.Error)
	}

	// Malformed target: rejected synchronously.
	if _, err := s.Start("not-a-version"); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("malformed target = %v, want ErrInvalidTarget", err)
	}

	// Equal to current (the feed's v0.7.8-beta): refused during detection.
	s2 := NewService("v0.7.8-beta", t.TempDir(), successHooks(rec)...)
	old, err := s2.Start("v0.7.8-beta")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s2, old.ID, TaskFailed)
	if !strings.Contains(failed.Error, "已是最新版本") {
		t.Fatalf("not-newer-target error = %q", failed.Error)
	}
}

// TestStartSingleFlight: while one upgrade runs, a second Start returns the
// SAME task and the download stage runs exactly once.
func TestStartSingleFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	rec := &recorder{}
	opts := append(successHooks(rec), WithDownloader(
		func(ctx context.Context, t *Task, rel *Release) (string, error) {
			rec.record(TaskDownloading)
			started <- struct{}{}
			<-release
			return "/fake/archive.tar.gz", nil
		}))
	s := NewService("v0.7.8-beta", t.TempDir(), opts...)

	t1, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := s.Start("v0.7.10-beta") // different target, still same task
	if err != nil {
		t.Fatal(err)
	}
	if t1.ID != t2.ID {
		t.Fatalf("single-flight split: %s vs %s", t1.ID, t2.ID)
	}
	<-started // download stage is running
	close(release)
	waitTask(t, s, t1.ID, TaskSuccess)
	if n := len(rec.seen()); n != 4 {
		t.Fatalf("stages recorded %d entries (%v), want exactly one full pass", n, rec.seen())
	}
}

// TestStartFailureCooldown: a failed task arms the cooldown; new starts are
// refused until it expires.
func TestStartFailureCooldown(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) {
			return "", errors.New("download boom")
		}))
	t1, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s, t1.ID, TaskFailed)
	if !strings.Contains(failed.Error, "download boom") {
		t.Fatalf("failed task error = %q", failed.Error)
	}
	if _, err := s.Start(""); !errors.Is(err, ErrCooldown) {
		t.Fatalf("start during cooldown = %v, want ErrCooldown", err)
	}
	// Expire the cooldown: a new task is accepted.
	s.mu.Lock()
	s.cooldown = s.now().Add(-time.Second)
	s.mu.Unlock()
	t2, err := s.Start("")
	if err != nil {
		t.Fatalf("start after cooldown expiry: %v", err)
	}
	waitTask(t, s, t2.ID, TaskFailed)
}

// TestCooldownClockSeam verifies the injectable clock drives the cooldown
// window without real waiting.
func TestCooldownClockSeam(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithNow(func() time.Time { return clock }),
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) {
			return "", errors.New("boom")
		}))
	t1, _ := s.Start("")
	waitTask(t, s, t1.ID, TaskFailed)
	if _, err := s.Start(""); !errors.Is(err, ErrCooldown) {
		t.Fatalf("start during cooldown = %v", err)
	}
	clock = clock.Add(failureCooldown + time.Minute)
	t2, err := s.Start("")
	if err != nil {
		t.Fatalf("start after fast-forwarded cooldown: %v", err)
	}
	waitTask(t, s, t2.ID, TaskFailed)
}

// TestStartReplaceNotConfigured pins the unconfigured-hook guard: since
// T-04/T-06 NewService wires the production defaults, so the nil hooks are
// only reachable via explicit nils (defense in depth) - a task failing at
// such a stage reports a clear internal error instead of hanging.
func TestStartReplaceNotConfigured(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithChecker(func(ctx context.Context) ([]Release, error) { return testFeed(), nil }),
		WithDownloader(func(ctx context.Context, t *Task, rel *Release) (string, error) {
			return "/fake/archive.tar.gz", nil
		}),
		WithVerifier(func(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
			return "/fake/artifact", nil
		}),
		WithReplacer(nil),
		WithRestarter(nil))
	t1, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s, t1.ID, TaskFailed)
	if !strings.Contains(failed.Error, "未配置") {
		t.Fatalf("unconfigured-stage error = %q", failed.Error)
	}
}

// TestHistoryCap: the history keeps the last 10 tasks, newest first, and
// evicted ids disappear from Task().
func TestHistoryCap(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir(), successHooks(&recorder{})...)
	var firstID, lastID string
	for i := 0; i < maxRecentTasks+5; i++ {
		task, err := s.Start("")
		if err != nil {
			t.Fatal(err)
		}
		waitTask(t, s, task.ID, TaskSuccess)
		if i == 0 {
			firstID = task.ID
		}
		lastID = task.ID
	}
	hist := s.History()
	if len(hist) != maxRecentTasks {
		t.Fatalf("history = %d entries, want %d", len(hist), maxRecentTasks)
	}
	if hist[0].ID != lastID {
		t.Fatal("history must be newest first")
	}
	if _, ok := s.Task(firstID); ok {
		t.Fatal("evicted task must no longer be addressable")
	}
}

// TestRunning covers the single-flight accessor used by the status endpoint.
func TestRunning(t *testing.T) {
	release := make(chan struct{})
	s := NewService("v0.7.8-beta", t.TempDir(),
		append(successHooks(&recorder{}), WithDownloader(
			func(ctx context.Context, t *Task, rel *Release) (string, error) {
				<-release
				return "/fake/archive.tar.gz", nil
			}))...)
	if _, ok := s.Running(); ok {
		t.Fatal("no task yet: Running must be false")
	}
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	running, ok := s.Running()
	if !ok || running.ID != task.ID {
		t.Fatalf("Running = %+v ok=%v, want the in-flight task", running, ok)
	}
	close(release)
	waitTask(t, s, task.ID, TaskSuccess)
	if _, ok := s.Running(); ok {
		t.Fatal("finished task must clear single-flight")
	}
}
