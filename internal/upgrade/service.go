// Package upgrade implements the console-driven self-upgrade pipeline:
// release detection against the public Gitee releases feed, asset download
// with mandatory SHA256 verification, and (later cards) binary replacement
// and service restart. The task model mirrors internal/certmgr: async
// tasks, global single-flight, failure cooldown, bounded history.
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	crand "crypto/rand"
	"encoding/hex"

	"golang.org/x/mod/semver"
)

// Task states. detecting → downloading → verifying → replacing →
// restarting → success; every stage may fail the task instead. This card
// wires detecting/downloading/verifying; replace and restart stage hooks
// are filled by later cards.
const (
	TaskDetecting   = "detecting"
	TaskDownloading = "downloading"
	TaskVerifying   = "verifying"
	TaskReplacing   = "replacing"
	TaskRestarting  = "restarting"
	TaskSuccess     = "success"
	TaskFailed      = "failed"
)

const (
	// maxRecentTasks bounds the in-memory task history (oldest dropped);
	// surfaced by History().
	maxRecentTasks = 10
	// failureCooldown blocks new upgrade tasks after a failed attempt.
	// An upgrade touches the running binary, so back-to-back retries of a
	// failing pipeline buy nothing but risk.
	failureCooldown = 10 * time.Minute
	// taskTimeout bounds one whole upgrade task (download of a 200MB
	// archive on a slow link included); each stage runs under it.
	taskTimeout = 20 * time.Minute
	// checkTimeout bounds a single releases-feed fetch. Applied inside
	// fetchReleases so both Check() and the detecting stage are bounded
	// regardless of the caller's context.
	checkTimeout = 30 * time.Second
	// maxReleaseFeedBytes caps the releases feed response (a page of
	// JSON releases; megabytes would mean something is wrong).
	maxReleaseFeedBytes = 4 << 20
)

// Sentinel error classes the API layer (T-07) maps to distinct UI messages.
var (
	ErrCooldown       = errors.New("升级冷却中")
	ErrInvalidTarget  = errors.New("目标版本号无效")
	ErrInvalidCurrent = errors.New("当前版本号无法解析")
)

// Task tracks one asynchronous upgrade attempt. Values are copied out under
// the service lock, so API handlers never race the running goroutine.
type Task struct {
	ID             string `json:"id"`
	State          string `json:"state"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Message        string `json:"message,omitempty"`
	Error          string `json:"error,omitempty"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at,omitempty"`

	// artifactDir is where the verified upgrade payload was unpacked
	// (<dataDir>/upgrade/<task-id>); it feeds the replace card (T-04) and
	// is never echoed to clients.
	artifactDir string `json:"-"`
}

// CheckFunc returns the current releases feed (production: the Gitee feed;
// tests: canned data).
type CheckFunc func(ctx context.Context) ([]Release, error)

// DownloadFunc fetches the platform asset for rel into the task workspace
// and returns the archive path. Contract: on error no artifacts remain.
type DownloadFunc func(ctx context.Context, t *Task, rel *Release) (archivePath string, err error)

// VerifyFunc checks the downloaded archive against the release checksums
// and unpacks the payload binaries, returning the artifact directory.
// Contract: on error no artifacts remain.
type VerifyFunc func(ctx context.Context, t *Task, rel *Release, archivePath string) (artifactDir string, err error)

// ReplaceFunc swaps the running binaries for the verified ones (T-04).
type ReplaceFunc func(ctx context.Context, t *Task) error

// RestartFunc restarts the service fire-and-forget (T-06).
type RestartFunc func(ctx context.Context, t *Task) error

// ProbeFunc reports whether this deployment can swap the running binaries
// and restart the service (production: platform, writable binary directory
// and systemd probe; tests: canned verdicts).
type ProbeFunc func() error

// Service hosts the self-upgrade pipeline. Upgrading is a process-wide
// singleton operation, so single-flight is one global slot (unlike
// certmgr's per-domain keys): a second Start while one task runs returns
// that same task.
type Service struct {
	currentVersion string // ldflags-injected main.version
	baseDir        string // data dir; downloads land in <baseDir>/upgrade/

	mu       sync.Mutex
	tasks    []*Task          // newest first, capped at maxRecentTasks
	byID     map[string]*Task // task id → task
	inflight *Task            // the one running upgrade task (single-flight)
	cooldown time.Time        // new tasks refused before this instant (armed on failure)
	sem      chan struct{}    // serializes upgrade tasks (cap 1)

	// Injectable pipeline stages (test seams; production defaults are
	// wired in NewService).
	checkFn    CheckFunc
	downloadFn DownloadFunc
	verifyFn   VerifyFunc
	replaceFn  ReplaceFunc
	restartFn  RestartFunc

	// Replace capability seams (see replace.go): probeFn overrides the
	// capability probe; binaryDir pins the directory of the running
	// binaries (tests; production derives it from os.Executable).
	probeFn   ProbeFunc
	binaryDir string

	// Releases feed transport (WithAPIBase/WithHTTPClient test seams).
	apiBase    string
	httpClient *http.Client

	// Running platform for asset matching (runtime values; overridden in
	// tests to exercise linux/windows archive paths on one host).
	goos, goarch string

	// allowedHosts restricts download URLs to the release origin (see
	// download.go; overridable in tests that serve assets from httptest).
	allowedHosts []string

	// now is the clock seam used for cooldown arithmetic (tests fast-forward).
	now func() time.Time
}

// Option customizes the service (test seams).
type Option func(*Service)

// WithChecker replaces the releases-feed source (tests: no network).
func WithChecker(f CheckFunc) Option { return func(s *Service) { s.checkFn = f } }

// WithDownloader replaces the download stage (tests: no network).
func WithDownloader(f DownloadFunc) Option { return func(s *Service) { s.downloadFn = f } }

// WithVerifier replaces the verify stage (tests: no network).
func WithVerifier(f VerifyFunc) Option { return func(s *Service) { s.verifyFn = f } }

// WithReplacer replaces the replace stage (wired by T-04).
func WithReplacer(f ReplaceFunc) Option { return func(s *Service) { s.replaceFn = f } }

// WithRestarter replaces the restart stage (wired by T-06).
func WithRestarter(f RestartFunc) Option { return func(s *Service) { s.restartFn = f } }

// WithProber replaces the replace-capability probe (tests: forced verdicts;
// see replace.go for the production probe).
func WithProber(f ProbeFunc) Option { return func(s *Service) { s.probeFn = f } }

// WithBinaryDir pins the directory holding the running kingmoat binaries
// (tests: a fake layout; production: derived from os.Executable).
func WithBinaryDir(dir string) Option { return func(s *Service) { s.binaryDir = dir } }

// WithAPIBase points the releases feed at another origin (tests: httptest).
func WithAPIBase(base string) Option { return func(s *Service) { s.apiBase = base } }

// WithHTTPClient replaces the feed/download HTTP client (tests: httptest
// TLS trust, timeouts).
func WithHTTPClient(c *http.Client) Option { return func(s *Service) { s.httpClient = c } }

// WithNow overrides the clock (tests: cooldown expiry without waiting).
func WithNow(f func() time.Time) Option { return func(s *Service) { s.now = f } }

// WithPlatform overrides the platform used for asset matching (tests).
func WithPlatform(goos, goarch string) Option {
	return func(s *Service) { s.goos, s.goarch = goos, goarch }
}

// WithAllowedHosts replaces the download origin allowlist (tests: httptest
// hosts; see download.go for the production default).
func WithAllowedHosts(hosts []string) Option {
	return func(s *Service) { s.allowedHosts = hosts }
}

// NewService builds the upgrade service on top of the data directory.
// currentVersion is the running binary's ldflags-injected version; dev
// builds ("dev") fail every check/start with ErrInvalidCurrent, since
// upgrade lineage cannot be established.
func NewService(currentVersion, dataDir string, opts ...Option) *Service {
	s := &Service{
		currentVersion: strings.TrimSpace(currentVersion),
		baseDir:        dataDir,
		byID:           map[string]*Task{},
		sem:            make(chan struct{}, 1),
		apiBase:        giteeAPIBase,
		httpClient:     &http.Client{}, // deadlines enforced via context
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
		allowedHosts:   defaultAllowedHosts,
		now:            time.Now,
	}
	s.checkFn = s.fetchReleases
	s.downloadFn = s.downloadRelease
	s.verifyFn = s.verifyDownload
	s.replaceFn = s.defaultReplace
	for _, o := range opts {
		o(s)
	}
	s.cleanupWorkspaces() // drop workspaces left over by previous runs/crashes
	return s
}

// CheckResult is the synchronous version-check outcome.
type CheckResult struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	Notes           string `json:"notes,omitempty"`
	// AssetsURL is the download URL of the platform-matched asset of the
	// latest release (manual-download fallback), empty when none matches.
	AssetsURL string `json:"assets_url,omitempty"`
}

// Check queries the releases feed synchronously and reports whether a newer
// version exists. No caching here — the TTL cache is an API-layer concern
// (T-07: page-open auto check vs. forced manual check).
func (s *Service) Check(ctx context.Context) (CheckResult, error) {
	cur := normalizeVersion(s.currentVersion)
	if !semver.IsValid(cur) {
		return CheckResult{}, fmt.Errorf("%w: %q（开发构建或格式异常），在线升级不可用", ErrInvalidCurrent, s.currentVersion)
	}
	releases, err := s.checkFn(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	latest, err := latestRelease(releases)
	if err != nil {
		return CheckResult{}, err
	}
	res := CheckResult{
		CurrentVersion: s.currentVersion,
		LatestVersion:  latest.TagName,
		Notes:          truncateNotes(latest.Body),
	}
	res.UpdateAvailable = semver.Compare(cur, normalizeVersion(latest.TagName)) < 0
	if asset, err := AssetForPlatform(latest, s.goos, s.goarch); err == nil {
		res.AssetsURL = asset.BrowserDownloadURL
	}
	return res, nil
}

// Start launches an async upgrade task toward targetVersion (empty =
// latest release). Single-flight: while a task runs, every caller receives
// that same task. After a failed task, a cooldown window blocks new starts.
func (s *Service) Start(targetVersion string) (Task, error) {
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion != "" && !semver.IsValid(normalizeVersion(targetVersion)) {
		return Task{}, fmt.Errorf("%w: %q", ErrInvalidTarget, targetVersion)
	}
	s.mu.Lock()
	if s.inflight != nil {
		snap := *s.inflight
		s.mu.Unlock()
		return snap, nil
	}
	if !semver.IsValid(normalizeVersion(s.currentVersion)) {
		s.mu.Unlock()
		return Task{}, fmt.Errorf("%w: %q（开发构建或格式异常），在线升级不可用", ErrInvalidCurrent, s.currentVersion)
	}
	if remaining := s.cooldown.Sub(s.now()); remaining > 0 {
		mins := int(math.Ceil(remaining.Minutes()))
		s.mu.Unlock()
		return Task{}, fmt.Errorf("%w: 上次升级失败，请约 %d 分钟后再试", ErrCooldown, mins)
	}
	t := &Task{
		ID:             newTaskID(),
		State:          TaskDetecting,
		CurrentVersion: s.currentVersion,
		TargetVersion:  targetVersion,
		StartedAt:      rfc3339(s.now()),
	}
	s.addTaskLocked(t)
	s.inflight = t
	// Snapshot under the lock: once the goroutine below is scheduled, run()
	// may already be mutating t, so copying after the unlock would race it.
	// Mirrors certmgr.
	snap := *t
	s.mu.Unlock()

	s.cleanupWorkspaces() // a previous task's workspace is pure residue once a new task starts

	go s.run(t)
	return snap, nil
}

// run drives one upgrade task through the pipeline stages. Any stage
// failure settles the task as failed and arms the retry cooldown.
func (s *Service) run(t *Task) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout)
	defer cancel()

	rel, err := s.stageDetect(ctx, t)
	if err != nil {
		s.finishTask(t, err)
		return
	}
	archivePath, err := s.stageDownload(ctx, t, rel)
	if err != nil {
		s.finishTask(t, err)
		return
	}
	artifactDir, err := s.stageVerify(ctx, t, rel, archivePath)
	if err != nil {
		s.finishTask(t, err)
		return
	}
	s.mu.Lock()
	t.artifactDir = artifactDir
	s.mu.Unlock()

	if err := s.stageReplace(ctx, t); err != nil {
		s.finishTask(t, err)
		return
	}
	if err := s.stageRestart(ctx, t); err != nil {
		s.finishTask(t, err)
		return
	}
	s.finishTask(t, nil)
}

// stageDetect resolves the target release and refuses no-op upgrades
// (current >= target). An empty target means "latest release"; the resolved
// tag is written back onto the task for the API/UI.
func (s *Service) stageDetect(ctx context.Context, t *Task) (*Release, error) {
	s.setState(t, TaskDetecting, "正在检查新版本")
	releases, err := s.checkFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("检查新版本失败: %w", err)
	}
	var rel *Release
	if t.TargetVersion == "" {
		rel, err = latestRelease(releases)
	} else {
		rel, err = findRelease(releases, t.TargetVersion)
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	t.TargetVersion = rel.TagName
	s.mu.Unlock()
	if semver.Compare(normalizeVersion(rel.TagName), normalizeVersion(s.currentVersion)) <= 0 {
		return nil, fmt.Errorf("当前已是最新版本 %s，无需升级", s.currentVersion)
	}
	return rel, nil
}

// stageDownload hands the task to the download stage (default: download.go).
func (s *Service) stageDownload(ctx context.Context, t *Task, rel *Release) (string, error) {
	s.setState(t, TaskDownloading, fmt.Sprintf("正在下载升级包 %s", rel.TagName))
	if s.downloadFn == nil {
		return "", errors.New("升级下载未配置（内部错误）")
	}
	archivePath, err := s.downloadFn(ctx, t, rel)
	if err != nil {
		return "", fmt.Errorf("下载升级包失败: %w", err)
	}
	return archivePath, nil
}

// stageVerify hands the task to the verify stage (default: download.go).
func (s *Service) stageVerify(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
	s.setState(t, TaskVerifying, "正在校验升级包完整性并解包")
	if s.verifyFn == nil {
		return "", errors.New("升级包校验未配置（内部错误）")
	}
	dir, err := s.verifyFn(ctx, t, rel, archivePath)
	if err != nil {
		return "", fmt.Errorf("升级包校验失败: %w", err)
	}
	return dir, nil
}

// stageReplace runs the replace stage hook (T-04).
func (s *Service) stageReplace(ctx context.Context, t *Task) error {
	if s.replaceFn == nil {
		return errors.New("二进制替换未配置（内部错误）")
	}
	s.setState(t, TaskReplacing, "正在替换二进制文件")
	return s.replaceFn(ctx, t)
}

// stageRestart runs the restart stage hook (T-06).
func (s *Service) stageRestart(ctx context.Context, t *Task) error {
	if s.restartFn == nil {
		return errors.New("服务重启未配置（内部错误）")
	}
	s.setState(t, TaskRestarting, "正在重启服务")
	return s.restartFn(ctx, t)
}

// finishTask settles the task (success or failed), releases single-flight
// and arms the cooldown on failure.
func (s *Service) finishTask(t *Task, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight = nil
	t.FinishedAt = rfc3339(s.now())
	if err != nil {
		t.State = TaskFailed
		t.Error = err.Error()
		s.cooldown = s.now().Add(failureCooldown)
		return
	}
	t.State = TaskSuccess
	t.Message = "升级完成"
}

// setState records stage progress on the task.
func (s *Service) setState(t *Task, state, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.State = state
	t.Message = message
}

// addTaskLocked registers t (caller holds s.mu), evicting the oldest task
// beyond maxRecentTasks.
func (s *Service) addTaskLocked(t *Task) {
	s.tasks = append([]*Task{t}, s.tasks...)
	s.byID[t.ID] = t
	if len(s.tasks) > maxRecentTasks {
		old := s.tasks[maxRecentTasks]
		delete(s.byID, old.ID)
		// Do not drop an in-flight task from inflight here: eviction only
		// removes it from the history, run() still owns the slot.
		s.tasks = s.tasks[:maxRecentTasks]
	}
}

// Task returns a snapshot of the task with the given id.
func (s *Service) Task(id string) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return Task{}, false
	}
	return *t, true
}

// Running returns a snapshot of the in-flight task, if any (status endpoint).
func (s *Service) Running() (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight == nil {
		return Task{}, false
	}
	return *s.inflight, true
}

// History returns the most recent tasks, newest first (last 10).
func (s *Service) History() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, *t)
	}
	return out
}

func newTaskID() string {
	b := make([]byte, 8)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
