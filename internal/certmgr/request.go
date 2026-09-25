package certmgr

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// IssueFunc performs one issuance attempt for domain and returns the issued
// leaf certificate. The default implementation drives a one-shot
// autocert.Manager against the target cache directory (production or
// staging); tests replace it via WithIssuer so nothing touches the network.
type IssueFunc func(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error)

const (
	// issueTimeout bounds one ACME issuance attempt. Real issuance typically
	// takes 20–90s; slow directory endpoints and autocert-internal retries
	// justify the generous ceiling.
	issueTimeout = 10 * time.Minute
	// maxConcurrentIssues caps ACME issuance goroutines process-wide. The
	// daily renewal pass shares this budget with certificate-library
	// requests so a renewal sweep can never stampede the ACME endpoints.
	maxConcurrentIssues = 2
	// maxRecentTasks bounds the in-memory task history (oldest dropped).
	maxRecentTasks = 50
	// failureCooldown backs off a domain after a failed issuance attempt.
	// Let's Encrypt penalizes repeated failures per account/hostname, so
	// operator retries stay blocked for the window.
	failureCooldown = 10 * time.Minute
)

// Task states as surfaced by the status endpoint.
const (
	TaskPending = "pending"
	TaskRunning = "running"
	TaskSuccess = "success"
	TaskFailed  = "failed"
)

// Sentinel error classes the API layer maps to HTTP statuses.
var (
	ErrInvalidDomain = errors.New("域名格式无效")
	ErrCooldown      = errors.New("签发冷却中")
)

// RequestTask tracks one asynchronous issuance request. Values are copied
// out under the service lock, so API handlers never race the issuing
// goroutine.
type RequestTask struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Staging bool   `json:"staging"`
	Status  string `json:"status"`
	// Reused marks a request answered from a cached certificate (no ACME
	// round-trip happened).
	Reused     bool   `json:"reused,omitempty"`
	Error      string `json:"error,omitempty"`
	CreatedAt  string `json:"created_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`

	// email is the requested contact (json "-": never echoed back); it
	// falls back to the global settings email at issuance time.
	email string `json:"-"`
}

// Service hosts the certificate-library ACME issuance queue (and, from the
// renewal file, the daily proactive renewal pass). It shares the data-plane
// ACMEHolder's cache base so certificates requested here are immediately
// servable by the data plane and rebuilt managers.
type Service struct {
	holder  *ACMEHolder
	base    string
	emailFn func() string // global AcmeEmail fallback (resolved on use)
	issueFn IssueFunc

	mu       sync.Mutex
	tasks    []*RequestTask          // newest first, capped at maxRecentTasks
	byID     map[string]*RequestTask // id → task
	inflight map[string]*RequestTask // key → running task (single-flight)
	cooldown map[string]time.Time    // key → earliest retry after failure
	sem      chan struct{}           // issuance concurrency cap

	// Daily proactive renewal (renewal.go): cancel for the active loop
	// (nil = none), latest result per domain+mode key, and the injectable
	// cadence (tests shorten both via WithRenewalTiming).
	renewCancel     context.CancelFunc
	renewals        map[string]RenewalResult
	renewFirstDelay time.Duration
	renewEvery      time.Duration
}

// Option customizes the service (test seams).
type Option func(*Service)

// WithIssuer replaces the issuance implementation (tests: no network).
func WithIssuer(f IssueFunc) Option {
	return func(s *Service) { s.issueFn = f }
}

// WithRenewalTiming overrides the daily renewal cadence (test seam): first
// run delay after (re)start, then the repeat interval.
func WithRenewalTiming(first, every time.Duration) Option {
	return func(s *Service) { s.renewFirstDelay, s.renewEvery = first, every }
}

// NewService builds the certificate-library service on top of the data-plane
// ACME holder (same cache base). globalEmail resolves the settings-page
// AcmeEmail fallback on every use so hot reloads are honored; nil falls back
// to an empty contact.
func NewService(holder *ACMEHolder, globalEmail func() string, opts ...Option) *Service {
	if holder == nil {
		panic("certmgr: NewService requires a holder")
	}
	s := &Service{
		holder:   holder,
		base:     holder.BaseDir(),
		emailFn:  globalEmail,
		byID:     map[string]*RequestTask{},
		inflight: map[string]*RequestTask{},
		cooldown: map[string]time.Time{},
		sem:      make(chan struct{}, maxConcurrentIssues),

		renewals:        map[string]RenewalResult{},
		renewFirstDelay: defaultRenewFirstDelay,
		renewEvery:      defaultRenewEvery,
	}
	s.issueFn = s.defaultIssue
	for _, o := range opts {
		o(s)
	}
	return s
}

// buildIssueManager assembles a one-shot manager for a single domain against
// one cache directory. Managers are intentionally rebuilt per attempt: the
// request/renewal paths are low-frequency, and reusing the data-plane holder
// would couple issuance to the site-config whitelist, which the
// request-first flow must not depend on.
func buildIssueManager(domain, email string, staging bool, cacheDir string) *autocert.Manager {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Prompt:     autocert.AcceptTOS,
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: stagingDirectoryURL}
	}
	return m
}

// defaultIssue drives the one-shot manager. autocert reads its context
// from hello.Context(), which a synthetic ClientHelloInfo cannot set
// (unexported field), so the issueTimeout is enforced by an outer select:
// on timeout the task fails while the issuance goroutine drains on its own
// (the ACME endpoints apply their own deadlines).
func (s *Service) defaultIssue(ctx context.Context, domain, email string, staging bool) (*x509.Certificate, error) {
	m := buildIssueManager(domain, email, staging, cacheDirFor(s.base, staging))
	type result struct {
		leaf *x509.Certificate
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		if err != nil {
			done <- result{err: err}
			return
		}
		if cert == nil || len(cert.Certificate) == 0 {
			done <- result{err: errors.New("acme: empty certificate chain")}
			return
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			done <- result{err: fmt.Errorf("parse issued certificate: %w", err)}
			return
		}
		done <- result{leaf: leaf}
	}()
	select {
	case r := <-done:
		return r.leaf, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("acme: issuance attempt timed out after %s", issueTimeout)
	}
}

// validateDomain enforces the ACME HTTP-01 scope: a plain lowercase DNS
// hostname, no wildcard (DNS-01 only), no scheme/port/path baggage.
func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("%w: 域名不能为空", ErrInvalidDomain)
	}
	if len(d) > 253 {
		return fmt.Errorf("%w: 域名长度超过 253 字符", ErrInvalidDomain)
	}
	if strings.Contains(d, "*") {
		return fmt.Errorf("%w: 不支持通配符域名（HTTP-01 验证无法签发），请申请单个域名", ErrInvalidDomain)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return fmt.Errorf("%w: 存在空标签", ErrInvalidDomain)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: 标签超过 63 字符", ErrInvalidDomain)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("%w: 含非法字符 %q（仅支持小写字母、数字与连字符）", ErrInvalidDomain, r)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: 标签不能以连字符开头或结尾", ErrInvalidDomain)
		}
	}
	return nil
}

// taskKey namespaces the per-domain bookkeeping by staging mode so a
// production attempt never blocks a staging one.
func taskKey(staging bool, domain string) string {
	if staging {
		return "staging|" + domain
	}
	return "prod|" + domain
}

func newTaskID() string {
	b := make([]byte, 8)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Request submits an asynchronous issuance request for ONE domain. It
// returns the task (existing one on single-flight/cache-idempotent hits,
// freshly created otherwise) or a classified error:
//   - ErrInvalidDomain: malformed domain (wildcards, ports, bad labels);
//   - ErrCooldown: a previous attempt for this domain+mode failed within
//     the cooldown window.
func (s *Service) Request(domain, email string, staging bool) (RequestTask, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return RequestTask{}, err
	}
	key := taskKey(staging, domain)
	now := time.Now()

	s.mu.Lock()
	// Single-flight: an in-flight request for the same domain+mode is
	// returned as-is so concurrent submissions share one task.
	if t := s.inflight[key]; t != nil {
		task := *t
		s.mu.Unlock()
		return task, nil
	}
	// Failure cooldown for the domain+mode.
	if until, ok := s.cooldown[key]; ok && now.Before(until) {
		mins := int(math.Ceil(until.Sub(now).Minutes()))
		s.mu.Unlock()
		return RequestTask{}, fmt.Errorf("%w: 域名 %s 上次签发失败，请约 %d 分钟后再试", ErrCooldown, domain, mins)
	}
	// Cache idempotency: an unexpired certificate well outside the renewal
	// window answers the request without an ACME round-trip, keeping the
	// Let's Encrypt duplicate-certificate rate limit untouched.
	if leaf, err := cachedLeaf(cacheDirFor(s.base, staging), domain); err == nil && leaf.NotAfter.After(now.Add(renewBefore)) {
		t := &RequestTask{
			ID:         newTaskID(),
			Domain:     domain,
			Staging:    staging,
			Status:     TaskSuccess,
			Reused:     true,
			CreatedAt:  rfc3339(now),
			FinishedAt: rfc3339(now),
			NotAfter:   rfc3339(leaf.NotAfter),
		}
		s.addTaskLocked(t)
		task := *t
		s.mu.Unlock()
		return task, nil
	}
	t := &RequestTask{
		ID:        newTaskID(),
		Domain:    domain,
		Staging:   staging,
		Status:    TaskPending,
		CreatedAt: rfc3339(now),
		email:     email,
	}
	s.addTaskLocked(t)
	s.inflight[key] = t
	// Snapshot under the lock: once the goroutine below is scheduled, run()
	// may already be mutating t (Status = running), so copying after the
	// unlock would race it. Mirrors the inflight/cache paths above.
	task := *t
	s.mu.Unlock()

	go s.run(t)
	return task, nil
}

// addTaskLocked registers t (caller holds s.mu), evicting the oldest task
// beyond maxRecentTasks.
func (s *Service) addTaskLocked(t *RequestTask) {
	s.tasks = append([]*RequestTask{t}, s.tasks...)
	s.byID[t.ID] = t
	if len(s.tasks) > maxRecentTasks {
		old := s.tasks[maxRecentTasks]
		delete(s.byID, old.ID)
		// Do not drop an in-flight task from inflight here: eviction only
		// removes it from the history, run() still owns the key.
		s.tasks = s.tasks[:maxRecentTasks]
	}
}

// run executes the issuance for t (single goroutine per task).
func (s *Service) run(t *RequestTask) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.mu.Lock()
	t.Status = TaskRunning
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()
	leaf, err := s.issueFn(ctx, t.Domain, s.emailFor(t.email), t.Staging)

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, taskKey(t.Staging, t.Domain))
	t.FinishedAt = rfc3339(time.Now())
	if err != nil {
		t.Status = TaskFailed
		t.Error = err.Error()
		s.cooldown[taskKey(t.Staging, t.Domain)] = time.Now().Add(failureCooldown)
		return
	}
	t.Status = TaskSuccess
	if leaf != nil {
		t.NotAfter = rfc3339(leaf.NotAfter)
	}
}

// emailFor resolves the contact fallback chain: requested email first, then
// the global settings email (resolved on use so hot reloads apply).
func (s *Service) emailFor(requested string) string {
	if requested != "" {
		return requested
	}
	if s.emailFn != nil {
		return s.emailFn()
	}
	return ""
}

// Task returns a snapshot of the task with the given id.
func (s *Service) Task(id string) (RequestTask, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return RequestTask{}, false
	}
	return *t, true
}

// Entries lists the ACME cert-library entries (both cache directories),
// merged with the latest daily-renewal outcome per entry.
func (s *Service) Entries() []CertEntry {
	entries := CacheEntries(s.base)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range entries {
		e := &entries[i]
		if r, ok := s.renewals[renewalKey(e.Staging, e.Domain)]; ok {
			e.LastRenewalCheck = r.At
			if !r.OK {
				e.LastRenewError = r.Error
			}
		}
	}
	return entries
}
