// Package api implements the M2 control plane: authenticated REST endpoints
// for configuration publishing (versioned), log inspection and status, plus
// the embedded web console. Routing uses the stdlib 1.22 ServeMux patterns
// (docs/ARCHITECTURE.md 搂4.1).
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"net/http/pprof"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/pquerna/otp/totp"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/certmgr"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/consoletls"
	"github.com/kingmoat/kingmoat/internal/geoip"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/hoststats"
	"github.com/kingmoat/kingmoat/internal/metrics"
	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/stages"
	"github.com/kingmoat/kingmoat/internal/store"
)

// base64RawStd is the alphabet used by standard argon2 encoded hashes.
var base64RawStd = base64.RawStdEncoding

// sessionCookie is the console login cookie name.
const sessionCookie = "km_session"

// sessionTTL is how long a console login stays valid.
const sessionTTL = 12 * time.Hour

// Auth holds the admin password verifier (argon2id encoded hash) and the
// optional TOTP secret for two-factor login. Authenticated clients use
// either HTTP Basic (user: admin, for API scripting) or a session cookie
// (issued by POST /api/login, for the web console).
type Auth struct {
	hash          string
	totpSecret    string
	cookieName    string
	sessionKey    []byte       // HMAC key derived from the password hash
	invalidBefore atomic.Int64 // sessions issued before this unix second are revoked
	ttl           time.Duration // session lifetime (0 = 12h default)
}

// NewAuth builds the authenticator from an argon2id encoded hash
// (generated via `kingmoat-cli hash-password`).
func NewAuth(passwordHash string) *Auth {
	hash := strings.TrimSpace(passwordHash)
	a := &Auth{hash: hash, cookieName: sessionCookie}
	if hash != "" {
		k := sha256.Sum256([]byte("kingmoat-session|" + hash))
		a.sessionKey = k[:]
	}
	return a
}

// armRandom enables console authentication on a fresh install with no
// operator-provided anchor hash (KINGMOAT_ADMIN_HASH unset): the middleware
// must enforce login for the seeded default account. The random value only
// keys session HMACs and can never authenticate the legacy "admin" fallback
// (argon2 verification against it always fails); sessions are invalidated
// by a restart.
func (a *Auth) armRandom() {
	if a == nil || a.hash != "" {
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return
	}
	a.hash = hex.EncodeToString(raw)
	k := sha256.Sum256([]byte("kingmoat-session|" + a.hash))
	a.sessionKey = k[:]
}

// SetSessionTTL overrides the console session lifetime (user management →
// security settings → session timeout). Boot-time snapshot; 0 keeps the 12h
// default. Returns the receiver for chaining.
func (a *Auth) SetSessionTTL(d time.Duration) *Auth {
	if d > 0 {
		a.ttl = d
	}
	return a
}

// SetTOTP enables two-factor verification with a base32 secret
// (KINGMOAT_ADMIN_TOTP).
func (a *Auth) SetTOTP(secret string) *Auth {
	a.totpSecret = strings.TrimSpace(secret)
	return a
}

// TOTPEnabled reports whether 2FA is active.
func (a *Auth) TOTPEnabled() bool { return a != nil && a.totpSecret != "" }

// issueSession signs and sets the console session cookie, carrying the
// account role and username so read/write gating and self-service endpoints
// work without a server-side store. The cookie is marked Secure when the
// request arrived over TLS.
func (a *Auth) issueSession(w http.ResponseWriter, r *http.Request, role, username string) {
	ttl := a.ttl
	if ttl <= 0 {
		ttl = sessionTTL
	}
	iat := time.Now().Unix()
	exp := iat + int64(ttl.Seconds())
	val := fmt.Sprintf("%x.%x.%s.%s.%s", iat, exp, role, username, a.signSession(iat, exp, role, username))
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (a *Auth) signSession(iat, exp int64, role, username string) string {
	m := hmac.New(sha256.New, a.sessionKey)
	fmt.Fprintf(m, "session|%d|%d|%s|%s", iat, exp, role, username)
	return hex.EncodeToString(m.Sum(nil))
}

// sessionIdentity validates a session cookie value and returns its role and
// username.
func (a *Auth) sessionIdentity(val string) (role, username string, ok bool) {
	parts := strings.Split(val, ".")
	if len(parts) != 5 || a.sessionKey == nil {
		return "", "", false
	}
	iat, err1 := strconv.ParseInt(parts[0], 16, 64)
	exp, err2 := strconv.ParseInt(parts[1], 16, 64)
	if err1 != nil || err2 != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	if iat <= a.invalidBefore.Load() {
		return "", "", false // revoked by a logout
	}
	if !store.ValidRole(parts[2]) {
		return "", "", false
	}
	want := a.signSession(iat, exp, parts[2], parts[3])
	if subtle.ConstantTimeCompare([]byte(parts[4]), []byte(want)) != 1 {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// Per-request identity plumbing (set by authMiddleware, read by requireRole).
type userContextKey struct{}

func withUser(ctx context.Context, u *currentUser) context.Context {
	return context.WithValue(ctx, userContextKey{}, u)
}

func userFromContext(r *http.Request) *currentUser {
	u, _ := r.Context().Value(userContextKey{}).(*currentUser)
	return u
}

// verify checks a password against the stored argon2id encoded hash.
func (a *Auth) verify(password string) bool {
	// format: $argon2id$v=19$m=<mem>,t=<time>,p=<par>$<salt-b64>$<hash-b64>
	parts := strings.Split(a.hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var (
		version int
		mem     uint32
		iters   uint32
		par     uint8
	)
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return false
	}
	salt, err := b64Decode(parts[4])
	if err != nil {
		return false
	}
	want, err := b64Decode(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iters, mem, par, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func b64Decode(s string) ([]byte, error) {
	return base64RawStd.DecodeString(s)
}

// LogsStorageInfo describes the audit-log storage posture shown on the
// console logs page: where events live and whether an external sink is
// configured (risk banner when not).
type LogsStorageInfo struct {
	Store                string `json:"store"`
	ExternalConfigured   bool   `json:"external_configured"`
	RetentionDays        int    `json:"retention_days"`
	ArchiveEnabled       bool   `json:"archive_enabled"`
	ArchiveRetentionDays int    `json:"archive_retention_days"`
	// Live query policy (hot-applied on publish; degraded rejects queries).
	QueryDegraded      bool `json:"query_degraded"`
	QueryMaxConcurrent int  `json:"query_max_concurrent"`
	QueryTimeoutMs     int  `json:"query_timeout_ms"`
}

// Options configures the control-plane API server.
type Options struct {
	Center  *configcenter.Center
	Logs    logstore.Queryable
	Auth    *Auth // nil 鈫?auth disabled
	Version string
	WebUI   http.Handler // optional embedded console
	// ConsoleTLS manages the management plane's own HTTPS certificate
	// (self-signed bootstrap + hot-swappable library binding). nil = the
	// /api/console/tls endpoints are not mounted (e.g. all-in-one console).
	ConsoleTLS *consoletls.Manager
	// AccessRing exposes the in-memory recent access-log tail (nil = the
	// access-log page reports the pipeline as off).
	AccessRing *accesslog.Ring
	// LogsStorage carries boot-time audit storage settings for
	// GET /api/logs/storage (nil 鈫?conservative defaults).
	LogsStorage *LogsStorageInfo
	// AIFn returns the live AI assistant service (nil = module disabled);
	// hot-reload swaps the instance when the ai config toggles.
	AIFn func() *ai.Service
	// AIKEKFn returns the key-encryption key guarding the stored provider
	// API key (nil = key storage unavailable, POST/DELETE /api/ai/key fail).
	AIKEKFn func() []byte
	// Assets carries the API-asset / risk module wiring (nil = disabled).
	// Static assemblies (tests, no-reload binaries) only.
	Assets *AssetsOptions
	// AssetsRef is the hot-rebuild container for the module wiring (atomic
	// snapshot pointer). Assemblies that rebuild the collector/engine on
	// every published revision (all-in-one) hands the server
	// this container instead of a mutable shared struct: each request loads
	// exactly one immutable snapshot, so a concurrent publish can neither
	// race an in-flight handler nor split its nil-check → use pair. When set
	// it is authoritative; Options.Assets keeps serving static assemblies.
	AssetsRef *atomic.Pointer[AssetsOptions]
	// PProf exposes net/http/pprof under /debug/pprof/ behind console auth
	// (for load tests and live profiling). Default off.
	PProf bool
	// GeoDBFn returns the GeoIP mmdb path for attack-origin analytics
	// ("" = unavailable).
	GeoDBFn func() string
	// GroupsFn returns the live IP-group subscription manager (nil = none.
	GroupsFn func() *ipgroups.Manager
	// SkipBootstrap disables the first-boot default account seeding
	// (kmadmin + auth arming). Tests set it to exercise exact user-table
	// states; production always leaves it false.
	SkipBootstrap bool
	// ValidatePublish is the pre-publish hook (listener port availability
	// probe from the listener manager). Returning an error rejects the
	// revision with 400 so "port already in use" reaches the user.
	ValidatePublish func(*config.Config) error
	// DisableStateFn returns the CURRENT data-plane build's matcher disable
	// registry for GET /api/policy/disable-state (nil = endpoint reports an
	// empty state, e.g. static assemblies without a reloadable plane).
	DisableStateFn func() *stages.StageDisableRegistry
	// ACME hosts the certificate-library issuance queue (async ACME
	// requests, status queries, cert-library entries; nil = the
	// /api/certs/acme/* endpoints report "not available").
	ACME *certmgr.Service
}

// Server is the control-plane HTTP server.
type Server struct {
	opts     Options
	mux      *http.ServeMux
	groupsFn func() *ipgroups.Manager
	aiFn     func() *ai.Service
	aiKEKFn  func() []byte
	logins   *loginLimiter
	// qInflight counts in-flight audit log queries, bounded by the live
	// config.AuditQuery policy so console scans stay off the forwarding path.
	qInflight atomic.Int64
}

// auditQueryGate applies the live audit-query policy (config.AuditQuery):
// degraded mode rejects every log query, concurrency is capped and each
// query gets a per-request timeout. Returns (release, timeout, ok);
// defer release when ok is true.
func (s *Server) auditQueryGate(cfg *config.Config) (func(), time.Duration, bool) {
	aq := cfg.AuditQuery
	if aq.DegradedOrDefault() {
		return nil, 0, false
	}
	if s.qInflight.Add(1) > int64(aq.MaxConcurrentOrDefault()) {
		s.qInflight.Add(-1)
		return nil, 0, false
	}
	return func() { s.qInflight.Add(-1) }, aq.TimeoutOrDefault(), true
}

// runBoundedQuery executes a log query under the configured timeout and
// writes the JSON response. On timeout it answers 504; the underlying store
// query self-terminates via its own 5s read context, so the goroutine exits.
func (s *Server) runBoundedQuery(w http.ResponseWriter, timeout time.Duration, run func() ([]logstore.Event, error)) bool {
	type result struct {
		events []logstore.Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		evs, err := run()
		done <- result{evs, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			writeErr(w, http.StatusInternalServerError, res.err)
			return false
		}
		writeJSON(w, http.StatusOK, res.events)
		return true
	case <-time.After(timeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{
			"error": "log query timed out; narrow the time range, add filters, or ship logs to an external store for long-term history",
		})
		return false
	}
}

// New assembles routes; the returned Handler() must be wrapped in
// Auth.Middleware by the caller.
func New(opts Options) *Server {
	s := &Server{opts: opts, groupsFn: opts.GroupsFn, aiFn: opts.AIFn, aiKEKFn: opts.AIKEKFn, logins: newLoginLimiter()}
	if !opts.SkipBootstrap {
		s.ensureAdminSeed()
		// Arm console auth whenever no anchor hash is configured, even when
		// the users table already has accounts (restart of a fresh install):
		// without it the middleware would run in dev (auth-free) mode.
		if s.opts.Auth != nil && s.opts.Auth.hash == "" {
			s.opts.Auth.armRandom()
		}
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/host/stats", s.handleHostStats)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("POST /api/config/publish", s.handlePublish)
	mux.HandleFunc("GET /api/policy/disable-state", s.handleDisableState)
	mux.HandleFunc("POST /api/config/site/publish", s.handleSitePublish)
	mux.HandleFunc("GET /api/revisions", s.handleRevisions)
	mux.HandleFunc("POST /api/revisions/{id}/rollback", s.handleRollback)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/logs/export", s.handleLogsExport)
	mux.HandleFunc("GET /api/logs/storage", s.handleLogsStorage)
	mux.HandleFunc("POST /api/logship/test", s.handleLogshipTest)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/stats/trend", s.handleStatsTrend)
	mux.HandleFunc("GET /api/stats/rules", s.handleStatsRules)
	mux.HandleFunc("GET /api/stats/per-site", s.handleStatsPerSite)
	mux.HandleFunc("GET /api/policy/micro-rules/hits", s.handleMicroRuleHits)
	mux.HandleFunc("GET /api/certificates", s.handleCertificates)
	mux.HandleFunc("POST /api/certificates/upload", s.handleCertUpload)
	mux.HandleFunc("GET /api/certificates/uploads", s.handleCertUploads)
	mux.HandleFunc("DELETE /api/certificates/uploads/{name}", s.handleCertUploadDelete)
	mux.HandleFunc("GET /api/certificates/ca", s.handleLocalCAGet)
	mux.HandleFunc("POST /api/certificates/ca", s.handleLocalCACreate)
	mux.HandleFunc("POST /api/certificates/ca/sign", s.handleLocalCASign)
	mux.HandleFunc("POST /api/certs/acme/request", s.handleACMERequest)
	mux.HandleFunc("GET /api/certs/acme/request", s.handleACMERequestStatus)
	mux.HandleFunc("GET /api/certs/acme/entries", s.handleACMEEntries)
	if opts.ConsoleTLS != nil {
		mux.HandleFunc("GET /api/console/tls", s.handleConsoleTLSGet)
		mux.HandleFunc("POST /api/console/tls", s.handleConsoleTLSApply)
	}
	mux.HandleFunc("GET /api/stats/geo", s.handleGeoStats)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)

	// Console user management (RBAC, admin only) + per-role gating on the
	// write endpoints (operator may publish/rollback; auditor is read-only).
	mux.HandleFunc("GET /api/users", s.handleUserList)
	mux.HandleFunc("POST /api/users", s.handleUserCreate)
	mux.HandleFunc("PATCH /api/users/{username}", s.handleUserUpdate)
	mux.HandleFunc("POST /api/users/{username}/reset-password", s.handleUserResetPassword)
	mux.HandleFunc("DELETE /api/users/{username}", s.handleUserDelete)
	// Per-user credentials: API keys and TOTP MFA enrollment.
	mux.HandleFunc("POST /api/users/{username}/apikey", s.handleUserAPIKeyCreate)
	mux.HandleFunc("DELETE /api/users/{username}/apikey", s.handleUserAPIKeyDelete)
	mux.HandleFunc("POST /api/users/{username}/mfa/setup", s.handleUserMFASetup)
	mux.HandleFunc("POST /api/users/{username}/mfa/confirm", s.handleUserMFAConfirm)
	mux.HandleFunc("DELETE /api/users/{username}/mfa", s.handleUserMFADisable)
	// Self-service credentials for any signed-in account + change audit.
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/me/password", s.handleMePassword)
	mux.HandleFunc("GET /api/access_logs", s.handleAccessLogs)
	mux.HandleFunc("POST /api/me/apikey", s.handleMeAPIKeyCreate)
	mux.HandleFunc("DELETE /api/me/apikey", s.handleMeAPIKeyDelete)
	mux.HandleFunc("POST /api/me/mfa/setup", s.handleMeMFASetup)
	mux.HandleFunc("POST /api/me/mfa/confirm", s.handleMeMFAConfirm)
	mux.HandleFunc("DELETE /api/me/mfa", s.handleMeMFADisable)
	mux.HandleFunc("GET /api/audit/changes", s.handleAuditList)
	if opts.PProf {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	// API asset & risk module.
	mux.HandleFunc("GET /api/assets/apis", s.handleAssetList)
	mux.HandleFunc("GET /api/assets/apis/{id}", s.handleAssetGet)
	mux.HandleFunc("POST /api/assets/apis/{id}/ignore", s.handleAssetIgnore)
	mux.HandleFunc("GET /api/assets/sites", s.handleAssetSites)
	mux.HandleFunc("GET /api/risks", s.handleRiskList)
	mux.HandleFunc("POST /api/risks/scan", s.handleRiskScan)
	mux.HandleFunc("POST /api/risks/{id}/status", s.handleRiskStatus)

	// Strategy console: one-click whitelist (creates a micro-engine allow
	// rule) and IP-group subscriptions. Mutations publish a new revision.
	// The legacy false-positive exceptions endpoints are deprecated and kept
	// only for migration of existing entries.
	mux.HandleFunc("POST /api/policy/whitelist", s.handlePolicyWhitelist)
	mux.HandleFunc("GET /api/policy/exceptions", s.handleExceptionList)
	mux.HandleFunc("POST /api/policy/exceptions", s.handleExceptionCreate)
	mux.HandleFunc("DELETE /api/policy/exceptions/{index}", s.handleExceptionDelete)
	mux.HandleFunc("GET /api/ipgroups", s.handleIPGroupList)
	mux.HandleFunc("POST /api/ipgroups/{name}/refresh", s.handleIPGroupRefresh)

	// AI assistant (read-only) + optional MCP endpoint.
	mux.HandleFunc("GET /api/ai/config", s.handleAIConfig)
	// AI provider key management (admin only; stores hash + KEK-encrypted
	// copy in the active config, plaintext never leaves memory).
	mux.HandleFunc("POST /api/ai/key", s.handleAIKeySet)
	mux.HandleFunc("DELETE /api/ai/key", s.handleAIKeyDelete)
	mux.HandleFunc("POST /api/ai/chat", s.handleAIChat)
	mux.HandleFunc("GET /api/ai/sessions", s.handleAISessions)
	mux.HandleFunc("GET /api/ai/sessions/{id}/messages", s.handleAISessionMessages)
	mux.HandleFunc("DELETE /api/ai/sessions/{id}", s.handleAISessionDelete)
	mux.HandleFunc("GET /api/ai/reports", s.handleAIReports)
	mux.HandleFunc("GET /api/ai/reports/{id}", s.handleAIReportGet)
	mux.HandleFunc("POST /api/ai/reports/run", s.handleAIReportRun)
	// AI MCP endpoint: mounted statically, forwarded at runtime so the
	// handler follows hot-rebuilt assistant instances.
	mux.HandleFunc("POST /mcp", s.handleMCPForward)
	mux.HandleFunc("GET /mcp", s.handleMCPForward)
	mux.HandleFunc("DELETE /mcp", s.handleMCPForward)

	if opts.WebUI != nil {
		mux.Handle("GET /{$}", opts.WebUI)
		mux.Handle("GET /ui/", opts.WebUI)
		mux.Handle("GET /", opts.WebUI)
	}
	s.mux = mux
	return s
}

// Handler returns the authenticated root handler with per-request identity
// resolution (session role or basic credentials) attached to the context.
func (s *Server) Handler() http.Handler {
	return s.authMiddleware(s.mux)
}

// authMiddleware enforces console authentication and resolves the acting
// identity into the request context. POST /api/login and /api/logout stay
// reachable without console credentials.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Management-plane IP restriction (settings page; hot-reloaded with
		// the active config). Empty list = no restriction. Applies to every
		// console request including login.
		_, ccfg := s.opts.Center.Current()
		if ccfg.Console != nil && len(ccfg.Console.AllowedIPs) > 0 {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !ipAllowed(ip, ccfg.Console.AllowedIPs) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		a := s.opts.Auth
		if a == nil || a.hash == "" {
			next.ServeHTTP(w, r) // auth disabled (dev mode) 鈥?warn at startup
			return
		}
		p := r.URL.Path
		if (p == "/api/login" && r.Method == http.MethodPost) ||
			(p == "/api/logout" && r.Method == http.MethodPost) {
			next.ServeHTTP(w, r)
			return
		}
		// Static SPA assets load without credentials (the login view lives
		// there); every API surface, the OpenAPI document, MCP, pprof and
		// /metrics stay gated behind console authentication.
		if r.Method == http.MethodGet && !strings.HasPrefix(p, "/api/") &&
			p != "/mcp" && p != "/metrics" && p != "/openapi.json" &&
			!strings.HasPrefix(p, "/debug/pprof/") {
			next.ServeHTTP(w, r)
			return
		}
		u := s.identify(r)
		if u == nil {
			// Browsers get a plain 401 the SPA turns into the login view.
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// CSRF: state-changing requests with an Origin header must be
		// same-origin (browsers always send Origin on cross-site POST).
		if isWriteMethod(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r) {
				http.Error(w, "Forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		// Forced first-login password change: while the account still carries
		// the initial password, only the self-service change (and the reads
		// it needs) may pass - everything else is rejected until cleared.
		if st := s.userStore(); st != nil {
			if rec, err := st.GetUser(u.Username); err == nil && rec.MustChange {
				pp := r.URL.Path
				allowed := (pp == "/api/me/password" && r.Method == http.MethodPost) ||
					(pp == "/api/me" && r.Method == http.MethodGet) ||
					(pp == "/api/logout" && r.Method == http.MethodPost)
				if !allowed {
					writeErr(w, http.StatusForbidden, simpleError("password_change_required"))
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
	})
}

// identify resolves the acting console user from Basic credentials, a
// Bearer token (API key) or a session cookie.
// Returns nil when unauthenticated.
func (s *Server) identify(r *http.Request) *currentUser {
	a := s.opts.Auth
	if a == nil {
		return nil
	}
	if user, pass, ok := r.BasicAuth(); ok {
		if s.logins.locked(r, s.loginMax(), s.loginWindow()) {
			return nil // locked out: fail closed without running argon2
		}
		// An empty Basic username selects the bootstrap account — normalize
		// here so the session identity matches the JSON login path; an
		// untracked empty-name admin would bypass the forced-change and
		// password max-age gates and write blank audit authors.
		username := strings.TrimSpace(user)
		if username == "" {
			username = bootstrapUsername
		}
		role, ok := s.authenticate(username, pass, "")
		if !ok {
			s.logins.recordFailure(r, s.loginWindow())
			return nil
		}
		s.logins.recordSuccess(r)
		return &currentUser{Username: username, Role: role}
	}
	if token := bearerToken(r); token != "" {
		// A presented Bearer token must be valid 鈥?no silent fallback.
		return s.identifyBearer(token)
	}
	ck, err := r.Cookie(a.cookieName)
	if err != nil {
		return nil
	}
	role, username, ok := a.sessionIdentity(ck.Value)
	if !ok || username == "" {
		return nil
	}
	return &currentUser{Username: username, Role: role}
}

// bearerToken extracts the raw token from an Authorization: Bearer header.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
}

// identifyBearer authenticates a Bearer token as a console API key
// ("kma1_<id>_<secret>", inheriting the owning user's role).
func (s *Server) identifyBearer(token string) *currentUser {
	if keyID, secret, ok := splitAPIKey(token); ok {
		st := s.userStore()
		if st == nil {
			return nil
		}
		u, err := st.GetUserByAPIKeyID(keyID)
		if err != nil || u.Disabled || u.APIKeyHash == "" {
			return nil
		}
		sum := sha256.Sum256([]byte(secret))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(u.APIKeyHash)) != 1 {
			return nil
		}
		_ = st.TouchAPIKeyUsed(keyID)
		return &currentUser{Username: u.Username, Role: u.Role}
	}
	return nil
}

// authenticate validates credentials against the users table. Unknown
// usernames burn one argon2id verification so response timing matches a real
// credential check (no enumeration oracle).
func (s *Server) authenticate(username, password, totpCode string) (string, bool) {
	a := s.opts.Auth
	if a == nil {
		return "", false
	}
	if username == "" {
		username = bootstrapUsername // sole built-in account (kmadmin)
	}
	if st := s.userStore(); st != nil {
		if u, err := st.GetUser(username); err == nil {
			// The hash verification runs unconditionally (even for disabled
			// accounts): every branch that answers a credential check must
			// pay the same argon2id cost, otherwise response timing becomes
			// an account-state oracle.
			verified := passhash.VerifyArgon2id(u.PasswordHash, password)
			if u.Disabled || !verified {
				return "", false
			}
			// Per-user TOTP takes precedence; the global env secret stays
			// as the fallback so existing deployments keep their 2FA.
			if u.TOTPEnabled {
				if !totp.Validate(totpCode, u.TOTPSecret) {
					return "", false
				}
			} else if a.TOTPEnabled() && !totp.Validate(totpCode, a.totpSecret) {
				return "", false
			}
			return u.Role, true
		}
	}
	// Unknown username: burn one argon2id verification so response timing
	// matches a real credential check (no enumeration oracle).
	passhash.VerifyDummy(password)
	return "", false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// handleLogin issues a console session (username + password + optional TOTP).
// The session carries the account role and username so read/write gating and
// self-service endpoints work without a server-side session store.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	a := s.opts.Auth
	if a == nil || a.hash == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("auth is not configured"))
		return
	}
	if s.logins.locked(r, s.loginMax(), s.loginWindow()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.loginWindow().Seconds())))
		writeErr(w, http.StatusTooManyRequests, fmt.Errorf("too many failed attempts, try again later"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Normalize once at the entry point: an empty username selects the sole
	// built-in bootstrap account. passwordExpired, authenticate and the
	// issued session must all see the same identity, otherwise an empty-name
	// login splits into an untracked role/admin session.
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = bootstrapUsername
	}
	role, ok := s.authenticate(username, req.Password, req.TOTP)
	if !ok {
		s.logins.recordFailure(r, s.loginWindow())
		writeErr(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"))
		return
	}
	// Password max-age policy (user management → security settings).
	if s.passwordExpired(username, s.cfgSecurity()) {
		writeErr(w, http.StatusForbidden, simpleError("密码已超过有效期，请联系管理员重置"))
		return
	}
	s.logins.recordSuccess(r)
	// Initial-password state is surfaced so the SPA can route the browser
	// into the forced change-password view before the console opens.
	mustChange := false
	if st := s.userStore(); st != nil {
		if rec, err := st.GetUser(username); err == nil {
			mustChange = rec.MustChange
		}
	}
	a.issueSession(w, r, role, username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": role, "username": username,
		"totp": a.TOTPEnabled(), "must_change": mustChange})
}

// handleLogout revokes all issued sessions and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.opts.Auth != nil && s.opts.Auth.hash != "" {
		s.opts.Auth.invalidBefore.Store(time.Now().Unix())
		http.SetCookie(w, &http.Cookie{
			Name: s.opts.Auth.cookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleCertificates returns the TLS certificate inventory.
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	writeJSON(w, http.StatusOK, certmgr.InspectSites(cfg))
}

// handleACMERequest submits an asynchronous ACME issuance request for ONE
// domain (cert-library "request first, attach site later" flow). It answers
// 202 immediately with the task; progress is polled via the status endpoint.
// Single-flight and cache-idempotent submissions answer with the existing
// task instead of issuing again.
func (s *Server) handleACMERequest(w http.ResponseWriter, r *http.Request) {
	svc := s.opts.ACME
	if svc == nil {
		writeErr(w, http.StatusNotImplemented, simpleError("当前运行模式未启用证书库 ACME 申请"))
		return
	}
	// HTTP-01 and TLS-ALPN-01 both need the global data-plane listeners;
	// without them the ACME servers could never reach the challenge handlers.
	_, cfg := s.opts.Center.Current()
	if cfg.ListenHTTP == "" || cfg.ListenHTTPS == "" {
		writeErr(w, http.StatusBadRequest, simpleError("请先在站点防护页配置全局 HTTP/HTTPS 监听地址，再申请 ACME 证书"))
		return
	}
	var req struct {
		Domain  string `json:"domain"`
		Email   string `json:"email"`
		Staging bool   `json:"staging"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	task, err := svc.Request(req.Domain, req.Email, req.Staging)
	if err != nil {
		switch {
		case errors.Is(err, certmgr.ErrCooldown):
			writeErr(w, http.StatusTooManyRequests, err)
		default:
			writeErr(w, http.StatusBadRequest, err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, task)
}

// handleACMERequestStatus returns a snapshot of one issuance task.
func (s *Server) handleACMERequestStatus(w http.ResponseWriter, r *http.Request) {
	svc := s.opts.ACME
	if svc == nil {
		writeErr(w, http.StatusNotImplemented, simpleError("当前运行模式未启用证书库 ACME 申请"))
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, simpleError("缺少任务 id 参数"))
		return
	}
	task, ok := svc.Task(id)
	if !ok {
		writeErr(w, http.StatusNotFound, simpleError("申请任务不存在或已被清理"))
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// handleACMEEntries lists the ACME-managed cert-library entries read live
// from both cache directories (production first, then staging).
func (s *Server) handleACMEEntries(w http.ResponseWriter, r *http.Request) {
	if s.opts.ACME == nil {
		writeJSON(w, http.StatusOK, []certmgr.CertEntry{})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.ACME.Entries())
}

// handleStatus returns build/runtime info.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	rev, cfg := s.opts.Center.Current()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.opts.Version,
		"revision": rev,
		"sites":    len(cfg.Sites),
		"time":     time.Now().UTC().Format(time.RFC3339),
		"engine":   engineVersions(),
	})
}

// upstreamReleases maps known upstream dependency versions to their release
// month (human-maintained table; unknown versions display "-").
var upstreamReleases = map[string]string{
	"github.com/corazawaf/coraza/v3@v3.0.0":  "2023-08",
	"github.com/corazawaf/coraza/v3@v3.1.0":  "2024-02",
	"github.com/corazawaf/coraza/v3@v3.1.1":  "2024-04",
	"github.com/corazawaf/coraza/v3@v3.2.0":  "2024-11",
	"github.com/corazawaf/coraza/v3@v3.2.1":  "2024-12",
	"github.com/corazawaf/coraza/v3@v3.2.2":  "2025-03",
	"github.com/corazawaf/coraza/v3@v3.3.0":  "2025-08",
	"github.com/corazawaf/coraza/v3@v3.7.0":  "2026-04",
	"github.com/corazawaf/coraza-coreruleset/v4@v4.25.0": "2026-03",
	"github.com/corazawaf/coraza-coreruleset@v4.0.0": "2023-11",
	"github.com/corazawaf/coraza-coreruleset@v4.1.0": "2024-06",
	"github.com/corazawaf/coraza-coreruleset@v4.2.0": "2024-12",
	"github.com/corazawaf/coraza-coreruleset@v4.3.0": "2025-03",
	"github.com/corazawaf/coraza-coreruleset@v4.4.0": "2025-06",
	"github.com/corazawaf/coraza-coreruleset@v4.5.0": "2025-09",
	"github.com/corazawaf/coraza-coreruleset@v4.6.0": "2025-12",
	"go1.23.0": "2024-08", "go1.23.4": "2024-12", "go1.24.0": "2025-02",
	"go1.24.1": "2025-03", "go1.24.4": "2025-06", "go1.25.0": "2025-08",
	"go1.25.1": "2025-09", "go1.26.0": "2026-02", "go1.26.1": "2026-03",
	"go1.27.0": "2026-08",
}

// engineCorazaVersion / engineCRSVersion are injected at build time via
// -ldflags -X as a fallback for builds where debug.ReadBuildInfo() has no
// coraza/CRS module info: the packaging injects the go.mod versions instead
// so the engine/rule version card stays populated.
// Values always originate from go.mod (single source of truth).
var (
	engineCorazaVersion string
	engineCRSVersion    string
)

// engineVersions extracts detection-engine dependency versions from the
// build info, plus each upstream's release month (read-only facts for the
// policy page version card).
func engineVersions() map[string]string {
	out := map[string]string{"go": runtime.Version()}
	foundCoraza, foundCRS := false, false
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			switch {
			case d.Path == "github.com/corazawaf/coraza/v3":
				out["coraza"] = d.Version
				out["coraza_release"] = upstreamReleases[d.Path+"@"+d.Version]
				foundCoraza = true
			case strings.HasPrefix(d.Path, "github.com/corazawaf/coraza-coreruleset"):
				out["crs"] = d.Version
				out["crs_release"] = upstreamReleases[d.Path+"@"+d.Version]
				foundCRS = true
			}
		}
	}
	// Engine-less builds: fall back to the ldflags-injected go.mod versions.
	if !foundCoraza && engineCorazaVersion != "" {
		out["coraza"] = engineCorazaVersion
		out["coraza_release"] = upstreamReleases["github.com/corazawaf/coraza/v3@"+engineCorazaVersion]
	}
	if !foundCRS && engineCRSVersion != "" {
		out["crs"] = engineCRSVersion
		out["crs_release"] = upstreamReleases["github.com/corazawaf/coraza-coreruleset/v4@"+engineCRSVersion]
	}
	if rel, ok := upstreamReleases[runtime.Version()]; ok {
		out["go_release"] = rel
	}
	// Embedded GeoIP country database (DB-IP Lite, CC BY 4.0).
	if dbType, build := geoip.Info(); dbType != "" {
		out["geoip"] = dbType
		out["geoip_build"] = build
	}
	return out
}

// handleGetConfig returns the active configuration with its revision.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	rev, cfg := s.opts.Center.Current()
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "config": cfg})
}

type publishRequest struct {
	Note   string        `json:"note"`
	Config config.Config `json:"config"`
}

// handlePublish validates and publishes a new configuration revision.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req publishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	author := "admin"
	if u := userFromContext(r); u != nil {
		author = u.Username
	} else if user, _, ok := r.BasicAuth(); ok && user != "" {
		author = user
	}
	rev, err := s.opts.Center.Publish(&req.Config, author, req.Note)
	if err != nil {
		if errors.Is(err, configcenter.ErrNoChanges) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "no_changes", "message": "配置无变更，未创建新版本"})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Wait briefly for the data plane to report the reload outcome so the
	// console can surface "saved but engine load failed" (fail-static kept
	// the previous engine). pending = no in-plane consumer or slow reload.
	apply := s.opts.Center.WaitForApply(rev, 5*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{
		"revision": rev,
		"apply": map[string]any{"revision": apply.Revision, "status": apply.Status, "error": apply.Error},
	})
}

// sitePublishRequest carries one site definition targeted by one of its
// domains. Existing sites are matched case-insensitively; an unmatched
// domain appends a new site.
type sitePublishRequest struct {
	Domain string        `json:"domain"`
	Note   string        `json:"note"`
	Site   config.Site   `json:"site"`
}

// handleSitePublish publishes a single-site change. Validation failures only
// affect the submitted site: the live configuration is always valid, so the
// aggregated error can only originate from the new site definition.
func (s *Server) handleSitePublish(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var req sitePublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	if req.Domain == "" {
		req.Domain = firstSiteDomain(&req.Site)
	}
	author := "admin"
	if u := userFromContext(r); u != nil {
		author = u.Username
	} else if user, _, ok := r.BasicAuth(); ok && user != "" {
		author = user
	}
	rev, err := s.opts.Center.PublishSite(req.Domain, req.Site, author, req.Note)
	if err != nil {
		if errors.Is(err, configcenter.ErrNoChanges) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "no_changes", "message": "配置无变更，未创建新版本"})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "domain": strings.ToLower(strings.TrimSpace(req.Domain))})
}

func firstSiteDomain(s *config.Site) string {
	if s != nil && len(s.Domains) > 0 {
		return s.Domains[0]
	}
	return ""
}

// handleRevisions lists recent revision metadata.
func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	revs, err := s.opts.Center.Store().ListRevisions(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if revs == nil {
		revs = []store.RevisionMeta{}
	}
	writeJSON(w, http.StatusOK, revs)
}

// handleRollback re-publishes an old revision as the new head.
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleOperator) {
		return
	}
	var id int64
	if _, err := fmt.Sscanf(r.PathValue("id"), "%d", &id); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid revision id"))
		return
	}
	rev, err := s.opts.Center.Rollback(id, "admin")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "rolled_back_to": id})
}

// handleLogs returns audit events: newest-first recent feed by default, or
// a filtered history query when any filter parameter is present (action,
// site, rule, ip, q full-text, since/until RFC3339). Supported whenever the
// backing store implements logstore.Searcher (SQLite store does). All query
// paths run through the audit-query gate (degraded switch, concurrency cap,
// per-request timeout) so heavy scans stay off the forwarding path.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	release, timeout, ok := s.auditQueryGate(cfg)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":    "log query degraded: audit queries are temporarily disabled (emergency mode); traffic forwarding is unaffected",
			"degraded": true,
		})
		return
	}
	defer release()

	qp := r.URL.Query()
	limit := 100
	if v := qp.Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var q logstore.LogQuery
	var filtered bool
	if v := qp.Get("action"); v != "" {
		q.Action, filtered = v, true
	}
	if v := qp.Get("site"); v != "" {
		q.Site, filtered = v, true
	}
	if v := qp.Get("rule"); v != "" {
		q.Rule, filtered = v, true
	}
	if v := qp.Get("ip"); v != "" {
		q.SrcIP, filtered = v, true
	}
	if v := qp.Get("q"); v != "" {
		q.Text, filtered = v, true
	}
	if v := qp.Get("trace_id"); v != "" {
		q.TraceID, filtered = v, true
	}
	if v := qp.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since, filtered = t, true
		}
	}
	if v := qp.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Until, filtered = t, true
		}
	}
	// Paged mode: ?page=N&page_size=M returns {items,total,page,page_size}
	// (console UI 2.0); the legacy callers (no page param) keep receiving a
	// plain array so LogDetail trace lookups stay compatible.
	if qp.Get("page") != "" {
		page, size := 1, limit
		if v := qp.Get("page_size"); v != "" {
			fmt.Sscanf(v, "%d", &size)
		}
		if size <= 0 || size > 1000 {
			size = 100
		}
		if page < 1 {
			page = 1
		}
		if paged, ok := s.opts.Logs.(logstore.PagedSearcher); ok {
			q.Limit, q.Offset = size, (page-1)*size
			type pagedResult struct {
				items []logstore.Event
				total int
				err   error
			}
			done := make(chan pagedResult, 1)
			go func() {
				items, err := paged.Query(q)
				if err != nil {
					done <- pagedResult{err: err}
					return
				}
				total, err := paged.Count(q)
				done <- pagedResult{items: enrichAttackType(items), total: total, err: err}
			}()
			select {
			case res := <-done:
				if res.err != nil {
					writeErr(w, http.StatusInternalServerError, res.err)
					return
				}
				if res.items == nil {
					res.items = []logstore.Event{}
				}
				writeJSON(w, http.StatusOK, logsPageResponse{
					Items: res.items, Total: res.total, Page: page, PageSize: size,
				})
			case <-time.After(timeout):
				writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "log query timed out"})
			}
			return
		}
	}
	if filtered {
		q.Limit = limit
		if srch, ok := s.opts.Logs.(logstore.Searcher); ok {
			s.runBoundedQuery(w, timeout, func() ([]logstore.Event, error) {
				evs, err := srch.Query(q)
				return enrichAttackType(evs), err
			})
			return
		}
	}
	s.runBoundedQuery(w, timeout, func() ([]logstore.Event, error) {
		events := []logstore.Event{}
		if s.opts.Logs != nil {
			events = s.opts.Logs.Recent(limit)
		}
		if events == nil {
			events = []logstore.Event{}
		}
		return enrichAttackType(events), nil
	})
}

// enrichAttackType back-fills the derived attack category for events stored
// by older builds (attack_type was not derived at write time before the
// console 2.0 rebuild).
func enrichAttackType(evs []logstore.Event) []logstore.Event {
	for i := range evs {
		if evs[i].AttackType == "" && evs[i].Rule != "" {
			evs[i].AttackType = logstore.AttackTypeOf(evs[i].Rule)
		}
	}
	return evs
}

// handleLogsStorage reports the audit storage posture for the console
// risk banner: boot-time store settings plus whether an external sink
// (webhook / log shipper) is configured in the active config.
func (s *Server) handleLogsStorage(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	external := cfg.Webhook != nil || cfg.LogShipper != nil
	info := LogsStorageInfo{
		Store:                "sqlite",
		ExternalConfigured:   external,
		RetentionDays:        7,
		ArchiveEnabled:       true,
		ArchiveRetentionDays: 30,
	}
	if s.opts.LogsStorage != nil {
		info.RetentionDays = s.opts.LogsStorage.RetentionDays
		info.ArchiveEnabled = s.opts.LogsStorage.ArchiveEnabled
		info.ArchiveRetentionDays = s.opts.LogsStorage.ArchiveRetentionDays
	}
	aq := cfg.AuditQuery
	info.QueryDegraded = aq.DegradedOrDefault()
	info.QueryMaxConcurrent = aq.MaxConcurrentOrDefault()
	info.QueryTimeoutMs = int(aq.TimeoutOrDefault() / time.Millisecond)
	writeJSON(w, http.StatusOK, info)
}

// handleStats returns dashboard aggregates for today. Backed by SQL
// aggregation when the store supports it (SQLite store), falling back to
// the recent-event feed otherwise.
// handleHostStats reports deployment-host resource usage (CPU, memory,
// disks, uptime, Go runtime) for the console server/host page. Binary
// deployments get host-level numbers; containers are detected and their
// cgroup v2 limits applied when readable.
func (s *Server) handleHostStats(w http.ResponseWriter, r *http.Request) {
	var auditDir string
	if _, cur := s.opts.Center.Current(); cur != nil {
		auditDir = cur.AuditLogDir // the audit volume is the busiest data disk
	}
	st, err := hoststats.Snapshot(auditDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleMetrics serves the optional Prometheus text exposition endpoint
// (GET /metrics). Disabled by default (config.metrics.enabled); while
// disabled it answers 404 so scrapers get a clear signal. The endpoint
// stays inside the console-authenticated surface and the setting is
// hot-applied on publish.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	_, cfg := s.opts.Center.Current()
	if !cfg.Metrics.EnabledOrDefault() {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "metrics endpoint disabled (config.metrics.enabled=false)",
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(metrics.PrometheusText(s.opts.Version)))
}


func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	// Window: today (default) or the last N days (dashboard time selector);
	// the shift marks the previous same-length window for the delta badge.
	days := 1
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 90 {
			days = n
		}
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	windowStart := dayStart.AddDate(0, 0, -(days - 1))
	prevStart := windowStart.AddDate(0, 0, -days)
	blockedToday, challengedToday, monitorToday := 0, 0, 0
	blockedPrev, monitorPrev := 0, 0
	botDist := map[string]int{}
	if agg, ok := s.opts.Logs.(logstore.Aggregator); ok {
		if sum, err := agg.Aggregate(windowStart, now); err == nil {
			blockedToday = sum.ByAction["blocked"]
			challengedToday = sum.ByAction["challenged"]
			monitorToday = sum.ByAction["monitor"]
			for k, v := range sum.TopBotClass {
				botDist[k] = v
			}
		}
		if sum, err := agg.Aggregate(prevStart, windowStart); err == nil {
			blockedPrev = sum.ByAction["blocked"]
			monitorPrev = sum.ByAction["monitor"]
		}
	} else if s.opts.Logs != nil {
		for _, ev := range s.opts.Logs.Recent(1000) {
			ts, err := time.Parse(time.RFC3339Nano, ev.TS)
			if err == nil && ts.Before(windowStart) {
				continue
			}
			switch ev.Action {
			case "blocked":
				blockedToday++
			case "challenged":
				challengedToday++
			case "monitor":
				monitorToday++
			}
			if ev.BotClass != "" {
				botDist[ev.BotClass]++
			}
		}
	}
	rev, cfg := s.opts.Center.Current()
	// Window request counts: per-day request history (outcome → count per
	// local date) summed over the selected range. Source: the local request
	// history (all-in-one deployment); the typed snapshot goes straight into
	// addHistory so window filtering stays in one place.
	reqMap := map[string]int64{}
	addHistory := func(hist map[string]map[string]int64) {
		for d, outcomes := range hist {
			dt, err := time.ParseInLocation("2006-01-02", d, time.Local)
			if err != nil || dt.Before(windowStart) || dt.After(now) {
				continue
			}
			for outcome, n := range outcomes {
				reqMap[outcome] += n
			}
		}
	}
	addHistory(metrics.SnapshotRequestsHistory())
	resp := map[string]any{
		"revision":          rev,
		"sites":             len(cfg.Sites),
		"days":              days,
		"window_start":      windowStart.Format(time.RFC3339),
		"blocked_today":     blockedToday,
		"challenged_today":  challengedToday,
		"monitor_today":     monitorToday,
		"blocked_prev":      blockedPrev,
		"monitor_prev":      monitorPrev,
		"bot_distribution":  botDist,
		"requests":          reqMap,
	}
	// Attack-type distribution for the dashboard donut (derived from rules).
	if dist, ok := s.opts.Logs.(logstore.TypeDistributor); ok {
		if hits, err := dist.TypeDistribution(windowStart, now, 12); err == nil {
			resp["attack_distribution"] = hits
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeBody decodes a JSON request body (1MB cap).
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

// simpleError is a static error value.
type simpleError string

func (e simpleError) Error() string { return string(e) }

// isWriteMethod reports whether the method mutates state.
func isWriteMethod(m string) bool {
	return m == http.MethodPost || m == http.MethodPut ||
		m == http.MethodPatch || m == http.MethodDelete
}

// sameOrigin checks that the Origin header matches the request Host
// scheme-agnostically (console is served on one origin).
func sameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	return strings.EqualFold(u.Hostname(), host) || strings.EqualFold(u.Host, r.Host)
}