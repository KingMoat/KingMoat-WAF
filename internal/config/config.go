// Package config defines the M0 static configuration model for KingMoat.
// Versioned config store + hot reload land in M2 (see docs/ARCHITECTURE.md §4).
package config

import (
	"time"
	"encoding/json"
	"fmt"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"errors"
)

// UpstreamNode is a single backend address.
type UpstreamNode struct {
	Address string `json:"address"` // host:port or scheme://host:port
	Weight  int    `json:"weight,omitempty"`
}

// Upstream is a pool of backend nodes for one site.
type Upstream struct {
	Nodes []UpstreamNode `json:"nodes"`
	// Algorithm selects the load-balancing strategy:
	// "wrr" (smooth weighted round-robin, default), "least_conn"
	// (fewest in-flight requests) or "source_ip" (client-IP hash pinning).
	Algorithm string `json:"algorithm,omitempty"`
	// SNIForward forwards the client's original TLS SNI to HTTPS upstream
	// nodes (per-request, from the inbound ClientHello) instead of the
	// upstream address host. Useful for SNI-routed backends; the upstream
	// certificate must match the forwarded name or the handshake fails.
	SNIForward bool `json:"sni_forward,omitempty"`
	// VerifyTLS enables strict upstream certificate verification for HTTPS
	// upstream nodes. Default false: forwarded traffic mostly targets
	// internal servers whose certificates are private-CA, self-signed or
	// awaiting renewal; opt in per site for strict end-to-end verification.
	// SNIHost pins the upstream TLS handshake ServerName to a fixed hostname
	// (connection-level, not per-request): every connection in the keep-alive
	// pool negotiates the same SNI, so reuse across requests for different
	// domains stays correct — unlike SNIForward, which forwards the TCP
	// connection's SNI and mismatches when a connection established for
	// domain A is reused by a request for domain B. Only meaningful for
	// HTTPS upstream nodes (harmless on HTTP). Mutually exclusive with
	// SNIForward. The upstream certificate must match this name unless
	// VerifyTLS is disabled.
	SNIHost string `json:"sni_host,omitempty"`
	// VerifyTLS enables strict upstream certificate verification for HTTPS
	// upstream nodes. Default false: forwarded traffic mostly targets
	// internal servers whose certificates are private-CA, self-signed or
	// awaiting renewal; opt in per site for strict end-to-end verification.
	VerifyTLS bool `json:"verify_tls,omitempty"`
}

// ValidAlgorithms lists the supported load-balancing algorithms.
func ValidAlgorithms() []string { return []string{"", "wrr", "least_conn", "source_ip"} }

// DefaultBodyLimit is the default per-request body inspection buffer (8 MiB).
const DefaultBodyLimit int64 = 8 << 20

// WAFSettings configures the Coraza detection stage for one site.
type WAFSettings struct {
	// Enabled defaults to true when omitted (nil).
	Enabled         *bool  `json:"enabled,omitempty"`
	CustomRulesFile string `json:"custom_rules_file,omitempty"`
	// BodyLimitBytes caps the buffered request body for inspection;
	// <= 0 means DefaultBodyLimit. It also aligns Coraza's SecRequestBodyLimit.
	BodyLimitBytes int64 `json:"body_limit_bytes,omitempty"`
	// BodyOverLimit: "reject" (default, 413), "bypass" (stream unbuffered,
	// header-phase detection only) or "stream" (deep-inspect the first
	// body_limit_bytes, forward the remainder untouched).
	BodyOverLimit string `json:"body_over_limit,omitempty"`
	// Categories filters which CRS attack-detection categories are loaded for
	// this site. Empty or omitted = all categories enabled (backward compat).
	// Valid values: sqli, xss, rce, lfi, rfi, php, generic, session, java,
	// scanner. Infrastructure rules (protocol enforcement, multipart,
	// blocking evaluation) are always loaded and cannot be disabled.
	Categories []string `json:"categories,omitempty"`
}

// IsEnabled reports whether the WAF stage should be attached to the site.
func (w *WAFSettings) IsEnabled() bool {
	return w == nil || w.Enabled == nil || *w.Enabled
}

// BodyLimit returns the effective body inspection limit in bytes.
func (w *WAFSettings) BodyLimit() int64 {
	if w == nil || w.BodyLimitBytes <= 0 {
		return DefaultBodyLimit
	}
	return w.BodyLimitBytes
}

// RejectOverLimit reports whether over-limit bodies are rejected (413).
func (w *WAFSettings) RejectOverLimit() bool {
	return w == nil || w.BodyOverLimit != "bypass" && w.BodyOverLimit != "stream"
}

// StreamOverLimit reports whether over-limit bodies are partially inspected
// (first body_limit_bytes) and then forwarded untouched.
func (w *WAFSettings) StreamOverLimit() bool {
	return w != nil && w.BodyOverLimit == "stream"
}

// WAFDetectionCategories lists all user-toggleable CRS detection categories.
// Infrastructure rules (901-init, 905-exceptions, 911-method, 920-protocol,
// 921-protocol-attack, 922-multipart, 949-blocking-eval, 999-after) are
// always loaded and cannot be disabled.
var WAFDetectionCategories = []string{
	"sqli", "xss", "rce", "lfi", "rfi",
	"php", "generic", "session", "java", "scanner",
}

// wafCategoryFiles maps each category to its CRS include file name.
var wafCategoryFiles = map[string]string{
	"sqli":    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"xss":     "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"rce":     "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"lfi":     "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"rfi":     "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"php":     "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
	"generic": "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"session": "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
	"java":    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
	"scanner": "REQUEST-913-SCANNER-DETECTION.conf",
}

// wafAlwaysOnFiles are CRS files that are always loaded regardless of
// category settings.
var wafAlwaysOnFiles = []string{
	"REQUEST-901-INITIALIZATION.conf",
	"REQUEST-905-COMMON-EXCEPTIONS.conf",
	"REQUEST-911-METHOD-ENFORCEMENT.conf",
	"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"REQUEST-921-PROTOCOL-ATTACK.conf",
	"REQUEST-922-MULTIPART-ATTACK.conf",
	"REQUEST-949-BLOCKING-EVALUATION.conf",
	"REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
	"RESPONSE-950-DATA-LEAKAGES.conf",
	"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
	"RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
	"RESPONSE-953-DATA-LEAKAGES-PHP.conf",
	"RESPONSE-954-DATA-LEAKAGES-IIS.conf",
	"RESPONSE-955-WEB-SHELLS.conf",
	"RESPONSE-956-DATA-LEAKAGES-RUBY.conf",
	"RESPONSE-980-CORRELATION.conf",
}

// ValidWAFCategory reports whether the given category name is valid.
func ValidWAFCategory(c string) bool {
	_, ok := wafCategoryFiles[c]
	return ok
}

// ValidWAFCategories returns all valid category names.
func ValidWAFCategories() []string {
	out := make([]string, len(WAFDetectionCategories))
	copy(out, WAFDetectionCategories)
	return out
}

// WAFAlwaysOnFiles returns the CRS include file names that are always
// loaded regardless of category settings.
func WAFAlwaysOnFiles() []string {
	return wafAlwaysOnFiles
}

// WAFCategoryFile returns the CRS include file name for a category.
func WAFCategoryFile(cat string) (string, bool) {
	f, ok := wafCategoryFiles[cat]
	return f, ok
}

// WAFCategoryFiles returns the full category-to-CRS-file mapping.
func WAFCategoryFiles() map[string]string {
	out := make(map[string]string, len(wafCategoryFiles))
	for k, v := range wafCategoryFiles {
		out[k] = v
	}
	return out
}

// Site maps one or more domains to an upstream pool.
type Site struct {
	// Name is an optional user-defined display name (console only; routing
	// always matches on domains).
	Name string `json:"name,omitempty"`
	// Disabled takes the site out of rotation without deleting it: matched
	// requests get an explicit "site disabled" block page instead of being
	// forwarded. Toggled from the console (hot-applied on publish).
	Disabled bool     `json:"disabled,omitempty"`
	// Comment is a free-form note maintained from the console.
	Comment  string   `json:"comment,omitempty"`
	Domains  []string `json:"domains"`
	Mode     string   `json:"mode,omitempty"` // "intercept" (default) | "monitor"
	Upstream Upstream `json:"upstream"`
	TLSCert  string   `json:"tls_cert,omitempty"` // PEM file path, used for SNI on the HTTPS listener
	TLSKey   string   `json:"tls_key,omitempty"`
	// TLSProfile selects the HTTPS cipher-suite group: "strong" (AEAD only),
	// "moderate" (default; AEAD + ECDHE CBC-SHA256/384) or "compatible"
	// (moderate + ECDHE CBC-SHA1 for legacy clients). TLS 1.2 is the floor
	// for every profile; TLS 1.3 is always available.
	TLSProfile string `json:"tls_profile,omitempty"`
	// Per-site service ports (0 = inherit the global listeners). Multiple
	// sites may share a port; a port stays bound while any site references it.
	// ListenHTTPPort / ListenHTTPSPort were removed in v0.6.1: service ports
	// are defined once at the top level (listen_http / listen_https). The
	// fields are gone from the schema; leftover values in old configs are
	// ignored on load and dropped by the strict schema on the next publish.
	// ACME enables automatic Let's Encrypt issuance/renewal for this site's
	// domains (TLS-ALPN-01 on the HTTPS listener, HTTP-01 fallback on 80).
	ACME   *ACMESettings   `json:"acme,omitempty"`
	Health *HealthSettings `json:"health,omitempty"`
	// RedirectToHTTPS answers 308 Permanent Redirect on the HTTP listener for
	// this site, pointing clients at the HTTPS URL (host + listen_https port).
	// Requires tls_cert/tls_key (or acme) and a global listen_https. Requests
	// under /.well-known/acme-challenge/ are exempt so renewals keep working.
	RedirectToHTTPS bool              `json:"redirect_to_https,omitempty"`
	// HTTP2Enabled controls HTTP/2 negotiation for this site's TLS
	// handshakes (nil/true = default, h2 + HTTP/1.1; false = HTTP/1.1 only).
	HTTP2Enabled *bool             `json:"http2_enabled,omitempty"`
	WAF          *WAFSettings      `json:"waf,omitempty"`
	Security     *SecuritySettings `json:"security,omitempty"`
	// RealIP enables trusted-proxy real client-IP resolution for this site
	// (deployments behind an LB/CDN). When enabled, requests whose TCP peer
	// is within trusted_proxies take their client IP from the configured
	// header (default X-Forwarded-For); ACL, GeoIP, rate limiting, bot
	// detection, matcher rules and every log then operate on the resolved
	// address. Peers outside trusted_proxies are never honored (anti-forgery).
	RealIP *RealIPSettings `json:"real_ip,omitempty"`
	// Headers applies user-defined request-header operations before the
	// request is forwarded upstream (nil = passthrough). Ops run after the
	// built-in X-Forwarded-* handling, so explicit config wins.
	Headers *HeaderRewrite `json:"headers,omitempty"`
}

// RealIPSettings configures trusted-proxy real client-IP resolution.
type RealIPSettings struct {
	Enabled bool   `json:"enabled"`
	// Header is the source header carrying the client chain
	// (default "X-Forwarded-For" when empty).
	Header string `json:"header,omitempty"`
	// TrustedProxies lists the IP/CIDR ranges allowed to set the header
	// (the direct TCP peer must match one of them). Required when enabled.
	TrustedProxies []string `json:"trusted_proxies"`
}

// HeaderRewrite applies user-defined request-header operations on the
// forwarded request.	Values support the placeholders $client_ip, $remote_addr,
// $host, $scheme, $trace_id and $hdr.<Name> (copy an inbound header; the op
// is skipped when the inbound header is absent).
type HeaderRewrite struct {
	// Set replaces (or adds) outbound headers with the given values.
	Set map[string]string `json:"set,omitempty"`
	// Add appends values without replacing existing ones.
	Add map[string]string `json:"add,omitempty"`
	// Del removes outbound headers (hop-by-hop / framing headers rejected
	// at config load).
	Del []string `json:"del,omitempty"`
}

// protectedHeaders must not be rewritten by user config: they are either
// framing/hop-by-hop headers owned by the transport or fields the proxy
// derives itself. Rewriting them would corrupt requests or bypass the
// built-in X-Forwarded-* handling.
var protectedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true,
	"Connection": true, "Keep-Alive": true, "Upgrade": true, "TE": true,
	"Trailer": true, "Proxy-Connection": true,
}

// Validate checks header names, values and placeholder syntax before any
// listener starts (fail-fast at config load).
func (h *HeaderRewrite) Validate() error {
	checkName := func(where, name string) error {
		if !validHeaderName(name) {
			return fmt.Errorf("%s: %q is not a valid header name", where, name)
		}
		if protectedHeaders[canonicalHeaderName(name)] {
			return fmt.Errorf("%s: %q is a protected header and cannot be rewritten", where, name)
		}
		return nil
	}
	checkVal := func(where, val string) error {
		if strings.ContainsAny(val, "\r\n\x00") {
			return fmt.Errorf("%s: value contains CR/LF/NUL", where)
		}
		for _, m := range placeholderRE.FindAllStringSubmatch(val, -1) {
			tok := m[1]
			if strings.HasPrefix(tok, "hdr.") && validHeaderName(strings.TrimPrefix(tok, "hdr.")) {
				continue
			}
			if !slices.Contains(knownPlaceholders, tok) {
				return fmt.Errorf("%s: unknown placeholder $%s", where, tok)
			}
		}
		return nil
	}
	for name, val := range h.Set {
		if err := checkName("set", name); err != nil {
			return err
		}
		if err := checkVal("set["+name+"]", val); err != nil {
			return err
		}
	}
	for name, val := range h.Add {
		if err := checkName("add", name); err != nil {
			return err
		}
		if err := checkVal("add["+name+"]", val); err != nil {
			return err
		}
	}
	for _, name := range h.Del {
		if err := checkName("del", name); err != nil {
			return err
		}
	}
	return nil
}

// knownPlaceholders are the variables usable in HeaderRewrite values.
var knownPlaceholders = []string{"client_ip", "remote_addr", "host", "scheme", "trace_id"}

// placeholderRE matches $name / $hdr.<Name> tokens in header values.
var placeholderRE = regexp.MustCompile(`\$([A-Za-z][A-Za-z0-9_.-]*)`)

// validHeaderName reports whether name is a valid RFC 7230 header field name
// (non-empty, token characters only).
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// canonicalHeaderName normalizes a header name for the protected-header
// check ("content-length" → "Content-Length").
func canonicalHeaderName(name string) string {
	return textproto.CanonicalMIMEHeaderKey(name)
}

// ACMESettings configures automatic certificate management for a site.
type ACMESettings struct {
	Email   string `json:"email"`             // ACME account contact
	Staging bool   `json:"staging,omitempty"` // use the Let's Encrypt staging CA (testing)
}

// Intercept reports whether the site blocks on deny verdicts.
// Sites default to intercept; monitor mode only records and forwards.
func (s *Site) Intercept() bool { return s.Mode != "monitor" }

// Config is the top-level M0 configuration file model (JSON).
type Config struct {
	ListenHTTP  string `json:"listen_http"`
	ListenHTTPS string `json:"listen_https,omitempty"`
	// AuditLogDir is where attack events are stored: audit.db (SQLite +
	// FTS5 full-text index) plus the archive/ subdirectory holding the
	// daily DB snapshots (default "logs").
	AuditLogDir string `json:"audit_log_dir,omitempty"`
	// AuditRetentionDays deletes attack events older than N days from the
	// live store (0 / unset = 7, negative = never purge). Applied by the
	// daily archiver; changes require a restart. Short defaults keep the
	// live database small: oversized local stores slow down console
	// queries - keep long-term history in an external sink instead.
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
	// AuditArchive configures the daily DB snapshot job (default on).
	AuditArchive *AuditArchiveSettings `json:"audit_archive,omitempty"`
	// AuditQuery governs console log-query concurrency/timeout and the
	// emergency degraded switch (settings page; hot-applied on publish).
	AuditQuery *AuditQuerySettings `json:"audit_query,omitempty"`
	// Metrics enables the optional Prometheus text exposition endpoint at
	// /metrics (console-authenticated). Off by default; while disabled the
	// endpoint answers 404, and the setting is hot-applied on publish.
	Metrics *MetricsSettings `json:"metrics,omitempty"`
	// DiskGuard reclaims audit-log space (archive FIFO, then oldest live
	// events) when the data volume exceeds the high watermark. Default on
	// (90% → reclaim to 65%); set enabled=false to opt out.
	DiskGuard *DiskGuardSettings `json:"disk_guard,omitempty"`
	// Webhook pushes blocked/challenged events to an HTTP endpoint.
	Webhook *WebhookSettings `json:"webhook,omitempty"`
	// LogShipper streams audit events to Elasticsearch, Loki, ClickHouse,
	// S3-compatible object storage or standard syslog.
	LogShipper *ShipperSettings `json:"log_shipper,omitempty"`
	// AccessLog streams the full access log (one entry per forwarded request)
	// to an external log platform; nothing is stored locally.
	AccessLog *AccessLogSettings `json:"access_log,omitempty"`
	// CaptureRequests stores sanitized request headers (and the body sample
	// for buffered requests) on every audit event, for log replay in the
	// console/API. Off by default (privacy).
	CaptureRequests bool `json:"capture_requests,omitempty"`
	// IPGroups defines subscribed IP lists referenced by ACL "group:<name>".
	IPGroups []IPGroupSettings `json:"ip_groups,omitempty"`
	// Email is the SMTP notification channel (alerts; settings page).
	Email *EmailSettings `json:"email,omitempty"`
	// Alerts configures the WAF anomaly alert engine (settings page).
	Alerts *AlertsSettings `json:"alerts,omitempty"`
	// Policy holds global detection settings: CRS thresholds, custom SecLang
	// rules and the global IP blacklist/whitelist (strategy page).
	Policy *Policy `json:"policy,omitempty"`
	// BlockPage customizes the interception page copy (settings page).
	BlockPage *BlockPage `json:"block_page,omitempty"`
	// Console restricts management-plane access (settings page).
	Console *Console `json:"console,omitempty"`
	// ApiAssets enables passive API asset learning (default off; zero
	// behavior change until explicitly enabled).
	ApiAssets *ApiAssetsSettings `json:"api_assets,omitempty"`
	// Risks configures the observe-only risk engine that consumes the asset
	// store and access statistics.
	Risks *RisksSettings `json:"risks,omitempty"`
	// AcmeEmail is the global ACME account contact used by sites that enable
	// acme without a per-site email (settings page).
	AcmeEmail string `json:"acme_email,omitempty"`
	// AI configures the embedded assistant; raw JSON decoded into
	// ai.Settings by the entrypoint (nil/absent → disabled).
	AI json.RawMessage `json:"ai,omitempty"`
	// Security bundles console security policy (user management → security
	// settings): password rules and session lifetime.
	Security *ConsoleSecuritySettings `json:"security,omitempty"`
	// Telemetry opts in to anonymous install statistics (random install ID,
	// version, OS/arch, install method). Default nil = disabled: no requests,
	// no local state. The user-facing switch lives in the console settings.
	Telemetry *TelemetrySettings `json:"telemetry,omitempty"`
	Sites []Site            `json:"sites"`
}

// AuditArchiveSettings configures the daily audit-database snapshot job.
type AuditArchiveSettings struct {
	// Enabled may be set to false to disable daily snapshots (default on).
	Enabled *bool `json:"enabled,omitempty"`
	// RetentionDays deletes local snapshot files older than N days
	// (default 30; <= 0 keeps them forever).
	RetentionDays int `json:"retention_days,omitempty"`
}

// DiskGuardSettings configures the audit disk guard: when the volume hosting
// the audit database exceeds high_pct usage, space is reclaimed oldest-first
// (archive snapshots, then oldest live events) until low_pct is reached.
type DiskGuardSettings struct {
	Enabled     bool `json:"enabled"`
	HighPct     int  `json:"high_pct,omitempty"`     // default 90
	LowPct      int  `json:"low_pct,omitempty"`      // default 65
	IntervalSec int  `json:"interval_sec,omitempty"` // default 300
}

// HighOrDefault returns the effective high watermark.
func (d *DiskGuardSettings) HighOrDefault() int {
	if d == nil || d.HighPct <= 0 || d.HighPct > 99 {
		return 90
	}
	return d.HighPct
}

// LowOrDefault returns the effective low watermark.
func (d *DiskGuardSettings) LowOrDefault() int {
	if d == nil || d.LowPct <= 0 || d.LowPct >= 100 {
		return 65
	}
	return d.LowPct
}

// IntervalOrDefault returns the check interval (min 60s).
func (d *DiskGuardSettings) IntervalOrDefault() time.Duration {
	if d == nil || d.IntervalSec <= 0 {
		return 300 * time.Second
	}
	if iv := time.Duration(d.IntervalSec) * time.Second; iv < 60*time.Second {
		return 60 * time.Second
	} else {
		return iv
	}
}

// IsEnabled reports whether the daily snapshot job should run (default on).
func (a *AuditArchiveSettings) IsEnabled() bool {
	return a == nil || a.Enabled == nil || *a.Enabled
}

// RetentionDaysOrDefault returns the local snapshot retention (default 30).
func (a *AuditArchiveSettings) RetentionDaysOrDefault() int {
	if a == nil || a.RetentionDays <= 0 {
		return 30
	}
	return a.RetentionDays
}

// AuditQuerySettings governs console log-query resource usage and the
// emergency degraded mode. Unlike retention settings (snapshotted at boot,
// require a restart), these apply immediately on publish. The query path
// runs on dedicated query_only connections, but a storm of heavy scans can
// still eat disk IO - these limits keep the blast radius bounded.
type AuditQuerySettings struct {
	// Degraded: when true, history/aggregation log queries are rejected
	// with 503 so console scans can never compete with forwarding
	// (emergency switch, e.g. during an attack storm).
	Degraded *bool `json:"degraded,omitempty"`
	// MaxConcurrent caps concurrent history/aggregation queries
	// (default 2; extra requests get 429 instead of piling up).
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	// TimeoutMs bounds a single query end to end (default 5000; the store
	// itself also enforces a 5s read timeout on its connections).
	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// DegradedOrDefault reports whether log queries should be rejected.
func (q *AuditQuerySettings) DegradedOrDefault() bool {
	return q != nil && q.Degraded != nil && *q.Degraded
}

// MaxConcurrentOrDefault caps the query concurrency (default 2, max 8).
func (q *AuditQuerySettings) MaxConcurrentOrDefault() int {
	if q == nil || q.MaxConcurrent <= 0 || q.MaxConcurrent > 8 {
		return 2
	}
	return q.MaxConcurrent
}

// TimeoutOrDefault bounds a single query (default 5s, clamp 1s..30s).
func (q *AuditQuerySettings) TimeoutOrDefault() time.Duration {
	if q == nil || q.TimeoutMs <= 0 {
		return 5 * time.Second
	}
	d := time.Duration(q.TimeoutMs) * time.Millisecond
	if d < time.Second {
		return time.Second
	}
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

// MetricsSettings toggles the optional Prometheus text endpoint (/metrics).
type MetricsSettings struct {
	Enabled bool `json:"enabled"`
	// Push optionally forwards the same Prometheus text exposition to a
	// remote receiver (e.g. a Pushgateway or a metrics collector endpoint):
	// the full /metrics body is POSTed every interval. Hot-adding a target
	// requires a restart (the pusher is assembled at boot).
	Push *MetricsPushSettings `json:"push,omitempty"`
}

// MetricsPushSettings configures the outbound metrics push target.
type MetricsPushSettings struct {
	// URL is the receiver endpoint; the Prometheus text body is POSTed there
	// (e.g. http://pushgateway:9091/metrics/job/kingmoat).
	URL string `json:"url"`
	// IntervalSec is the push interval (default 30, min 5).
	IntervalSec int `json:"interval_sec,omitempty"`
	// BearerToken is sent as "Authorization: Bearer <token>" when set.
	BearerToken string `json:"bearer_token,omitempty"`
}

// IntervalOrDefault returns the push interval (min 5s, default 30s).
func (p *MetricsPushSettings) IntervalOrDefault() time.Duration {
	if p == nil || p.IntervalSec <= 0 {
		return 30 * time.Second
	}
	if d := time.Duration(p.IntervalSec) * time.Second; d < 5*time.Second {
		return 5 * time.Second
	} else {
		return d
	}
}

// Validate checks the push target (only when enabled).
func (p *MetricsPushSettings) Validate() error {
	if p == nil {
		return nil
	}
	if p.URL == "" {
		return fmt.Errorf("metrics: push url is required")
	}
	if !strings.HasPrefix(p.URL, "http://") && !strings.HasPrefix(p.URL, "https://") {
		return fmt.Errorf("metrics: push url must be http(s)")
	}
	return nil
}

// ConsoleSecuritySettings bundles console security policy (user management →
// security settings): password rules and session lifetime.
type ConsoleSecuritySettings struct {
	// PasswordMinLen is the minimum password length for user
	// create/change-password (default 8; existing passwords are unaffected).
	PasswordMinLen int `json:"password_min_len,omitempty"`
	// PasswordComplexity requires upper+lower+digit when true.
	PasswordComplexity bool `json:"password_complexity,omitempty"`
	// PasswordMaxAgeDays forces a password change after N days (0 = off).
	// Enforced at login via users.password_changed_at.
	PasswordMaxAgeDays int `json:"password_max_age_days,omitempty"`
	// SessionTimeoutMin bounds the console session lifetime (default 0 =
	// 12h). Snapshotted at boot; changes require a restart.
	SessionTimeoutMin int `json:"session_timeout_min,omitempty"`
	// LoginMaxFailures bounds failed logins per source IP inside the
	// lockout window (default 10; values below 3 are clamped to 3).
	LoginMaxFailures int `json:"login_max_failures,omitempty"`
	// LoginLockoutMin is the sliding lockout window in minutes (default 15).
	LoginLockoutMin int `json:"login_lockout_min,omitempty"`
	// PasswordHistoryCount blocks reusing any of the last N passwords
	// (default 0 = off; max 24).
	PasswordHistoryCount int `json:"password_history_count,omitempty"`
}

// TelemetrySettings opts in to anonymous install statistics. Default nil
// (= absent from config) means disabled: no requests, no local state. The
// collected set is deliberately minimal (random install ID, version,
// OS/arch, install method) and is documented in the README telemetry
// disclosure. DO_NOT_TRACK always wins over this switch.
type TelemetrySettings struct {
	Enabled bool `json:"enabled,omitempty"`
}

// MinLenOrDefault returns the effective password minimum length (default 8).
func (s *ConsoleSecuritySettings) MinLenOrDefault() int {
	if s == nil || s.PasswordMinLen <= 0 {
		return 8
	}
	return s.PasswordMinLen
}

// MaxAgeOrDefault returns the password max age in days (0 = off).
func (s *ConsoleSecuritySettings) MaxAgeOrDefault() int {
	if s == nil || s.PasswordMaxAgeDays < 0 {
		return 0
	}
	return s.PasswordMaxAgeDays
}

// SessionTTLOrDefault returns the effective session TTL.
func (s *ConsoleSecuritySettings) SessionTTLOrDefault() time.Duration {
	if s == nil || s.SessionTimeoutMin <= 0 {
		return 12 * time.Hour
	}
	return time.Duration(s.SessionTimeoutMin) * time.Minute
}

// LoginMaxFailuresOrDefault returns the failed-login threshold (default 10,
// clamped to >= 3 so the protection never becomes decorative).
func (s *ConsoleSecuritySettings) LoginMaxFailuresOrDefault() int {
	if s == nil || s.LoginMaxFailures <= 0 {
		return 10
	}
	if s.LoginMaxFailures < 3 {
		return 3
	}
	return s.LoginMaxFailures
}

// LoginLockoutOrDefault returns the sliding lockout window (default 15
// minutes, clamped to 1 minute .. 24 hours).
func (s *ConsoleSecuritySettings) LoginLockoutOrDefault() time.Duration {
	if s == nil || s.LoginLockoutMin <= 0 {
		return 15 * time.Minute
	}
	d := time.Duration(s.LoginLockoutMin) * time.Minute
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

// PasswordHistoryCountOrDefault returns how many previous passwords are
// blocked on change (0 = off, clamped to <= 24).
func (s *ConsoleSecuritySettings) PasswordHistoryCountOrDefault() int {
	if s == nil || s.PasswordHistoryCount <= 0 {
		return 0
	}
	if s.PasswordHistoryCount > 24 {
		return 24
	}
	return s.PasswordHistoryCount
}

// ValidatePassword checks a new password against the policy; err explains
// the first violated rule.
func (s *ConsoleSecuritySettings) ValidatePassword(password string) error {
	minLen := s.MinLenOrDefault()
	if len(password) < minLen {
		return fmt.Errorf("密码长度至少 %d 位", minLen)
	}
	if s != nil && s.PasswordComplexity {
		var hasUpper, hasLower, hasDigit bool
		for _, c := range password {
			switch {
			case 'A' <= c && c <= 'Z':
				hasUpper = true
			case 'a' <= c && c <= 'z':
				hasLower = true
			case '0' <= c && c <= '9':
				hasDigit = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit {
			return fmt.Errorf("密码需同时包含大写字母、小写字母和数字")
		}
	}
	return nil
}

// EnabledOrDefault reports whether /metrics should serve (default off).
func (m *MetricsSettings) EnabledOrDefault() bool {
	return m != nil && m.Enabled
}

// AuditRetentionDaysOrDefault returns the live audit-event retention
// (default 7; negative means never purge).
func (c *Config) AuditRetentionDaysOrDefault() int {
	if c.AuditRetentionDays == 0 {
		return 7
	}
	return c.AuditRetentionDays
}

// ApiAssetsSettings configures passive API inventory learning from traffic.
type ApiAssetsSettings struct {
	Enabled    bool    `json:"enabled"`
	SampleRate float64 `json:"sample_rate,omitempty"` // default 1.0
	// MinHits is the hit count before a candidate path is promoted to a
	// confirmed asset (scanner noise suppression).
	MinHits   int `json:"min_hits,omitempty"`   // default 5
	PurgeDays int `json:"purge_days,omitempty"` // drop assets unseen for N days, default 90
	// DbPath overrides the SQLite location (default: derived from console db).
	DbPath string `json:"db_path,omitempty"`
}

// Sample returns the effective sampling rate clamped to (0, 1].
func (a *ApiAssetsSettings) Sample() float64 {
	if a == nil || a.SampleRate <= 0 || a.SampleRate > 1 {
		return 1.0
	}
	return a.SampleRate
}

// MinHitsOrDefault returns the promotion threshold (default 5).
func (a *ApiAssetsSettings) MinHitsOrDefault() int {
	if a == nil || a.MinHits <= 0 {
		return 5
	}
	return a.MinHits
}

// PurgeDaysOrDefault returns the stale-asset retention (default 90).
func (a *ApiAssetsSettings) PurgeDaysOrDefault() int {
	if a == nil || a.PurgeDays <= 0 {
		return 90
	}
	return a.PurgeDays
}

// RisksSettings configures the observe-only risk engine.
type RisksSettings struct {
	Enabled bool `json:"enabled"`
	// Cron schedule for the batch analyzer (default "0 2 * * *" is applied
	// by the runtime when empty).
	Cron string `json:"cron,omitempty"`
	// Bruteforce threshold for R3 (login brute force), default 30 req / 300s.
	Bruteforce    RateThreshold `json:"bruteforce,omitempty"`
	ZombieDays    int           `json:"zombie_days,omitempty"`    // R5, default 30
	NotifyWebhook string        `json:"notify_webhook,omitempty"` // generic POST target
}

// Load reads and validates a JSON config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks structural invariants before any listener starts.
func (c *Config) Validate() error {
	if c.ListenHTTP == "" && c.ListenHTTPS == "" {
		return fmt.Errorf("config: at least one of listen_http / listen_https is required")
	}
	groups := map[string]bool{}
	for i, g := range c.IPGroups {
		if g.Name == "" {
			return fmt.Errorf("config: ip_groups[%d].name is empty", i)
		}
		if groups[g.Name] {
			return fmt.Errorf("config: ip_groups[%d]: duplicate name %q", i, g.Name)
		}
		groups[g.Name] = true
		if (g.URL == "") == (g.File == "") {
			return fmt.Errorf("config: ip_groups[%d] (%s): exactly one of url / file is required", i, g.Name)
		}
	}
	if c.Webhook != nil && !isHTTPURL(c.Webhook.URL) {
		return fmt.Errorf("config: webhook.url must be an http(s) URL")
	}
	if c.LogShipper != nil {
		ls := c.LogShipper
		switch ls.Type {
		case "elasticsearch", "loki", "clickhouse":
			if !isHTTPURL(ls.URL) {
				return fmt.Errorf("config: log_shipper.url must be an http(s) URL")
			}
		case "s3":
			if ls.Endpoint == "" || ls.Bucket == "" || ls.AccessKey == "" || ls.SecretKey == "" {
				return fmt.Errorf("config: log_shipper (s3): endpoint, bucket, access_key and secret_key are required")
			}
		case "syslog":
			if err := ls.Syslog.Validate(); err != nil {
				return fmt.Errorf("config: log_shipper (syslog): %w", err)
			}
			if err := validateSyslogURL(ls.URL); err != nil {
				return err
			}
		case "kafka":
			nBrokers := 0
			for _, b := range ls.Brokers {
				if strings.TrimSpace(b) != "" {
					nBrokers++
				}
			}
			if nBrokers == 0 {
				return fmt.Errorf("config: log_shipper (kafka): at least one broker is required")
			}
			if strings.TrimSpace(ls.Topic) == "" {
				return fmt.Errorf("config: log_shipper (kafka): topic is required")
			}
			switch ls.SASL {
			case "", "none", "plain", "scram-sha256":
			default:
				return fmt.Errorf("config: log_shipper (kafka): sasl must be \"none\", \"plain\" or \"scram-sha256\", got %q", ls.SASL)
			}
			// plain / scram authenticate with SASL credentials: an empty
			// username or password would make the shipper fail its handshake
			// (or worse, silently stall) — reject it up front.
			if ls.SASL == "plain" || ls.SASL == "scram-sha256" {
				if strings.TrimSpace(ls.Username) == "" || strings.TrimSpace(ls.Password) == "" {
					return fmt.Errorf("config: log_shipper (kafka): sasl %q requires both username and password", ls.SASL)
				}
			}
		default:
			return fmt.Errorf("config: log_shipper.type must be \"elasticsearch\", \"loki\", \"clickhouse\", \"s3\", \"kafka\" or \"syslog\", got %q", ls.Type)
		}
	}
	// Collect every failing site so one broken entry does not hide the
	// problems of the rest (per-site publish relies on the full list).
	siteErrs := make([]error, 0, len(c.Sites))
	for i := range c.Sites {
		if err := c.validateSite(i, &c.Sites[i], groups); err != nil {
			siteErrs = append(siteErrs, err)
		}
	}
	if len(siteErrs) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "config: %d site(s) invalid:", len(siteErrs))
		for _, e := range siteErrs {
			b.WriteString("\n  ")
			b.WriteString(e.Error())
		}
		return errors.New(b.String())
	}
	// Cross-site duplicate-domain check: the data-plane router rejects
	// duplicate domains at build time (buildRouter), so a conflicting publish
	// would apply on the console but fail to reload on every node
	// (apply_error). Reject it up front instead. Normalization matches the
	// router (lower-case, trimmed). Wildcard entries are skipped: "*.a.com"
	// overlapping "a.com" is a legitimate apex/subdomain combination, and
	// exact wildcard duplicates never route by exact-match anyway.
	seenDomains := map[string]string{}
	for i := range c.Sites {
		label := c.Sites[i].Name
		if label == "" && len(c.Sites[i].Domains) > 0 {
			label = c.Sites[i].Domains[0]
		}
		for _, d := range c.Sites[i].Domains {
			dn := strings.ToLower(strings.TrimSpace(d))
			if dn == "" || strings.Contains(dn, "*") {
				continue
			}
			if prev, dup := seenDomains[dn]; dup {
				return fmt.Errorf("config: duplicate domain %q in sites %q and %q (a domain may only belong to one site)", dn, prev, label)
			}
			seenDomains[dn] = label
		}
	}
	if err := c.Policy.Validate(); err != nil {
		return err
	}
	// Variant-engine caps: a config exceeding them would pass validation,
	// get stored, and only fail at data-plane reload (console shows success
	// while the engine keeps the old state; cold starts would exit). Reject
	// the publish up front instead — the coraza stage re-checks with the
	// same caps and wording.
	if err := c.validateScopedDisableLimits(); err != nil {
		return err
	}
	if err := c.BlockPage.Validate(); err != nil {
		return err
	}
	if c.Metrics != nil && c.Metrics.Enabled {
		if err := c.Metrics.Push.Validate(); err != nil {
			return err
		}
	}
	if err := c.Console.Validate(); err != nil {
		return err
	}
	if c.DiskGuard != nil && c.DiskGuard.Enabled && c.DiskGuard.LowPct >= c.DiskGuard.HighPct && c.DiskGuard.HighPct > 0 {
		return fmt.Errorf("config: disk_guard.low_pct must be lower than high_pct")
	}
	return nil
}

// validateScopedDisableLimits enforces the pre-compiled coraza variant
// engine caps across all WAF-enabled sites: the per-site scoped-rule cap
// (MaxScopedCorazaRulesPerSite, via ScopedCorazaExclusionSets) and the
// global variant budget (MaxTotalCorazaVariants).
func (c *Config) validateScopedDisableLimits() error {
	if c.Policy == nil {
		return nil
	}
	total := 0
	for i := range c.Sites {
		s := &c.Sites[i]
		if !s.WAF.IsEnabled() {
			continue
		}
		sets, err := ScopedCorazaExclusionSets(c.Policy, s.Domains)
		if err != nil {
			return fmt.Errorf("config: sites[%d] (%s): %w", i, strings.Join(s.Domains, ","), err)
		}
		total += len(sets)
	}
	if total > MaxTotalCorazaVariants {
		return fmt.Errorf("config: %d coraza variant engines would be pre-compiled across all sites (max %d): reduce coraza:<category> disable rules or merge them per site", total, MaxTotalCorazaVariants)
	}
	return nil
}

// validDomainEntry validates one site domain entry: letters, digits, dot,
// hyphen, wildcard star and IPv6 colon are allowed. Anything else — commas
// (the "a.com,b.com" paste accident), whitespace, full-width characters — is
// rejected so a typo can never silently become a literal routed hostname.
func validDomainEntry(s string) bool {	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '*' || r == ':':
		default:
			return false
		}
	}
	return true
}

// validateSite checks one site entry. The error carries the site index so
// batch validation can report every failing site at once (see Validate).
// Validate checks the upstream SNI options: sni_forward and sni_host are
// mutually exclusive, and sni_host must be a bare hostname (no scheme,
// port, path or whitespace — SNI carries a DNS name only).
func (u *Upstream) Validate() error {
	if u.SNIForward && u.SNIHost != "" {
		return fmt.Errorf("upstream: sni_forward and sni_host are mutually exclusive")
	}
	if u.SNIHost != "" && !validSNIHostname(u.SNIHost) {
		return fmt.Errorf("upstream: sni_host %q is not a valid hostname (bare DNS name only: no scheme, port, path or whitespace)", u.SNIHost)
	}
	return nil
}

// validSNIHostname reports whether s is a bare DNS hostname: letters,
// digits, dot and hyphen only. Everything else — "https://" scheme,
// host:port colons, path slashes, whitespace or full-width characters —
// is rejected; SNI never carries a scheme, port or path.
func validSNIHostname(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// ValidAlgorithms lists the supported load-balancing algorithms.


func (c *Config) validateSite(i int, s *Site, groups map[string]bool) error {
	if err := s.Upstream.Validate(); err != nil {
		return fmt.Errorf("config: sites[%d]: %w", i, err)
	}
		if len(s.Domains) == 0 {
			return fmt.Errorf("config: sites[%d].domains is empty", i)
		}
		for _, d := range s.Domains {
			if !validDomainEntry(d) {
				return fmt.Errorf("config: sites[%d].domains: %q is not a valid domain (no commas, spaces or full-width characters)", i, d)
			}
		}
		if len(s.Upstream.Nodes) == 0 {
			return fmt.Errorf("config: sites[%d].upstream.nodes is empty", i)
		}
		if s.Mode != "" && s.Mode != "intercept" && s.Mode != "monitor" {
			return fmt.Errorf("config: sites[%d].mode must be \"intercept\" or \"monitor\", got %q", i, s.Mode)
		}
		if err := ValidateTLSProfile(s.TLSProfile); err != nil {
			return fmt.Errorf("config: sites[%d]: %w", i, err)
		}
		if (s.TLSCert == "") != (s.TLSKey == "") {
			return fmt.Errorf("config: sites[%d] must set both tls_cert and tls_key", i)
		}
		if s.ACME != nil {
			if s.ACME.Email == "" && c.AcmeEmail == "" {
				return fmt.Errorf("config: sites[%d].acme requires acme_email (settings) or a per-site email", i)
			}
			if c.ListenHTTPS == "" {
				return fmt.Errorf("config: sites[%d].acme requires a global listen_https", i)
			}
		}
		if s.RedirectToHTTPS {
			if s.TLSCert == "" && s.ACME == nil {
				return fmt.Errorf("config: sites[%d].redirect_to_https requires tls_cert/tls_key or acme", i)
			}
			if c.ListenHTTPS == "" {
				return fmt.Errorf("config: sites[%d].redirect_to_https requires a global listen_https", i)
			}
		}
		if s.Health != nil && s.Health.Enabled && s.Health.Path != "" && !strings.HasPrefix(s.Health.Path, "/") {
			return fmt.Errorf("config: sites[%d].health.path must start with /", i)
		}
		if s.WAF != nil {
			switch s.WAF.BodyOverLimit {
			case "", "bypass", "reject", "stream":
			default:
				return fmt.Errorf("config: sites[%d].waf.body_over_limit must be \"bypass\", \"reject\" or \"stream\", got %q", i, s.WAF.BodyOverLimit)
			}
			if s.WAF.CustomRulesFile != "" {
				if _, err := os.Stat(s.WAF.CustomRulesFile); err != nil {
					return fmt.Errorf("config: sites[%d].waf.custom_rules_file: %w", i, err)
				}
			}
			for _, cat := range s.WAF.Categories {
				if !ValidWAFCategory(cat) {
					return fmt.Errorf("config: sites[%d].waf.categories: %q is not a valid category (valid: %s)", i, cat, strings.Join(WAFDetectionCategories, ", "))
				}
			}
		}
		if s.Security != nil {
			if err := s.Security.validateGroups(groups); err != nil {
				return fmt.Errorf("config: sites[%d]: %w", i, err)
			}
			if err := s.Security.Validate(); err != nil {
				return fmt.Errorf("config: sites[%d]: %w", i, err)
			}
		}
		if s.RealIP != nil && s.RealIP.Enabled {
			if len(s.RealIP.TrustedProxies) == 0 {
				return fmt.Errorf("config: sites[%d].real_ip: trusted_proxies is required when enabled", i)
			}
			for _, c := range s.RealIP.TrustedProxies {
				if !validCIDR(c) {
					return fmt.Errorf("config: sites[%d].real_ip.trusted_proxies: %q is not a valid IP or CIDR", i, c)
				}
			}
		}
		if s.Headers != nil {
			if err := s.Headers.Validate(); err != nil {
				return fmt.Errorf("config: sites[%d].headers: %w", i, err)
			}
		}
		for j := range s.Upstream.Nodes {
			if s.Upstream.Nodes[j].Address == "" {
				return fmt.Errorf("config: sites[%d].upstream.nodes[%d].address is empty", i, j)
			}
		}
		switch s.Upstream.Algorithm {
		case "", "wrr", "least_conn", "source_ip":
		default:
			return fmt.Errorf("config: sites[%d].upstream.algorithm must be wrr, least_conn or source_ip, got %q", i, s.Upstream.Algorithm)
		}
		return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// EmailSettings configures the SMTP notification channel.
type EmailSettings struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	From     string   `json:"from"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	SSL      bool     `json:"ssl,omitempty"`
	To       []string `json:"to"`
}

// Validate checks the email channel.
func (e *EmailSettings) Validate() error {
	if e == nil || !e.Enabled {
		return nil
	}
	if e.Host == "" || e.Port <= 0 || e.From == "" || len(e.To) == 0 {
		return fmt.Errorf("email: host/port/from/to are required when enabled")
	}
	if e.Port > 65535 {
		return fmt.Errorf("email: invalid port")
	}
	return nil
}

// AlertsSettings configures the WAF anomaly alert engine.
type AlertsSettings struct {
	Enabled       bool       `json:"enabled"`
	Rules         AlertRules `json:"rules,omitempty"`
	IntervalSec   int        `json:"interval_sec,omitempty"`
	CooldownMin   int        `json:"cooldown_min,omitempty"`
	NotifyWebhook bool       `json:"notify_webhook,omitempty"`
	NotifyEmail   bool       `json:"notify_email,omitempty"`
}

// AlertRules are the WAF anomaly thresholds.
type AlertRules struct {
	// Legacy flat fields (kept for old configs; mapped onto the new rules
	// when the structured form is absent).
	CPUHighPct    int `json:"cpu_high_pct,omitempty"`
	MemHighPct    int `json:"mem_high_pct,omitempty"`
	QPSHigh       int `json:"qps_high,omitempty"`
	AttackSpikePc int `json:"attack_spike_pct,omitempty"`
	// Structured rules (user-adjustable thresholds; all optional, defaults
	// apply when nil). Windows: cpu/mem = 1-min average sample, disk =
	// instantaneous, web_requests/web_attacks/blocked = 1-min event count,
	// top_attack_ip/top_target = 1-h per-key count.
	CPU       *AlertRule `json:"cpu,omitempty"`
	Mem       *AlertRule `json:"mem,omitempty"`
	Disk      *AlertRule `json:"disk,omitempty"`
	Requests  *AlertRule `json:"web_requests,omitempty"`
	Attacks   *AlertRule `json:"web_attacks,omitempty"`
	Blocked   *AlertRule `json:"blocked,omitempty"`
	TopIP     *AlertRule `json:"top_attack_ip,omitempty"`
	TopTarget *AlertRule `json:"top_target,omitempty"`
}

// AlertRule is one adjustable threshold. For resource rules (cpu/mem) the
// threshold must be exceeded continuously for WindowSec before firing;
// for count rules (requests/attacks/etc.) WindowSec is the evaluation
// window. 0 uses the built-in default (60s for cpu/mem, 60s evaluation
// interval for the rest).
type AlertRule struct {
	Enabled   bool `json:"enabled"`
	Threshold int  `json:"threshold"` // pct for cpu/mem/disk, count for the rest
	WindowSec int  `json:"window_sec,omitempty"` // continuous-over/window duration
}

// ruleDefault returns the rule with the default threshold applied.
func ruleDefault(r *AlertRule, def int) AlertRule {
	if r != nil && r.Threshold > 0 {
		return AlertRule{Enabled: r.Enabled, Threshold: r.Threshold}
	}
	return AlertRule{Enabled: r == nil || r.Enabled, Threshold: def}
}

// Validate checks the alert settings.
func (a *AlertsSettings) Validate() error {
	if a == nil || !a.Enabled {
		return nil
	}
	if a.IntervalSec > 0 && a.IntervalSec < 10 {
		return fmt.Errorf("alerts: interval_sec must be >= 10")
	}
	return nil
}

// IntervalOrDefault returns the evaluation period.
func (a *AlertsSettings) IntervalOrDefault() time.Duration {
	if a == nil || a.IntervalSec <= 0 {
		return 60 * time.Second
	}
	return time.Duration(a.IntervalSec) * time.Second
}

// CooldownOrDefault returns the per-rule silence window.
func (a *AlertsSettings) CooldownOrDefault() time.Duration {
	if a == nil || a.CooldownMin <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(a.CooldownMin) * time.Minute
}

// RulesOrDefault returns thresholds with defaults filled.
func (a *AlertsSettings) RulesOrDefault() AlertRules {
	var rules AlertRules
	if a != nil {
		rules = a.Rules
	}
	cpuR := ruleDefault(rules.CPU, 80)
	memR := ruleDefault(rules.Mem, 80)
	diskR := ruleDefault(rules.Disk, 80)
	reqR := ruleDefault(rules.Requests, 20000)
	atkR := ruleDefault(rules.Attacks, 10000)
	blkR := ruleDefault(rules.Blocked, 10000)
	ipR := ruleDefault(rules.TopIP, 20000)
	tgtR := ruleDefault(rules.TopTarget, 20000)
	// Legacy flat fields map onto the new rules when no structured value was
	// saved (old configs keep their thresholds; attack_spike is retired in
	// favor of the absolute web_attacks rule).
	if rules.CPU == nil && rules.CPUHighPct > 0 {
		cpuR.Threshold = rules.CPUHighPct
	}
	if rules.Mem == nil && rules.MemHighPct > 0 {
		memR.Threshold = rules.MemHighPct
	}
	if rules.Requests == nil && rules.QPSHigh > 0 {
		reqR.Threshold = rules.QPSHigh * 60 // qps → per-minute
	}
	out := AlertRules{
		CPU: &cpuR, Mem: &memR, Disk: &diskR,
		Requests: &reqR, Attacks: &atkR, Blocked: &blkR,
		TopIP: &ipR, TopTarget: &tgtR,
	}
	return out
}
