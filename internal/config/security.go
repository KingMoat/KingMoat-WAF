package config

import (
	"net/url"
	"strings"
	"time"
)

// SecuritySettings groups the per-site protection stages. Every sub-block is
// optional; omitted means the stage is disabled.
type SecuritySettings struct {
	ACL        *ACLSettings        `json:"acl,omitempty"`
	RateLimit  *RateLimitSettings  `json:"ratelimit,omitempty"`
	BotCheck   *BotSettings        `json:"bot,omitempty"`
	BotDetect  *BotDetectSettings  `json:"bot_detect,omitempty"`
	Captcha    *CaptchaSettings    `json:"captcha,omitempty"`
	Geo        *GeoSettings        `json:"geo,omitempty"`
	Auth       *AuthSettings       `json:"auth,omitempty"`
	Semantic   *SemanticSettings   `json:"semantic,omitempty"`
	RespFilter *RespFilterSettings `json:"resp_filter,omitempty"`
	Dynamic    *DynamicSettings    `json:"dynamic,omitempty"`
}

// SemanticSettings enables the libinjection-based lightweight semantic
// detection layer (SQLi/XSS on path, query, referer headers and buffered
// body), independent of the OWASP CRS rule set.
type SemanticSettings struct {
	Enabled    bool `json:"enabled"`
	CheckBody  bool `json:"check_body,omitempty"`  // default on when buffered
	CheckQuery bool `json:"check_query,omitempty"` // default on
}

// ACLSettings configures IP/CIDR access control. Whitelist hits mark the
// request as trusted and skip the remaining detection stages. Entries may be
// a plain IP, a CIDR block, or "group:<name>" referencing a subscribed
// IPGroup defined at the top level.
type ACLSettings struct {
	Blacklist []string `json:"blacklist,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// RateLimitSettings configures CC protection with a fixed-window counter
// per key. Sliding-window refinement is tracked for a later release.
type RateLimitSettings struct {
	Requests  int    `json:"requests"`         // allowed requests per window per key
	WindowSec int    `json:"window_sec"`       // default 60
	Key       string `json:"key,omitempty"`    // "ip" (default) | "ip+uri"
	Action    string `json:"action,omitempty"` // "deny" (403, default) | "throttle" (429)
}

// BotSettings configures the lightweight JS challenge bot check. When a
// site also enables Captcha the slider challenge replaces this stage.
type BotSettings struct {
	Secret     string `json:"secret,omitempty"`      // HMAC secret; empty → random per boot
	CookieName string `json:"cookie_name,omitempty"` // default km_challenge
	TTLMin     int    `json:"ttl_min,omitempty"`     // challenge validity in minutes, default 60
}

// BotDetectSettings configures the observe-first bot classification stage.
// Actions map class → "allow" | "observe" | "deny" | "challenge";
// the default for every class is observe (v0.4 ships with zero interception
// change so operators can review the data first).
type BotDetectSettings struct {
	Enabled bool              `json:"enabled"`
	Actions map[string]string `json:"actions,omitempty"` // good | unknown | bad → action
	// RateThreshold flags clients exceeding requests/window_sec per fingerprint.
	RateThreshold RateThreshold `json:"rate_threshold,omitempty"`
	// GoodBotBypassChallenge lets verified good bots skip the JS challenge.
	GoodBotBypassChallenge bool `json:"good_bot_bypass_challenge,omitempty"`
}

// RateThreshold is a shared requests-per-window rule.
type RateThreshold struct {
	Requests  int `json:"requests"`
	WindowSec int `json:"window_sec,omitempty"` // default 60
}

// Default returns the effective rate threshold (300 req / 60s).
func (t RateThreshold) Defaults() (int, time.Duration) {
	r := t.Requests
	if r <= 0 {
		r = 300
	}
	w := time.Duration(t.WindowSec) * time.Second
	if w <= 0 {
		w = time.Minute
	}
	return r, w
}

// CaptchaSettings configures the slider human-verification challenge.
type CaptchaSettings struct {
	Enabled    bool   `json:"enabled"`
	Secret     string `json:"secret,omitempty"`      // HMAC secret; empty → random per boot
	CookieName string `json:"cookie_name,omitempty"` // default km_captcha
	TTLMin     int    `json:"ttl_min,omitempty"`     // pass validity in minutes, default 60
	Tolerance  int    `json:"tolerance,omitempty"`   // accepted drag offset in px, default 8
}

// GeoSettings configures GeoIP country access control using a MaxMind
// mmdb database (user-supplied file, e.g. GeoLite2-Country.mmdb).
type GeoSettings struct {
	Enabled          bool     `json:"enabled"`
	DBPath           string   `json:"db_path"`             // path to the .mmdb file
	Blacklist        []string `json:"blacklist,omitempty"` // ISO 3166-1 alpha-2 codes
	Whitelist        []string `json:"whitelist,omitempty"`
	WhitelistTrusted bool     `json:"whitelist_trusted,omitempty"` // whitelist hit skips later stages
}

// AuthUser is one account for site-level Basic authentication. Either
// Password (plaintext, for quick internal use) or PasswordHash (argon2id,
// via `kingmoat-cli hash-password`) must be set, not both.
type AuthUser struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// AuthSettings gates the whole site behind HTTP Basic authentication.
type AuthSettings struct {
	Realm string     `json:"realm,omitempty"` // default "Restricted"
	Users []AuthUser `json:"users"`
}

// DynamicSettings enables response dynamic protection: HTML responses are
// encrypted per request and reassembled by injected JavaScript, so the
// wire format changes on every visit. Requires a secure context
// (HTTPS) because the decoder uses WebCrypto.
type DynamicSettings struct {
	Enabled  bool  `json:"enabled"`
	MinBytes int64 `json:"min_bytes,omitempty"` // skip smaller bodies, default 512
	MaxBytes int64 `json:"max_bytes,omitempty"` // skip larger bodies, default 1 MiB
}

// HealthSettings configures upstream pool health: active probing plus
// passive circuit breaking on consecutive failures.
type HealthSettings struct {
	Enabled       bool   `json:"enabled"`
	Path          string `json:"path,omitempty"`           // probe path, default "/"
	IntervalSec   int    `json:"interval_sec,omitempty"`   // active probe interval, default 10
	TimeoutSec    int    `json:"timeout_sec,omitempty"`    // probe timeout, default 3
	Passive       bool   `json:"passive,omitempty"`        // passive circuit breaker, default on
	FailThreshold int    `json:"fail_threshold,omitempty"` // consecutive failures before cooling down, default 3
	CooldownSec   int    `json:"cooldown_sec,omitempty"`   // passive cooldown, default 30
}

// RespPattern is a custom response-body detection pattern.
type RespPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// RespFilterSettings configures response-body sensitive-information
// filtering. Presets: "phone", "idcard", "secret".
type RespFilterSettings struct {
	Enabled   bool          `json:"enabled"`
	Action    string        `json:"action,omitempty"` // "mask" (default) | "block"
	Presets   []string      `json:"presets,omitempty"`
	Patterns  []RespPattern `json:"patterns,omitempty"`
	BodyLimit int64         `json:"body_limit,omitempty"` // response scan size cap, default 8 MiB
}

// WebhookSettings pushes every blocked/challenged event to an HTTP endpoint
// (POST JSON, asynchronous queue, drops under backpressure).
type WebhookSettings struct {
	URL        string `json:"url"`
	TimeoutSec int    `json:"timeout_sec,omitempty"` // default 5
	// Secret enables HMAC-SHA256 signing: each POST gets a
	// "X-KingMoat-Signature: sha256=<hex>" header over the raw body so the
	// receiver can verify authenticity.
	Secret string `json:"secret,omitempty"`
	// Keyword appends a "keyword" field to the JSON payload (企业微信/
	// 钉钉机器人关键词安全设置)。Empty = no keyword.
	Keyword string `json:"keyword,omitempty"`

	S3 *S3Settings `json:"s3,omitempty"`
}

// ShipperSettings streams audit events to an external log platform or
// S3-compatible object storage.
type ShipperSettings struct {
	Type       string `json:"type"`                  // "clickhouse" | "elasticsearch" | "loki" | "s3" | "syslog"
	URL        string `json:"url,omitempty"`          // base URL for es/loki/ch (http://...), syslog target (udp|tcp|tls://host:514)
	Index      string `json:"index,omitempty"`        // table / index prefix / label app (default kingmoat)
	BatchSize  int    `json:"batch_size,omitempty"`   // default 100
	FlushSec   int    `json:"flush_sec,omitempty"`    // default 5
	TimeoutSec int    `json:"timeout_sec,omitempty"` // default 5
	// S3-compatible object storage (type "s3"): MinIO, Alibaba Cloud OSS,
	// Huawei Cloud OBS, AWS S3, ... Events are shipped as gzipped NDJSON
	// objects; the daily DB snapshots can be uploaded too (upload_archives).
	Endpoint  string `json:"endpoint,omitempty"` // host[:port], e.g. minio.example.com:9000
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Region    string `json:"region,omitempty"`
	// Username / Password enable HTTP basic authentication for the
	// elasticsearch / loki / clickhouse sinks (internal deployments commonly
	// require it). Empty = no Authorization header sent.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// UseSSL defaults to the endpoint scheme (https → true, no scheme → true).
	UseSSL *bool `json:"use_ssl,omitempty"`
	// Prefix is the object-key prefix (default "kingmoat/audit").
	Prefix string `json:"prefix,omitempty"`
	// UploadArchives also uploads the daily SQLite snapshot files
	// (type "s3" only, default off).
	UploadArchives bool `json:"upload_archives,omitempty"`
	// Syslog holds the standard-syslog transport options (type "syslog").
	Syslog *SyslogSettings `json:"syslog,omitempty"`
	// Kafka (type "kafka"): bootstrap broker list + topic. Events ship as
	// one JSON message per audit event, keyed by trace_id when present.
	Brokers []string `json:"brokers,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	// UseTLS enables TLS for the kafka connection (default plaintext).
	// SASL reuses Username / Password: "plain" or "scram-sha256" (empty =
	// no authentication).
	UseTLS bool `json:"use_tls,omitempty"`
	SASL   string `json:"sasl,omitempty"`
	// TLSSkipVerify controls broker-certificate verification when UseTLS is
	// on (type "kafka"). nil (absent) keeps the legacy zero-config behavior
	// for internal self-signed brokers (certificates NOT verified); an
	// explicit false enables chain verification.
	TLSSkipVerify *bool `json:"tls_skip_verify,omitempty"`
}

// SyslogSettings configures a standard syslog (RFC 5424 / RFC 3164) sink.
// The target address comes from the shipper URL: udp://host:514,
// tcp://host:514 or tls://host:6514 (Protocol overrides the URL scheme).
type SyslogSettings struct {
	// Protocol is the transport: "udp" (default), "tcp" or "tls". Overrides
	// the URL scheme when set.
	Protocol string `json:"protocol,omitempty"`
	// Format is the message format: "rfc5424" (default) or "rfc3164".
	Format string `json:"format,omitempty"`
	// Framing is the TCP/TLS framing: "octet" (RFC 6587 octet counting,
	// default for RFC 5424) or "newline" (legacy, default for RFC 3164).
	Framing string `json:"framing,omitempty"`
	// Facility is the syslog facility 0..23; 0 (kernel) means "unset" and
	// defaults to 16 (local0).
	Facility int `json:"facility,omitempty"`
	// Severity is the default severity 0..7; 0 (emerg) means "unset" and
	// defaults to 6 (info). Blocked and challenged events ship as warning
	// (4) regardless of this setting.
	Severity int `json:"severity,omitempty"`
	// Hostname is the syslog HOSTNAME field (default: local hostname).
	Hostname string `json:"hostname,omitempty"`
	// AppName overrides the program name (APP-NAME / tag); default is the
	// shipper index ("kingmoat" / "kingmoat_access").
	AppName string `json:"app_name,omitempty"`
	// TLSSkipVerify disables certificate verification for tls:// targets.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
}

// Validate checks the syslog settings; nil is valid (feature unused).
func (s *SyslogSettings) Validate() error {
	if s == nil {
		return nil
	}
	switch s.Protocol {
	case "", "udp", "tcp", "tls":
	default:
		return errSecurityf("syslog: protocol must be udp, tcp or tls, got %q", s.Protocol)
	}
	switch s.Format {
	case "", "rfc5424", "rfc3164":
	default:
		return errSecurityf("syslog: format must be rfc5424 or rfc3164, got %q", s.Format)
	}
	switch s.Framing {
	case "", "octet", "newline":
	default:
		return errSecurityf("syslog: framing must be octet or newline, got %q", s.Framing)
	}
	if s.Facility < 0 || s.Facility > 23 {
		return errSecurityf("syslog: facility must be 0..23, got %d", s.Facility)
	}
	if s.Severity < 0 || s.Severity > 7 {
		return errSecurityf("syslog: severity must be 0..7, got %d", s.Severity)
	}
	return nil
}

// AccessLogSettings configures the full access-log pipeline. Entries are
// batched and pushed to ClickHouse/Elasticsearch/Loki asynchronously; the
// request hot path only pays a bounded-queue send (drops under backpressure
// are counted). Nothing is stored locally.
type AccessLogSettings struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`            // "clickhouse" | "elasticsearch" | "loki" | "s3" | "syslog"
	URL     string `json:"url,omitempty"`   // base URL (HTTP backends; syslog target for syslog; unused for s3)
	Index   string `json:"index,omitempty"` // table / index prefix / bucket (default kingmoat_access)
	// SamplePct keeps only N percent of entries (1..100); default 100.
	SamplePct  int `json:"sample_pct,omitempty"`
	BatchSize  int `json:"batch_size,omitempty"`  // default 200
	FlushSec   int `json:"flush_sec,omitempty"`   // default 5
	TimeoutSec int `json:"timeout_sec,omitempty"` // default 5
	// S3 sink settings (type = "s3"; MinIO / OSS / OBS / AWS S3 compatible).
	S3 *S3Settings `json:"s3,omitempty"`
	// Username / Password enable HTTP basic authentication for the
	// clickhouse / elasticsearch / loki backends. Empty = no auth header.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Syslog holds the standard-syslog transport options (type "syslog").
	Syslog *SyslogSettings `json:"syslog,omitempty"`
}

// SamplePctOrDefault returns the effective sampling percentage (default 100).
func (a *AccessLogSettings) SamplePctOrDefault() int {
	if a == nil || a.SamplePct <= 0 || a.SamplePct > 100 {
		return 100
	}
	return a.SamplePct
}

// validateSyslogURL checks the syslog target address: scheme udp://, tcp://
// or tls:// plus host[:port] (no path). A bare host is accepted (defaults to
// udp://host:514 at the sink).
func validateSyslogURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errSecurityf("syslog: url must be udp://host[:514], tcp://host[:514] or tls://host[:6514], got %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "udp", "tcp", "tls":
		if u.Path != "" && u.Path != "/" {
			return errSecurityf("syslog: url must not contain a path, got %q", raw)
		}
		return nil
	case "":
		if u.Path != "" && u.Path != "/" {
			return errSecurityf("syslog: url must not contain a path, got %q", raw)
		}
		return nil // bare host[:port]; transport defaults to udp
	default:
		return errSecurityf("syslog: url scheme must be udp, tcp or tls, got %q", raw)
	}
}

// IPGroupSettings subscribes an IP list from a URL or a local file. Lists
// may contain comments (#) and one IP/CIDR per line; ACL entries reference
// them as "group:<name>".
type IPGroupSettings struct {
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"`
	File        string `json:"file,omitempty"`
	IntervalMin int    `json:"interval_min,omitempty"` // refresh interval, default 60
	// Members is a manually maintained list (IP/CIDR per entry). When set the
	// group needs no subscription source; it loads once per config revision.
	Members []string `json:"members,omitempty"`
}

// validateGroups checks that every ACL "group:<name>" reference resolves
// to a subscribed IP group defined at the top level.
func (s *SecuritySettings) validateGroups(groups map[string]bool) error {
	if s.ACL == nil {
		return nil
	}
	for _, c := range append(append([]string{}, s.ACL.Blacklist...), s.ACL.Whitelist...) {
		if isGroupRef(c) && !groups[c[6:]] {
			return errSecurityf("acl: %q references an unknown ip_group", c)
		}
	}
	return nil
}

// Validate checks the security sub-blocks (called from Config.Validate).
func (s *SecuritySettings) Validate() error {
	if s.ACL != nil {
		for _, c := range append(append([]string{}, s.ACL.Blacklist...), s.ACL.Whitelist...) {
			if isGroupRef(c) {
				continue // existence checked against ip_groups by Config.Validate
			}
			if !validCIDR(c) {
				return errSecurityf("acl: %q is not a valid IP, CIDR or group reference", c)
			}
		}
	}
	if s.RateLimit != nil {
		rl := s.RateLimit
		if rl.Requests <= 0 {
			return errSecurityf("ratelimit: requests must be > 0")
		}
		switch rl.Key {
		case "", "ip", "ip+uri":
		default:
			return errSecurityf("ratelimit: key must be \"ip\" or \"ip+uri\", got %q", rl.Key)
		}
		switch rl.Action {
		case "", "deny", "throttle":
		default:
			return errSecurityf("ratelimit: action must be \"deny\" or \"throttle\", got %q", rl.Action)
		}
	}
	if s.Captcha != nil && s.Captcha.Enabled && s.Captcha.Tolerance < 0 {
		return errSecurityf("captcha: tolerance must be >= 0")
	}
	if s.Geo != nil && s.Geo.Enabled {
		// db_path empty → use the embedded GeoIP country database
		// (internal/geoip); a custom path always wins.
		for _, cc := range append(append([]string{}, s.Geo.Blacklist...), s.Geo.Whitelist...) {
			if len(cc) < 2 || len(cc) > 3 {
				return errSecurityf("geo: %q is not a valid ISO country code", cc)
			}
		}
	}
	if s.Auth != nil {
		if len(s.Auth.Users) == 0 {
			return errSecurityf("auth: at least one user is required")
		}
		seen := map[string]bool{}
		for _, u := range s.Auth.Users {
			if u.Username == "" {
				return errSecurityf("auth: username is empty")
			}
			if seen[u.Username] {
				return errSecurityf("auth: duplicate user %q", u.Username)
			}
			seen[u.Username] = true
			if (u.Password == "") == (u.PasswordHash == "") {
				return errSecurityf("auth: user %q must set exactly one of password / password_hash", u.Username)
			}
		}
	}
	if s.RespFilter != nil {
		rf := s.RespFilter
		switch rf.Action {
		case "", "mask", "block":
		default:
			return errSecurityf("resp_filter: action must be \"mask\" or \"block\", got %q", rf.Action)
		}
	}
	if s.Dynamic != nil && s.Dynamic.Enabled {
		d := s.Dynamic
		if d.MaxBytes > 0 && d.MinBytes > 0 && d.MaxBytes < d.MinBytes {
			return errSecurityf("dynamic: max_bytes must be >= min_bytes")
		}
	}
	return nil
}

func isGroupRef(s string) bool {
	return len(s) > 6 && s[:6] == "group:"
}

func validCIDR(s string) bool {
	// Accept bare IPs and CIDR blocks alike.
	if !containsByte(s, '/') {
		return isIP(s)
	}
	return isCIDR(s)
}
