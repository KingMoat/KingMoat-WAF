// Package syslogsink implements a minimal standard-syslog client used by the
// audit-log and access-log shippers (log_shipper/access_log type "syslog"):
// RFC 5424 (IETF syslog) and RFC 3164 (BSD syslog) message formats over UDP,
// TCP or TLS transports. TCP/TLS framing follows RFC 6587 octet counting by
// default (safe for multi-line payloads) and can be forced to newline framing
// for legacy collectors. The client is safe for concurrent use; dial and
// write timeouts are bounded so log shipping never stalls the hot path.
package syslogsink

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kingmoat/kingmoat/internal/config"
)

// Client sends syslog messages to one target. Safe for concurrent use.
type Client struct {
	mu       sync.Mutex
	network  string // udp | tcp | tls
	addr     string
	format   string // rfc5424 | rfc3164
	framing  string // octet | newline (tcp/tls only)
	facility int
	severity int
	hostname string
	appName  string
	dialTO   time.Duration
	tlsSkip  bool

	conn net.Conn
}

// New validates the settings and returns a client. defaultApp is the program
// name (APP-NAME / tag) used when SyslogSettings.AppName is empty; callers
// pass their shipper index ("kingmoat" / "kingmoat_access").
func New(cfg config.ShipperSettings, defaultApp string) (*Client, error) {
	return newClient(cfg.Syslog, cfg.URL, cfg.Index, defaultApp, durationSec(cfg.TimeoutSec, 5))
}

func newClient(sys *config.SyslogSettings, rawURL, index, defaultApp string, dialTO time.Duration) (*Client, error) {
	if sys == nil {
		return nil, fmt.Errorf("syslogsink: syslog settings are required")
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("syslogsink: url is required (udp://host:514, tcp://host:514 or tls://host:6514)")
	}
	network := ""
	if u, err := url.Parse(rawURL); err == nil && u.Scheme != "" && u.Host != "" {
		network = strings.ToLower(u.Scheme)
		rawURL = u.Host
	}
	if sys.Protocol != "" {
		network = strings.ToLower(sys.Protocol)
	}
	switch network {
	case "":
		network = "udp"
	case "udp", "tcp", "tls":
	default:
		return nil, fmt.Errorf("syslogsink: protocol must be udp, tcp or tls, got %q", network)
	}

	format := strings.ToLower(sys.Format)
	if format == "" {
		format = "rfc5424"
	}
	if format != "rfc5424" && format != "rfc3164" {
		return nil, fmt.Errorf("syslogsink: format must be rfc5424 or rfc3164, got %q", sys.Format)
	}

	framing := strings.ToLower(sys.Framing)
	if framing == "" {
		if format == "rfc3164" {
			framing = "newline"
		} else {
			framing = "octet"
		}
	}
	if framing != "octet" && framing != "newline" {
		return nil, fmt.Errorf("syslogsink: framing must be octet or newline, got %q", sys.Framing)
	}

	if sys.Facility < 0 || sys.Facility > 23 {
		return nil, fmt.Errorf("syslogsink: facility must be 0..23, got %d", sys.Facility)
	}
	if sys.Severity < 0 || sys.Severity > 7 {
		return nil, fmt.Errorf("syslogsink: severity must be 0..7, got %d", sys.Severity)
	}
	// Zero means "unset": default facility is local0 (16) and the default
	// severity is info (6).
	facility := sys.Facility
	if facility == 0 {
		facility = 16
	}
	severity := sys.Severity
	if severity == 0 {
		severity = 6
	}

	hostname := strings.TrimSpace(sys.Hostname)
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "kingmoat"
		}
	}
	appName := strings.TrimSpace(sys.AppName)
	if appName == "" {
		appName = strings.TrimSpace(index)
	}
	if appName == "" {
		appName = defaultApp
	}

	return &Client{
		network:  network,
		addr:     rawURL,
		format:   format,
		framing:  framing,
		facility: facility,
		severity: severity,
		hostname: hostname,
		appName:  appName,
		dialTO:   dialTO,
		tlsSkip:  sys.TLSSkipVerify,
	}, nil
}

// Send formats and delivers one message. ts is the event timestamp, msgID
// labels the event kind (RFC 5424 MSGID; ignored by RFC 3164) and msg is the
// message body (single line; newlines are escaped). sevOverride > 0 replaces
// the configured severity (e.g. blocked events ship as warning).
func (c *Client) Send(ts time.Time, msgID, msg string, sevOverride int) error {
	payload := c.formatMessage(ts, msgID, msg, sevOverride)
	return c.send([]byte(payload))
}

// formatMessage renders one syslog frame body (without TCP framing).
func (c *Client) formatMessage(ts time.Time, msgID, msg string, sevOverride int) string {
	sev := c.severity
	if sevOverride > 0 && sevOverride <= 7 {
		sev = sevOverride
	}
	pri := c.facility*8 + sev
	// Keep MSG single-line: JSON payloads are already flat, but escape any
	// embedded newlines defensively so framing stays unambiguous.
	msg = strings.ReplaceAll(strings.ReplaceAll(msg, "\r", "\\r"), "\n", "\\n")
	if c.format == "rfc3164" {
		return fmt.Sprintf("<%d>%s %s %s: %s",
			pri, ts.Local().Format("Jan _2 15:04:05"), c.hostname, c.appName, msg)
	}
	if msgID == "" {
		msgID = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
		pri, ts.Format("2006-01-02T15:04:05.000000Z07:00"), c.hostname, c.appName, msgID, msg)
}

// send delivers one frame, (re)connecting lazily with one retry on failure.
func (c *Client) send(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.write(frame); err != nil {
		c.closeLocked()
		if err := c.connect(); err != nil {
			return err
		}
		if err := c.write(frame); err != nil {
			c.closeLocked()
			return err
		}
	}
	return nil
}

func (c *Client) connect() error {
	deadline := time.Now().Add(c.dialTO)
	if c.network == "tls" {
		d := &net.Dialer{Timeout: c.dialTO}
		conn, err := tls.DialWithDialer(d, "tcp", c.addr, &tls.Config{InsecureSkipVerify: c.tlsSkip}) //nolint:gosec // opt-in via tls_skip_verify
		if err != nil {
			return fmt.Errorf("syslogsink: tls connect %s: %w", c.addr, err)
		}
		c.conn = conn
		return nil
	}
	conn, err := net.DialTimeout(c.network, c.addr, c.dialTO)
	if err != nil {
		return fmt.Errorf("syslogsink: %s connect %s: %w", c.network, c.addr, err)
	}
	if c.network == "tcp" {
		_ = conn.SetDeadline(deadline)
	}
	c.conn = conn
	return nil
}

func (c *Client) write(frame []byte) error {
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return err
		}
	}
	var buf []byte
	if c.network == "udp" {
		buf = frame
	} else if c.framing == "octet" {
		buf = append([]byte(strconv.Itoa(len(frame))+" "), frame...)
	} else {
		buf = append(append([]byte{}, frame...), '\n')
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.dialTO))
	if _, err := c.conn.Write(buf); err != nil {
		return err
	}
	if c.network == "udp" {
		// One datagram per message: drop the socket so a later send re-dials
		// (cheap) and never inherits a stale peer.
		c.closeLocked()
	}
	return nil
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// MarshalLine renders one event as a single-line JSON payload (the message
// body shipped to the collector).
func MarshalLine(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":"marshal: %s"}`, strings.ReplaceAll(err.Error(), `"`, "'")))
	}
	return b
}

// ParseEventTS parses an event timestamp (RFC 3339); it falls back to
// time.Now() when empty or malformed so syslog timestamps stay valid.
func ParseEventTS(ts string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	return time.Now()
}

// SeverityFor maps an outcome/action to a syslog severity: blocked and
// challenged verdicts ship as warning (4), everything else keeps the
// configured default.
func SeverityFor(action string) int {
	switch strings.ToLower(action) {
	case "blocked", "challenged":
		return 4 // warning
	default:
		return 0 // keep configured severity
	}
}

func durationSec(n int, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}
