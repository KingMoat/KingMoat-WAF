// Package redact removes embedded credentials from URLs before they reach
// logs: userinfo (user:pass@host) is always stripped, and query values of
// token-like parameters (access_token, key, signature, ...) are masked.
// Webhook endpoints and log-platform URLs routinely carry credentials, and
// http client errors (*url.Error) embed the full URL — so every log site
// that prints a URL or an error should go through this package.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// sensitiveKeyRe matches query parameter names whose values must not be
// logged in clear.
var sensitiveKeyRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|pwd|api[_-]?key|access[_-]?key|signature|(^|[^a-z])sig([^a-z]|$)|(^|[^a-z])sign([^a-z]|$))`)

// urlInTextRe finds http(s) URLs embedded in arbitrary text such as error
// messages.
var urlInTextRe = regexp.MustCompile(`https?://[^\s"']+`)

// userinfoRe is the fallback scrubber for unparseable URLs.
var userinfoRe = regexp.MustCompile(`(https?://)([^/@\s:]+):([^/@\s]+)@`)

// URL returns a copy of a URL string with userinfo removed and sensitive
// query values masked. Non-sensitive query values are preserved for
// debuggability.
func URL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return userinfoRe.ReplaceAllString(raw, "$1***@")
	}
	redacted := false
	if u.User != nil {
		u.User = nil
		redacted = true
	}
	q := u.Query()
	for k, vs := range q {
		if !sensitiveKeyRe.MatchString(k) {
			continue
		}
		for i, v := range vs {
			if v != "" {
				vs[i] = "***"
				redacted = true
			}
		}
		q[k] = vs
	}
	if redacted {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// String redacts credentials from every URL embedded in an arbitrary string
// (e.g. an error message that wraps a *url.Error).
func String(s string) string {
	if s == "" || !strings.Contains(s, "://") {
		return s
	}
	return urlInTextRe.ReplaceAllStringFunc(s, URL)
}
