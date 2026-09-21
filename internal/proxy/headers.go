// headers.go applies user-configured request-header operations (config.Site
// .Headers) to the outbound proxy request. Ops run after the built-in
// X-Forwarded-* handling so explicit site config wins; protected framing /
// hop-by-hop headers were rejected at config-load time.
package proxy

import (
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"sort"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/pipeline"
)

// hdrPlaceholderRE matches $hdr.<Name> tokens (inbound header copies).
var hdrPlaceholderRE = regexp.MustCompile(`\$hdr\.([A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+)`)

// headerRewriteConfig is the compiled per-site header-rewrite plan.
type headerRewriteConfig struct {
	set map[string]string
	add map[string]string
	del []string
}

// compileHeaderRewrite precomputes the per-site plan from config (names are
// validated at config load; canonicalize for case-insensitive semantics).
func compileHeaderRewrite(h *config.HeaderRewrite) *headerRewriteConfig {
	if h == nil {
		return nil
	}
	c := &headerRewriteConfig{set: map[string]string{}, add: map[string]string{}}
	for k, v := range h.Set {
		c.set[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	for k, v := range h.Add {
		c.add[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	for _, k := range h.Del {
		c.del = append(c.del, textproto.CanonicalMIMEHeaderKey(k))
	}
	return c
}

// applyHeaderOps mutates out with the configured del/set/add operations.
// in is the inbound request, used for placeholder resolution. Deterministic:
// del first (so a deleted header cannot be re-added by set), then set and
// add in sorted key order.
func applyHeaderOps(out http.Header, in *http.Request, c *headerRewriteConfig) {
	if c == nil || (len(c.set) == 0 && len(c.add) == 0 && len(c.del) == 0) {
		return
	}
	vars := headerVars(in)
	for _, name := range c.del {
		out.Del(name)
	}
	for _, name := range sortedKeys(c.set) {
		if v, ok := renderValue(c.set[name], in, vars); ok {
			out.Set(name, v)
		}
	}
	for _, name := range sortedKeys(c.add) {
		if v, ok := renderValue(c.add[name], in, vars); ok {
			out.Add(name, v)
		}
	}
}

// headerVars caches per-request scalar placeholders.
func headerVars(in *http.Request) map[string]string {
	scheme := "http"
	if in.TLS != nil {
		scheme = "https"
	}
	peer, _, _ := net.SplitHostPort(in.RemoteAddr)
	return map[string]string{
		"remote_addr": peer,
		"host":        in.Host,
		"scheme":      scheme,
	}
}

// renderValue substitutes placeholders in a configured value. Returns
// ok=false when the value resolves to empty (e.g. a missing $hdr source) so
// the operation is skipped instead of injecting an empty header.
func renderValue(tpl string, in *http.Request, vars map[string]string) (string, bool) {
	v := hdrPlaceholderRE.ReplaceAllStringFunc(tpl, func(m string) string {
		return in.Header.Get(strings.TrimPrefix(m, "$hdr."))
	})
	for k, val := range vars {
		v = strings.ReplaceAll(v, "$"+k, val)
	}
	if strings.Contains(v, "$client_ip") {
		client := ""
		if ip := pipeline.ClientIPFromContext(in.Context()); ip != nil {
			client = ip.String()
		}
		if peer, _, err := net.SplitHostPort(in.RemoteAddr); err == nil && client == "" {
			client = peer
		}
		v = strings.ReplaceAll(v, "$client_ip", client)
	}
	if strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}

// sortedKeys returns the map keys in deterministic order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
