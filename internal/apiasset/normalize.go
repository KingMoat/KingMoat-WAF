// Package apiasset implements passive API inventory learning from traffic:
// an observation side-channel (AccessTick), path normalization, tag
// classification, SQLite persistence and the observe-only risk engine.
// The module is disabled by default; enabling it never changes proxy
// behavior — the side-channel drops ticks under backpressure instead of
// ever blocking the hot path.
package apiasset

import (
	"encoding/json"
	"net/url"
	"strings"
)

// maxSegments bounds normalized path depth; deeper paths collapse into a
// trailing wildcard to keep the inventory finite.
const maxSegments = 10

// NormalizePath maps a raw request path onto a route template: purely
// numeric, UUID, long-hex, date and email-like segments become {param};
// short version segments (v1, api) stay literal. Query strings are dropped.
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	out := make([]string, 0, len(segs))
	for i, seg := range segs {
		if i >= maxSegments {
			out = append(out, "...")
			break
		}
		if seg == "" {
			continue
		}
		if isVersionSegment(seg) || !isParamSegment(seg) {
			out = append(out, seg)
			continue
		}
		out = append(out, "{param}")
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

// isVersionSegment keeps API version literals such as v1, api/v2, v1_0.
func isVersionSegment(seg string) bool {
	l := strings.ToLower(seg)
	if l == "api" {
		return true
	}
	if len(l) >= 2 && l[0] == 'v' {
		rest := l[1:]
		for i := 0; i < len(rest); i++ {
			c := rest[i]
			if (c < '0' || c > '9') && c != '.' && c != '_' {
				return false
			}
		}
		return true
	}
	return false
}

// isParamSegment reports whether a segment looks like a per-resource
// identifier rather than a static route word.
func isParamSegment(seg string) bool {
	if isAllDigits(seg) {
		return true
	}
	if isUUID(seg) {
		return true
	}
	if len(seg) >= 16 && isAllHex(seg) {
		return true
	}
	if isDateLike(seg) {
		return true
	}
	if strings.Contains(seg, "@") {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return len(s) > 0
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for _, pos := range []int{8, 13, 18, 23} {
		if s[pos] != '-' {
			return false
		}
	}
	return isAllHex(strings.ReplaceAll(s, "-", ""))
}

func isDateLike(s string) bool {
	// YYYY-MM-DD, YYYYMMDD, epoch seconds/millis.
	if len(s) == 10 && s[4] == '-' && s[7] == '-' && isAllDigits(s[0:4]+s[5:7]+s[8:10]) {
		return true
	}
	if len(s) == 8 && isAllDigits(s) {
		// "20260915" is a date; "12345678" may be an ID — treat 8-digit as
		// ambiguous and keep it literal unless it looks like a year prefix.
		return s[0] == '2' && s[1] == '0' && s[2] == '2'
	}
	if (len(s) == 10 || len(s) == 13) && isAllDigits(s) {
		return true // epoch timestamps
	}
	return false
}

// QueryKeys extracts parameter names from a raw query string. Values are
// never retained.
func QueryKeys(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// JSONTopKeys reads the top-level object keys of a buffered JSON body
// without retaining any values. It returns nil for non-JSON or oversized
// bodies.
func JSONTopKeys(body []byte, maxLen int) []string {
	if len(body) == 0 || len(body) > maxLen {
		return nil
	}
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if _, ok := tok.(json.Delim); !ok {
		return nil
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return keys
		}
		key, ok := t.(string)
		if !ok {
			return keys
		}
		keys = append(keys, key)
		// Skip the value.
		if err := skipValue(dec); err != nil {
			return keys
		}
	}
	return keys
}

func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{', '[':
			depth := 1
			for depth > 0 {
				t, err := dec.Token()
				if err != nil {
					return err
				}
				if dd, ok := t.(json.Delim); ok {
					switch dd {
					case '{', '[':
						depth++
					case '}', ']':
						depth--
					}
				}
			}
		}
	}
	return nil
}
