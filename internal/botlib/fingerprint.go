package botlib

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// Fingerprint derives a stable per-client identifier from the remote address,
// User-Agent and the set of header names (order-insensitive). It is cheap,
// cacheable and requires no cookies; it is not a strong identity and must
// only drive behavioral signals (rate, challenge history).
func Fingerprint(ip, ua string, r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(ip))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(ua)))
	h.Write([]byte{0})

	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		switch strings.ToLower(k) {
		case "x-kingmoat-trace-id", "cookie", "authorization":
			continue // per-request or credential-bearing headers
		}
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{','})
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}
