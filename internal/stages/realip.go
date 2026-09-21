// realip.go implements trusted-proxy real client-IP resolution: when a site
// is deployed behind an LB/CDN the TCP peer is the proxy, not the client.
// The operator declares which peers may set the forwarding header; only for
// those peers is the header honored (anti-forgery), and the client address
// is taken from the rightmost non-trusted entry of the chain.
package stages

import (
	"net"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
)

// defaultRealIPHeader is the source header when config.Header is empty.
const defaultRealIPHeader = "X-Forwarded-For"

// ResolveRealIP returns the real client IP for the request when the site
// enables real-ip resolution and the direct TCP peer is a trusted proxy.
// It returns nil when the site has no real-ip config, the peer is not
// trusted, or the header carries no usable address — callers fall back to
// the TCP peer address (fail-closed: a spoofed header from an untrusted
// client never changes the resolved IP).
func ResolveRealIP(s *config.Site, r *http.Request) net.IP {
	rp := s.RealIP
	if rp == nil || !rp.Enabled || len(rp.TrustedProxies) == 0 {
		return nil
	}
	peer := peerIP(r)
	if peer == nil || !trustsProxy(rp, peer) {
		return nil
	}
	header := rp.Header
	if header == "" {
		header = defaultRealIPHeader
	}
	ips := parseForwardedChain(r.Header.Values(http.CanonicalHeaderKey(header)))
	if len(ips) == 0 {
		return nil
	}
	// Walk right-to-left skipping trusted proxies: the rightmost entry was
	// appended by the closest trusted proxy; the first non-trusted address
	// is the client (recursive trust, mirroring nginx real_ip behavior).
	for i := len(ips) - 1; i >= 0; i-- {
		if !trustsProxy(rp, ips[i]) {
			return ips[i]
		}
	}
	// Every entry is a trusted proxy (nested trusted chains): the leftmost
	// entry is the closest address to the real client.
	return ips[0]
}

// trustsProxy reports whether ip falls within the configured trusted ranges.
func trustsProxy(rp *config.RealIPSettings, ip net.IP) bool {
	for _, c := range rp.TrustedProxies {
		if n := parseTrustEntry(c); n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustEntry parses one trusted_proxies entry (IP or CIDR) into a
// network; nil when invalid (rejected earlier by config validation).
func parseTrustEntry(c string) *net.IPNet {
	if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
		return ipnet
	}
	if ip := net.ParseIP(strings.TrimSpace(c)); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	return nil
}

// parseForwardedChain folds multi-header + comma-separated chains into the
// ordered IP list (left = first hop, right = last hop). Entries with a port
// ("203.0.113.9:1234", "[2001:db8::1]:443") are accepted; malformed entries
// are skipped.
func parseForwardedChain(values []string) []net.IP {
	var ips []net.IP
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if ip := parseIPOrHostPort(part); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// parseIPOrHostPort parses an address that may be a bare IP or carry a port.
func parseIPOrHostPort(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// peerIP extracts the TCP peer address from the request.
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
