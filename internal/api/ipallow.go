package api

import (
	"strings"
	"net"
	"net/netip"
)

// ipAllowed reports whether the client IP matches any of the configured
// IPs/CIDRs (console management-plane restriction).
func ipAllowed(ip string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // empty list = no restriction
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, a := range allowed {
		if strings.Contains(a, "/") {
			prefix, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(parsed)
			if !ok {
				continue
			}
			if prefix.Contains(addr.Unmap()) {
				return true
			}
			continue
		}
		if parsed.Equal(net.ParseIP(a)) {
			return true
		}
	}
	return false
}
