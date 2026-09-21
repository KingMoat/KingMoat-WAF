package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// errSecurityf builds a validation error for the security block.
func errSecurityf(format string, args ...any) error {
	return fmt.Errorf("config: security: %s", fmt.Sprintf(format, args...))
}

func containsByte(s string, c byte) bool {
	return strings.IndexByte(s, c) >= 0
}

func isIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func isCIDR(s string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(s))
	return err == nil
}

// ParseIPNet accepts both a bare IP (→ /32 or /128) and a CIDR block.
func ParseIPNet(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if !containsByte(s, '/') {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.New("invalid IP")
		}
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return ipnet, nil
}
