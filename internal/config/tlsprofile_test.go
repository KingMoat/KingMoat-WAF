package config

import (
	"crypto/tls"
	"testing"
)

// goSupportedCipherSuites indexes the suites this Go runtime can actually
// negotiate (RSA key-exchange suites are excluded since Go 1.22 by default).
func goSupportedCipherSuites() map[uint16]bool {
	m := map[uint16]bool{}
	for _, cs := range tls.CipherSuites() {
		m[cs.ID] = true
	}
	for _, cs := range tls.InsecureCipherSuites() {
		m[cs.ID] = true
	}
	return m
}

func TestCipherSuitesNesting(t *testing.T) {
	strong := CipherSuitesForProfile(TLSProfileStrong)
	moderate := CipherSuitesForProfile(TLSProfileModerate)
	compatible := CipherSuitesForProfile(TLSProfileCompatible)

	set := func(list []uint16) map[uint16]bool {
		m := map[uint16]bool{}
		for _, id := range list {
			if m[id] {
				t.Errorf("duplicate suite 0x%04X", id)
			}
			m[id] = true
		}
		return m
	}
	s, m, c := set(strong), set(moderate), set(compatible)

	if len(s) == 0 || len(m) <= len(s) || len(c) <= len(m) {
		t.Fatalf("profile sizes must grow strong<moderate<compatible: %d/%d/%d", len(s), len(m), len(c))
	}
	for id := range s {
		if !m[id] || !c[id] {
			t.Errorf("strong suite 0x%04X missing from moderate/compatible", id)
		}
	}
	for id := range m {
		if !c[id] {
			t.Errorf("moderate suite 0x%04X missing from compatible", id)
		}
	}
}

func TestCipherSuitesSupportedByGo(t *testing.T) {
	supported := goSupportedCipherSuites()
	for _, profile := range []string{TLSProfileStrong, TLSProfileModerate, TLSProfileCompatible} {
		for _, id := range CipherSuitesForProfile(profile) {
			if !supported[id] {
				t.Errorf("profile %s: suite 0x%04X is not supported by this Go runtime", profile, id)
			}
		}
	}
}

func TestValidateTLSProfile(t *testing.T) {
	for _, ok := range []string{"", "strong", "moderate", "compatible"} {
		if err := ValidateTLSProfile(ok); err != nil {
			t.Errorf("profile %q: expected valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{"weak", "MODERATE", "strong1"} {
		if err := ValidateTLSProfile(bad); err == nil {
			t.Errorf("profile %q: expected error, got nil", bad)
		}
	}
	if got := TLSProfileOrDefault(""); got != TLSProfileModerate {
		t.Errorf("empty profile should default to moderate, got %q", got)
	}
	if got := TLSProfileOrDefault("strong"); got != TLSProfileStrong {
		t.Errorf("strong profile mangled: %q", got)
	}
}

func TestCipherSuitesOverride(t *testing.T) {
	cases := map[string]bool{
		"":            false,
		"moderate":    false,
		"strong":      true,
		"compatible":  true,
		"nonsense":    false, // normalizes to moderate
	}
	for profile, want := range cases {
		if got := CipherSuitesOverride(profile); got != want {
			t.Errorf("override(%q) = %v, want %v", profile, got, want)
		}
	}
}
