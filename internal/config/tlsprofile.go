// TLS cipher-suite profiles: HTTPS sites ship with a named cipher-suite
// group instead of raw per-suite lists. All groups negotiate TLS 1.2+ (the
// listener floor) and TLS 1.3 is always available (Go manages its suites).
// The groups are strictly nested — strong ⊂ moderate ⊂ compatible — so a
// higher-compatibility group only ever widens the offered set.
//
//	go:embed note: TLS_RSA_* (static key exchange) suites are disabled by
//	default since Go 1.22 and are intentionally NOT part of any profile:
//	compatibility with them would require GODEBUG=tlsrsakex=1 and drops
//	forward secrecy. The compatible profile reaches legacy clients via the
//	ECDHE-CBC-SHA1 suites instead.
package config

import "fmt"

// TLS cipher-suite profile names (Site.TLSProfile).
const (
	TLSProfileStrong     = "strong"     // AEAD only (ECDHE + AES-GCM / ChaCha20-Poly1305)
	TLSProfileModerate   = "moderate"   // default: strong + ECDHE CBC-SHA256/384
	TLSProfileCompatible = "compatible" // moderate + ECDHE CBC-SHA1 (legacy clients)
)

// TLS1.2 cipher suites per profile (IANA IDs; Go picks TLS 1.3 suites on
// its own and the listener always sets MinVersion = TLS 1.2).

// TLSCipherSuitesStrong lists only AEAD suites with forward secrecy: the
// modern baseline (matches the Chromium/ Firefox "modern" set).
var TLSCipherSuitesStrong = []uint16{
	0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
}

// TLSCipherSuitesModerate widens the strong set with ECDHE-CBC-SHA1 suites
// for older-but-not-ancient clients (Java 7, old OpenSSL). These are in Go's
// secure list (Go applies the Lucky13 mitigations) and keep forward secrecy.
// This is the default profile.
var TLSCipherSuitesModerate = append(TLSCipherSuitesStrong,
	0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
)

// TLSCipherSuitesCompatible further widens the moderate set with the
// ECDHE-CBC-SHA256 suites (Go classifies them as insecure: the CBC-HMAC
// construction here predates the enhanced hardening). They only matter for
// peers that enforce a strict suite whitelist; the ECDHE key exchange keeps
// forward secrecy. Go does not implement the AES-256-CBC-SHA384 IDs, and
// TLS_RSA_* (static key exchange) suites require GODEBUG=tlsrsakex=1 since
// Go 1.22 — neither is part of any profile.
var TLSCipherSuitesCompatible = append(TLSCipherSuitesModerate,
	0xC023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
)

// TLSProfileOrDefault normalizes an empty/unknown-but-valid-at-parse-time
// value to the default profile.
func TLSProfileOrDefault(profile string) string {
	if profile == TLSProfileStrong || profile == TLSProfileCompatible {
		return profile
	}
	return TLSProfileModerate
}

// ValidateTLSProfile checks a user-supplied profile name.
func ValidateTLSProfile(profile string) error {
	switch profile {
	case "", TLSProfileStrong, TLSProfileModerate, TLSProfileCompatible:
		return nil
	default:
		return fmt.Errorf("tls_profile must be \"strong\", \"moderate\" or \"compatible\", got %q", profile)
	}
}

// CipherSuitesForProfile returns the TLS 1.2 cipher-suite IDs for a profile
// (nil for the default profile is NOT used: callers always receive an
// explicit list so the effective set never drifts with Go defaults).
func CipherSuitesForProfile(profile string) []uint16 {
	switch TLSProfileOrDefault(profile) {
	case TLSProfileStrong:
		return TLSCipherSuitesStrong
	case TLSProfileCompatible:
		return TLSCipherSuitesCompatible
	default:
		return TLSCipherSuitesModerate
	}
}

// CipherSuitesOverride reports whether the site's profile differs from the
// listener default (moderate): only then does the listener need a
// per-handshake tls.Config override.
func CipherSuitesOverride(profile string) bool {
	p := TLSProfileOrDefault(profile)
	return p == TLSProfileStrong || p == TLSProfileCompatible
}
