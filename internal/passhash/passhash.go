// Package passhash centralizes credential hashing helpers shared by the
// console auth and site-level authentication.
package passhash

import (
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// VerifyArgon2id reports whether password matches an encoded argon2id hash
// of the form $argon2id$v=19$m=<mem>,t=<iters>,p=<par>$<salt>$<key>.
func VerifyArgon2id(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return false
	}
	var memory, iters, threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iters, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iters, memory, uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VerifyPlain is a constant-time plaintext comparison for quick internal
// deployments.
func VerifyPlain(want, got string) bool {
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// HashPassword derives an argon2id encoded hash for a new password
// (parameters match kingmoat-cli hash-password: 64MiB, 3 iterations, 4 threads).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// dummyHash is a per-process argon2id hash of an unknown random secret. It
// exists purely to equalize authentication timing (see VerifyDummy).
var dummyHash = buildDummyHash()

func buildDummyHash() string {
	pw := make([]byte, 32)
	if _, err := crand.Read(pw); err != nil {
		return ""
	}
	h, err := HashPassword(string(pw))
	if err != nil {
		return ""
	}
	return h
}

// VerifyDummy burns one argon2id verification against the per-process dummy
// hash. Login handlers call it for UNKNOWN usernames so that the response
// timing matches a real credential check and the (costly) hash step no
// longer leaks which accounts exist (CWE-208 user-enumeration oracle).
// The dummy hash uses the same argon2id parameters as real password hashes.
func VerifyDummy(password string) {
	if dummyHash != "" {
		VerifyArgon2id(dummyHash, password)
	}
}
