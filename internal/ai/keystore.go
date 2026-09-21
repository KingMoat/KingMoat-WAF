// Provider API key storage: a 32-byte key-encryption key (KEK) file next to
// the console DB guards the provider API key at rest. The key is stored in
// the active config as an argon2id hash (integrity/audit) plus an
// AES-256-GCM sealed copy (use) — the plaintext never touches disk and is
// only re-derived in memory when the assistant builds its HTTP client.
package ai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// kekLen is the AES-256 key size in bytes.
const kekLen = 32

// LoadOrCreateKEK reads the 32-byte key-encryption key at path, creating a
// random one on first use (best-effort 0600 on Windows). A file of any other
// size is a hard error — silently regenerating would orphan every stored
// cipher blob.
func LoadOrCreateKEK(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != kekLen {
			return nil, fmt.Errorf("ai: kek %s: invalid size %d (want %d)", path, len(b), kekLen)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ai: kek %s: %w", path, err)
	}
	raw := make([]byte, kekLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("ai: kek entropy: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("ai: kek %s: write: %w", path, err)
	}
	return raw, nil
}

// EncryptKey seals the plaintext API key with AES-256-GCM under the KEK;
// the random nonce is prepended and the result is base64 (StdEncoding).
func EncryptKey(kek []byte, plaintext string) (string, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("ai: nonce entropy: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptKey opens a blob produced by EncryptKey.
func DecryptKey(kek []byte, blob string) (string, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("ai: key blob: %w", err)
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("ai: key blob too short")
	}
	pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("ai: key decrypt: %w", err)
	}
	return string(pt), nil
}

func newAEAD(kek []byte) (cipher.AEAD, error) {
	if len(kek) != kekLen {
		return nil, fmt.Errorf("ai: kek size %d (want %d)", len(kek), kekLen)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// KeySource values for the read-only diagnostic field surfaced through
// GET /api/ai/config (never the key material itself).
const (
	KeySourceStored = "stored" // decrypted from the stored cipher blob
	KeySourceEnv    = "env"    // read from the configured environment variable
	// KeySourceInline marks the tolerant fallback: the user pasted the literal
	// key into api_key_env (a field whose contract is an env-var NAME) and it
	// never resolves as a variable. Usable, but the key sits in plaintext in
	// the config store — the stored-cipher path (POST /api/ai/key) is the
	// correct way.
	KeySourceInline = "inline"
	KeySourceNone   = "none" // no usable key configured
)

// looksLikeAPIKey reports whether s looks like a literal API key rather than
// an environment-variable name: an OpenAI-style "sk-" prefix, or a long token
// without whitespace (env names are short UPPER_SNAKE identifiers; keys are
// 40+ chars). Used only AFTER the env lookup missed, so a properly set
// environment variable always wins.
func looksLikeAPIKey(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return strings.HasPrefix(s, "sk-") || len(s) > 40
}

// ResolveAPIKey resolves the provider API key by priority: the stored
// encrypted key (api_key_cipher, decrypted with the KEK) first, then the
// environment variable (api_key_env, default KINGMOAT_AI_API_KEY), then a
// tolerant inline fallback, then none. A missing KEK or a decryption failure
// is logged and degrades to the lower-priority source — a rotated KEK must
// never hard-disable the assistant while an env fallback still works.
//
// The inline fallback covers the misconfiguration observed in the field:
// users paste the literal key into api_key_env (semantically an env-var
// NAME), so the lookup misses and the assistant dies with no key. When the
// stored value itself looks like a key it is used as-is (source "inline")
// with a loud warning — trading config-store plaintext for availability;
// re-saving via the stored-key path re-encrypts it under the KEK.
func (p *ProviderSettings) ResolveAPIKey(kek []byte, logger *slog.Logger) (apiKey, source string) {
	if p.APIKeyCipher != "" {
		if len(kek) == kekLen {
			if pt, derr := DecryptKey(kek, p.APIKeyCipher); derr == nil && pt != "" {
				return pt, KeySourceStored
			} else if logger != nil {
				logger.Warn("ai: stored api key decrypt failed, falling back to env", "err", derr)
			}
		} else if logger != nil {
			logger.Warn("ai: kek unavailable, stored api key ignored, falling back to env")
		}
	}
	env := p.APIKeyEnv
	if env == "" {
		env = "KINGMOAT_AI_API_KEY"
	}
	if v := os.Getenv(env); v != "" {
		return v, KeySourceEnv
	}
	if v := strings.TrimSpace(p.APIKeyEnv); looksLikeAPIKey(v) {
		if logger != nil {
			logger.Warn("ai: api_key_env holds a literal key, using it inline (plaintext in the config store); prefer storing the key via POST /api/ai/key")
		}
		return v, KeySourceInline
	}
	return "", KeySourceNone
}
