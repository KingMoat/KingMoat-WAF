package ai

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	for _, pt := range []string{"sk-abc123", "中文密钥内容", "x"} {
		blob, err := EncryptKey(kek, pt)
		if err != nil {
			t.Fatalf("EncryptKey(%q): %v", pt, err)
		}
		got, err := DecryptKey(kek, blob)
		if err != nil {
			t.Fatalf("DecryptKey: %v", err)
		}
		if got != pt {
			t.Fatalf("round trip = %q, want %q", got, pt)
		}
	}
}

func TestDecryptKeyWrongKEKFails(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	blob, err := EncryptKey(kek, "sk-secret")
	if err != nil {
		t.Fatal(err)
	}
	other := []byte("ffffffffffffffffffffffffffffffff")
	if _, err := DecryptKey(other, blob); err == nil {
		t.Fatal("decrypt with wrong KEK must fail")
	}
	if _, err := DecryptKey(kek[:16], blob); err == nil {
		t.Fatal("decrypt with short KEK must fail")
	}
	if _, err := DecryptKey(kek, "not-base64!!"); err == nil {
		t.Fatal("decrypt of malformed blob must fail")
	}
}

func TestLoadOrCreateKEKCreatesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai-kek.key")
	kek, err := LoadOrCreateKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(kek) != 32 {
		t.Fatalf("generated KEK size = %d, want 32", len(kek))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("kek file not created: %v", err)
	}
	if info.Size() != 32 {
		t.Fatalf("kek file size = %d, want 32", info.Size())
	}
	again, err := LoadOrCreateKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(kek) {
		t.Fatal("second load must return the same KEK")
	}
}

func TestLoadOrCreateKEKRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai-kek.key")
	if err := os.WriteFile(path, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKEK(path); err == nil {
		t.Fatal("KEK file with wrong size must be rejected")
	}
}

func TestResolveAPIKeyPriority(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	good, err := EncryptKey(kek, "stored-key")
	if err != nil {
		t.Fatal(err)
	}
	bad := "AAAA" + good // same length, wrong KEK → GCM open fails
	t.Setenv("KINGMOAT_AI_API_KEY", "env-key")

	// stored cipher beats env
	p := &ProviderSettings{APIKeyCipher: good}
	if key, src := p.ResolveAPIKey(kek, quietLogger()); key != "stored-key" || src != KeySourceStored {
		t.Fatalf("cipher+kek: got (%q,%s), want stored", key, src)
	}

	// broken cipher degrades to env (rotation must not hard-disable)
	p = &ProviderSettings{APIKeyCipher: bad}
	if key, src := p.ResolveAPIKey(kek, quietLogger()); key != "env-key" || src != KeySourceEnv {
		t.Fatalf("bad cipher: got (%q,%s), want env fallback", key, src)
	}

	// broken cipher without env → none
	t.Setenv("KINGMOAT_AI_API_KEY", "")
	p = &ProviderSettings{APIKeyCipher: bad}
	if key, src := p.ResolveAPIKey(kek, quietLogger()); key != "" || src != KeySourceNone {
		t.Fatalf("bad cipher without env: got (%q,%s), want none", key, src)
	}

	// env only (re-arm a non-empty value)
	t.Setenv("KINGMOAT_AI_API_KEY", "env-key")
	p = &ProviderSettings{}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "env-key" || src != KeySourceEnv {
		t.Fatalf("env only: got (%q,%s), want env", key, src)
	}

	// nothing configured → none
	t.Setenv("KINGMOAT_AI_API_KEY", "")
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "" || src != KeySourceNone {
		t.Fatalf("no key: got (%q,%s), want none", key, src)
	}
}

// TestResolveAPIKeyInlineFallback pins the tolerant fallback for the field
// misconfiguration observed in the field: a literal key pasted into
// api_key_env (whose contract is an env-var NAME) still resolves as "inline"
// once the env lookup missed, while real env-var names and a working env
// variable are never misdetected.
func TestResolveAPIKeyInlineFallback(t *testing.T) {
	t.Setenv("KINGMOAT_AI_API_KEY", "")
	t.Setenv("SK_CUSTOM_KEY", "env-wins")

	literal := "sk-" + strings.Repeat("a", 48)

	// sk- prefixed literal → inline
	p := &ProviderSettings{APIKeyEnv: literal}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != literal || src != KeySourceInline {
		t.Fatalf("sk- literal: got (len=%d,%s), want inline", len(key), src)
	}

	// long key without sk- prefix (no whitespace) → inline
	long := strings.Repeat("b", 48)
	p = &ProviderSettings{APIKeyEnv: long}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != long || src != KeySourceInline {
		t.Fatalf("long literal: got (%q,%s), want inline", key, src)
	}

	// real env-var name that IS set → env wins over any inline guess
	p = &ProviderSettings{APIKeyEnv: "SK_CUSTOM_KEY"}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "env-wins" || src != KeySourceEnv {
		t.Fatalf("set env var: got (%q,%s), want env", key, src)
	}

	// real env-var name, unset → none (never inline)
	p = &ProviderSettings{APIKeyEnv: "KINGMOAT_AI_API_KEY"}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "" || src != KeySourceNone {
		t.Fatalf("env name unset: got (%q,%s), want none", key, src)
	}

	// short non-sk value → none
	p = &ProviderSettings{APIKeyEnv: "my-short-key"}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "" || src != KeySourceNone {
		t.Fatalf("short value: got (%q,%s), want none", key, src)
	}

	// whitespace inside → none (never inline)
	p = &ProviderSettings{APIKeyEnv: "sk- key with spaces"}
	if key, src := p.ResolveAPIKey(nil, quietLogger()); key != "" || src != KeySourceNone {
		t.Fatalf("spaced value: got (%q,%s), want none", key, src)
	}

	// stored cipher still beats the inline fallback
	kek := []byte("0123456789abcdef0123456789abcdef")
	good, err := EncryptKey(kek, "stored-key")
	if err != nil {
		t.Fatal(err)
	}
	p = &ProviderSettings{APIKeyCipher: good, APIKeyEnv: literal}
	if key, src := p.ResolveAPIKey(kek, quietLogger()); key != "stored-key" || src != KeySourceStored {
		t.Fatalf("cipher beats inline: got (%q,%s), want stored", key, src)
	}
}

func TestResolveSettingsWiresKEKAndStoredKey(t *testing.T) {
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "ai-kek.key")
	kek, err := LoadOrCreateKEK(kekPath)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := EncryptKey(kek, "stored-key")
	if err != nil {
		t.Fatal(err)
	}
	cfgAI := []byte(`{"enabled":true,"provider":{"template":"openai","base_url":"https://api.example/v1","api_key_cipher":"` + cipher + `"}}`)
	st := ResolveSettings(cfgAI, "", kekPath, quietLogger())
	if st == nil {
		t.Fatal("ResolveSettings returned nil")
	}
	if len(st.KEK) != 32 {
		t.Fatalf("settings KEK size = %d, want 32", len(st.KEK))
	}
	if string(st.KEK) != string(kek) {
		t.Fatal("settings KEK must match the persisted file")
	}
	if key, src := st.Provider.ResolveAPIKey(st.KEK, quietLogger()); key != "stored-key" || src != KeySourceStored {
		t.Fatalf("resolved (%q,%s), want stored", key, src)
	}
}
