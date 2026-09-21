// AI provider API key management: admin-only endpoints that store the key
// as an argon2id hash + KEK-sealed copy inside the active config's
// ai.provider section. The plaintext exists only in the request body and
// transient memory — never in responses, logs or the change audit.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/passhash"
	"github.com/kingmoat/kingmoat/internal/store"
)

// updateAIProvider mutates the ai section of the ACTIVE configuration in
// place and republishes it through the normal revision pipeline (the
// no-change comparison is based on the stored revision JSON, so an in-place
// mutation followed by Publish is the established handler pattern). The
// publish triggers the Supervisor rebuild so the new key hot-applies.
func (s *Server) updateAIProvider(w http.ResponseWriter, r *http.Request, note, action, detail string, mutate func(*ai.Settings) (bool, error)) {
	_, cfg := s.opts.Center.Current()
	if len(cfg.AI) == 0 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ai assistant is not configured"))
		return
	}
	var st ai.Settings
	if err := json.Unmarshal(cfg.AI, &st); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ai config invalid: %w", err))
		return
	}
	changed, err := mutate(&st)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !changed {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	cfg.AI = b
	author := "admin"
	if u := userFromContext(r); u != nil {
		author = u.Username
	}
	if _, err := s.opts.Center.Publish(cfg, author, note); err != nil {
		if errors.Is(err, configcenter.ErrNoChanges) {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.recordChange(r, action, "ai.provider", detail)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAIKeySet serves POST /api/ai/key {"key":"..."} (admin only):
// computes the argon2id hash and the KEK-encrypted copy of the submitted
// key, stores both in the active config and hot-rebuilds the assistant.
// Re-saving the SAME key is a no-op: the argon2id salt and the GCM nonce are
// random per call, so byte comparison of the stored material would always
// differ — the existing cipher is decrypted and compared constant-time
// instead, keeping duplicate saves from creating dirty revisions.
func (s *Server) handleAIKeySet(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		writeErr(w, http.StatusBadRequest, simpleError("key is required"))
		return
	}
	kek := s.aiKEK()
	if len(kek) == 0 {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("ai key storage unavailable (kek not configured)"))
		return
	}
	s.updateAIProvider(w, r, "ai key updated", "ai.key_set",
		"provider API key stored (argon2id hash + KEK-encrypted copy)", func(st *ai.Settings) (bool, error) {
			if st.Provider.APIKeyCipher != "" {
				if existing, derr := ai.DecryptKey(kek, st.Provider.APIKeyCipher); derr == nil &&
					subtle.ConstantTimeCompare([]byte(existing), []byte(key)) == 1 {
					return false, nil // same key already stored: idempotent no-op
				}
			}
			hash, err := passhash.HashPassword(key)
			if err != nil {
				return false, err
			}
			cipherText, err := ai.EncryptKey(kek, key)
			if err != nil {
				return false, err
			}
			st.Provider.APIKeyHash = hash
			st.Provider.APIKeyCipher = cipherText
			return true, nil
		})
}

// handleAIKeyDelete serves DELETE /api/ai/key (admin only): removes the
// stored hash/cipher pair from the active config (the env-var fallback
// keeps working) and hot-rebuilds the assistant.
func (s *Server) handleAIKeyDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, store.RoleAdmin) {
		return
	}
	s.updateAIProvider(w, r, "ai key cleared", "ai.key_delete",
		"stored provider API key removed", func(st *ai.Settings) (bool, error) {
			if st.Provider.APIKeyHash == "" && st.Provider.APIKeyCipher == "" {
				return false, nil
			}
			st.Provider.APIKeyHash = ""
			st.Provider.APIKeyCipher = ""
			return true, nil
		})
}

// aiKEK returns the key-encryption key for the stored API key
// (nil when the assembly point did not wire AIKEKFn or the KEK is unusable).
func (s *Server) aiKEK() []byte {
	if s.aiKEKFn == nil {
		return nil
	}
	return s.aiKEKFn()
}
