package stages

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/passhash"
)

// SiteAuth gates configured sites behind HTTP Basic authentication. It is
// not a pipeline stage: it needs to write a 401 with WWW-Authenticate, so
// the proxy invokes Authorize before the detection pipeline.
type SiteAuth struct {
	byDomain map[string]*authSite
	logger   *slog.Logger
}

type authSite struct {
	realm string
	users map[string]string // username → password (plaintext) or hash
	hash  map[string]bool   // username → true when the stored secret is an argon2id hash
}

// NewSiteAuth builds the authenticator; sites without security.auth are skipped.
func NewSiteAuth(cfg *config.Config, logger *slog.Logger) (*SiteAuth, error) {
	if logger == nil {
		logger = slog.Default()
	}
	byDomain := map[string]*authSite{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security == nil || s.Security.Auth == nil {
			continue
		}
		as := &authSite{
			realm: s.Security.Auth.Realm,
			users: map[string]string{},
			hash:  map[string]bool{},
		}
		if as.realm == "" {
			as.realm = "Restricted"
		}
		for _, u := range s.Security.Auth.Users {
			if u.PasswordHash != "" {
				as.users[u.Username] = u.PasswordHash
				as.hash[u.Username] = true
			} else {
				as.users[u.Username] = u.Password
			}
		}
		for _, d := range s.Domains {
			byDomain[strings.ToLower(strings.TrimSpace(d))] = as
		}
	}
	return &SiteAuth{byDomain: byDomain, logger: logger}, nil
}

// Authorize checks the Basic credentials for the request's site.
// ok=false means the caller must answer 401 (challenge handled by the proxy).
func (a *SiteAuth) Authorize(r *http.Request) bool {
	site := a.byDomain[strings.ToLower(rcDomain(r.Host))]
	if site == nil {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	secret, known := site.users[user]
	if !known {
		// burn comparable time to blunt user enumeration
		passhash.VerifyArgon2id(dummyHash, pass)
		return false
	}
	if site.hash[user] {
		if passhash.VerifyArgon2id(secret, pass) {
			return true
		}
		return false
	}
	if passhash.VerifyPlain(secret, pass) {
		return true
	}
	a.logger.Warn("site auth failed", "site", rcDomain(r.Host), "user", user)
	return false
}

// Challenge writes the 401 response with the site's realm.
func (a *SiteAuth) Challenge(w http.ResponseWriter, r *http.Request) {
	site := a.byDomain[strings.ToLower(rcDomain(r.Host))]
	realm := "Restricted"
	if site != nil && site.realm != "" {
		realm = site.realm
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="UTF-8"`, realm))
	http.Error(w, "401 Authorization Required", http.StatusUnauthorized)
}

func rcDomain(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// dummyHash is a valid argon2id encoding used to equalize timing for
// unknown users.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
	"MDAwMDAwMDAwMDAwMDAwMA$" +
	"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
