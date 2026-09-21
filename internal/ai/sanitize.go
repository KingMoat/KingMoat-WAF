package ai

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

// Placeholder categories follow the enterprise masking taxonomy.
const (
	CatEnt = "ENT" // company / brand / project names
	CatUsr = "USR" // usernames, emails, employee ids
	CatNet = "NET" // internal IPs, MACs, internal URLs
	CatInf = "INF" // site domains, upstream hosts, internal paths
	CatSec = "SEC" // credentials, tokens, keys
)

var (
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reIP    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reJWT   = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b`)
	reCred  = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|authorization|bearer)\b\s*[:=]\s*"?([A-Za-z0-9._~+/=-]{6,})`)
	rePem   = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	rePH    = regexp.MustCompile(`\[(ENT|USR|NET|INF|SEC)-(\d+)\]`)
)

// Sanitizer masks outbound payloads per category and restores them on the
// way back. Mapping state is per-conversation so placeholders are stable
// across turns and restorable at the console.
type Sanitizer struct {
	cfg           SanitizeSettings
	internalHosts func() []string // dynamic site-domain source (may be nil)
}

// NewSanitizer builds the pipeline; internalHosts supplies the current site
// domains (re-evaluated per request, hot-reload safe).
func NewSanitizer(cfg SanitizeSettings, internalHosts func() []string) *Sanitizer {
	return &Sanitizer{cfg: cfg, internalHosts: internalHosts}
}

// Enabled reports whether masking is active.
func (s *Sanitizer) Enabled() bool { return s != nil && s.cfg.EnabledOrDefault() }

// EntityMap holds one conversation's placeholder ↔ original mapping.
type EntityMap struct {
	mu    sync.Mutex
	byCat map[string]map[string]int // cat → original → ordinal
	byPH  map[string]string         // placeholder → original
}

// NewEntityMap creates an empty per-session map.
func NewEntityMap() *EntityMap {
	return &EntityMap{byCat: map[string]map[string]int{}, byPH: map[string]string{}}
}

func (em *EntityMap) add(cat, value string) string {
	em.mu.Lock()
	defer em.mu.Unlock()
	if n, ok := em.byCat[cat][value]; ok {
		return "[" + cat + "-" + itoaAI(n) + "]"
	}
	if em.byCat[cat] == nil {
		em.byCat[cat] = map[string]int{}
	}
	n := len(em.byCat[cat]) + 1
	em.byCat[cat][value] = n
	em.byPH["["+cat+"-"+itoaAI(n)+"]"] = value
	return "[" + cat + "-" + itoaAI(n) + "]"
}

// Restore replaces every known placeholder with its original value.
// Unknown placeholders (model hallucinations) pass through untouched.
func (em *EntityMap) Restore(text string) string {
	if em == nil {
		return text
	}
	em.mu.Lock()
	defer em.mu.Unlock()
	return rePH.ReplaceAllStringFunc(text, func(ph string) string {
		if v, ok := em.byPH[ph]; ok {
			return v
		}
		return ph
	})
}

// Sanitize applies the full pipeline to one text blob.
func (s *Sanitizer) Sanitize(text string, em *EntityMap) string {
	if !s.Enabled() || text == "" || em == nil {
		return text
	}
	truncate := s.cfg.PayloadMax
	if truncate > 0 && len(text) > truncate {
		text = text[:truncate] + "…(truncated)"
	}

	// SEC: keys, tokens, JWTs, PEM blocks.
	if s.cfg.MaskCredential {
		text = rePem.ReplaceAllStringFunc(text, func(m string) string { return em.add(CatSec, "PRIVATE-KEY-BLOCK") })
		text = reJWT.ReplaceAllStringFunc(text, func(m string) string { return em.add(CatSec, m) })
		text = reCred.ReplaceAllStringFunc(text, func(m string) string {
			parts := reCred.FindStringSubmatch(m)
			if len(parts) < 3 {
				return m
			}
			return parts[1] + "=" + em.add(CatSec, parts[2])
		})
	}

	// USR: emails.
	text = reEmail.ReplaceAllStringFunc(text, func(m string) string { return em.add(CatUsr, m) })

	// INF: internal hosts from the live site config.
	if s.cfg.MaskInternal && s.internalHosts != nil {
		for _, host := range s.internalHosts() {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if strings.Contains(text, host) {
				text = strings.ReplaceAll(text, host, em.add(CatInf, host))
			}
		}
	}

	// NET: private-range IPs always; public IPs optionally.
	text = reIP.ReplaceAllStringFunc(text, func(m string) string {
		ip := net.ParseIP(m)
		if ip == nil {
			return m
		}
		if isPrivateAIIp(ip) {
			return em.add(CatNet, m)
		}
		if s.cfg.MaskPublicIP {
			return em.add(CatNet, m)
		}
		return m
	})

	// ENT: custom vocabulary (case-insensitive).
	for _, term := range s.cfg.CustomTerms {
		term = strings.TrimSpace(term)
		if term == "" || !strings.Contains(strings.ToLower(text), strings.ToLower(term)) {
			continue
		}
		ph := em.add(CatEnt, term)
		text = replaceInsensitive(text, term, ph)
	}
	return text
}

func isPrivateAIIp(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true // CGNAT
		}
	}
	return false
}

func replaceInsensitive(s, old, new string) string {
	lower, oldLower := strings.ToLower(s), strings.ToLower(old)
	var b strings.Builder
	for {
		i := strings.Index(lower, oldLower)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(new)
		s = s[i+len(old):]
		lower = lower[i+len(old):]
	}
}

func itoaAI(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
