// Package certmgr inspects site TLS certificates and integrates ACME
// (Let's Encrypt) automatic issuance via x/crypto/acme/autocert.
package certmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/naming"
)

// Info describes one site's certificate state (for /api/certificates).
type Info struct {
	Site      string   `json:"site"`
	Source    string   `json:"source"` // "file" | "acme"
	Domains   []string `json:"domains,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	Error     string   `json:"error,omitempty"`
	// Sites lists the primary domains of every site whose tls_cert/tls_key
	// resolves to the same certificate material (site itself included).
	Sites []string `json:"sites,omitempty"`
}

// DefaultCacheBase is the ACME cache directory base, relative to the working
// directory, that main hands to NewACMEHolder. InspectSites reads the same
// directories to backfill the ACME entries' validity window (review N-4).
const DefaultCacheBase = "acme-cache"

// inspectCacheBase returns the cache base InspectSites reads for that
// backfill; production returns DefaultCacheBase, tests override it to point
// at fixture directories (the seam mirrors resolveDataPath below).
var inspectCacheBase = func() string { return DefaultCacheBase }

// InspectFile parses a PEM certificate file and returns its metadata.
func InspectFile(site, domain, certPath string) Info {
	info := Info{Site: site, Source: "file", Domains: []string{domain}}
	b, err := os.ReadFile(certPath)
	if err != nil {
		info.Error = fmt.Sprintf("read: %v", err)
		return info
	}
	var lastErr string
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			lastErr = fmt.Sprintf("parse: %v", err)
			continue
		}
		// Report the leaf (first certificate that is not a CA, else first).
		if cert.IsCA && rest != nil {
			if info.Subject == "" {
				info.Subject = cert.Subject.CommonName
				info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
				info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
			}
			continue
		}
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		info.Domains = cert.DNSNames
		if info.Error != "" {
			info.Error = ""
		}
		return info
	}
	if info.Subject == "" {
		if lastErr != "" {
			info.Error = lastErr
		} else {
			info.Error = "no CERTIFICATE block found"
		}
	}
	return info
}

// resolveDataPath routes actual file access through the runtime path
// contract (internal/config.ResolveLegacyDataPath — the inspection twin of
// the data-plane read in proxy/router.go): a path still under the
// pre-rename data directory is remapped to the current layout when the
// remapped file exists there. The indirection mirrors
// config.legacyDataFileExists so tests can simulate the legacy remap
// without populating /var/lib.
var resolveDataPath = config.ResolveLegacyDataPath

// InspectSites builds the certificate inventory for a configuration. Each
// entry carries the list of sites sharing the same certificate material.
// Paths are compared in normalized form (internal/naming.NormalizePath), so
// the pre-migration and post-migration spellings of the same file still
// group together after the v0.7.10 data-directory rename.
func InspectSites(cfg *config.Config) []Info {
	out := []Info{}
	// Group sites by tls_cert / tls_key path so shared certificates surface
	// every referencing site (site primary domains, deduplicated).
	refs := map[string][]string{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		domain := s.Domains[0]
		for _, p := range []string{s.TLSCert, s.TLSKey} {
			p = naming.NormalizePath(p)
			if p == "" {
				continue
			}
			if !containsStr(refs[p], domain) {
				refs[p] = append(refs[p], domain)
			}
		}
	}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		domain := s.Domains[0]
		switch {
		case s.TLSCert != "":
			// Read through the runtime path contract: without the remap a
			// legacy spelling survives the read as "file not found" even when
			// the certificate is intact under the current layout (review C5).
			certPath := resolveDataPath(s.TLSCert, nil)
			info := InspectFile(domain, domain, certPath)
			info.Sites = sharedSites(refs, naming.NormalizePath(s.TLSCert), naming.NormalizePath(s.TLSKey))
			out = append(out, info)
		case s.ACME != nil:
			info := Info{
				Site:    domain,
				Source:  "acme",
				Domains: append([]string{}, s.Domains...),
				Subject: "managed by ACME (auto-renew)",
				Sites:   []string{domain},
			}
			fillACMETimes(&info, s.ACME.Staging)
			out = append(out, info)
		}
	}
	return out
}

// sharedSites merges the site lists for the cert and key paths.
func sharedSites(refs map[string][]string, certPath, keyPath string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range []string{certPath, keyPath} {
		for _, d := range refs[p] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// fillACMETimes backfills not_before/not_after for an ACME-managed site
// entry from the slot's DirCache leaf (review N-4: the site inventory used
// to carry no validity window for ACME entries at all). Any cached domain
// of the site describes the same certificate (autocert files the full SAN
// set under whichever ServerName triggered issuance), so the first cache
// hit wins; a site with no cached leaf yet (not issued, or the read races
// an in-flight write) keeps the fields empty, exactly as before.
func fillACMETimes(info *Info, staging bool) {
	dir := cacheDirFor(inspectCacheBase(), staging)
	for _, d := range info.Domains {
		leaf, err := cachedLeaf(dir, d)
		if err != nil {
			continue
		}
		info.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
		info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		return
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ACMEHosts returns the deduplicated domain list of every site with ACME
// enabled, in first-appearance order.
func ACMEHosts(cfg *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.ACME == nil {
			continue
		}
		for _, d := range s.Domains {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// stagingDirectoryURL is the Let's Encrypt staging CA (testing endpoint).
const stagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// ErrACMEDisabled is returned by ACMEHolder.GetCertificate when neither slot
// has a manager (no ACME site, no cached certificate, no pending library
// request), letting the data plane degrade to its plain certificate path.
var ErrACMEDisabled = errors.New("certmgr: ACME disabled")

// normHost normalizes a host for whitelist and routing comparisons the way
// autocert compares them: lowercase, no trailing dot, no :port suffix (the
// HTTP-01 handler receives r.Host, which may carry one).
func normHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") {
		h = h[:i] // strip :port, keep IPv6 literals intact
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// slotSnapshot is the rebuild-time knowledge of one slot: the site ACME
// domains whose staging flag matches the slot, and every domain with a
// certificate cached in the slot's directory. Immutable after construction
// (the dynamic HostPolicy and the routing read it without locking); the
// holder registry is the mutable part and is consulted live.
type slotSnapshot struct {
	sites  map[string]struct{}
	cached map[string]struct{}
}

func emptySnapshot() *slotSnapshot {
	return &slotSnapshot{sites: map[string]struct{}{}, cached: map[string]struct{}{}}
}

// allows reports whether host belongs to this slot per the snapshot.
func (s *slotSnapshot) allows(host string) bool {
	host = normHost(host)
	if _, ok := s.sites[host]; ok {
		return true
	}
	_, ok := s.cached[host]
	return ok
}

// acmeSlot pairs a slot manager with the snapshot its HostPolicy was built
// from. Stored atomically so routing and policy always agree within one
// manager generation.
type acmeSlot struct {
	mgr  *autocert.Manager
	snap *slotSnapshot
}

// slotIdx maps the staging flag to the slot array index (0 production).
func slotIdx(staging bool) int {
	if staging {
		return 1
	}
	return 0
}

// ACMEHolder dynamically holds the ACME managers — one per issuance mode —
// for the ACTIVE configuration: the production slot (DirCache(cacheDir)) and
// the staging slot (DirCache(cacheDir+stagingCacheSuffix) against the
// Let's Encrypt staging CA). The console publishes new revisions without a
// restart, so data-plane wiring (the TLS getCertificate chain and the HTTP-01
// challenge handler) must re-resolve the current managers on every use
// instead of holding the ones built at boot. Rebuild swaps both slots
// atomically; a slot is nil when nothing belongs to it (no ACME site with
// the matching staging flag, no cached certificate, no pending library
// request), which disables that mode cleanly. Manager construction is a pure
// in-memory operation, so a rebuild itself cannot fail: the swap always
// lands.
//
// Splitting the slots removes the old cross-site staging OR: a single
// staging-flagged site used to flip the one manager's DirectoryURL for every
// domain, sending production sites to the staging CA. Now each mode issues
// through — and serves from — its own manager and cache directory only.
//
// The per-publish full rebuild is a deliberate trade-off (review item S-1
// kept as-is): publish/ACME changes are low-frequency, and a singleton
// manager with incremental whitelist mutation would add shared-state
// complexity for no measurable gain. Accepted consequence: an ACME order in
// flight across a publish loses its challenge tokens (they live in the
// manager instance that created the order) and must be retried.
//
// Besides the managers the holder keeps a registry of certificate-library
// domains (registered by Service.Request, settled by run): in-flight and
// cooling-down domains stay whitelisted in their own slot so "request first,
// attach site later" issuance passes the HostPolicy before any site or cache
// entry exists, and a successful issuance keeps serving the fresh cache
// entry until the next rebuild folds it into the baked whitelist.
type ACMEHolder struct {
	cacheDir string

	slots [2]atomic.Pointer[acmeSlot] // [0] production, [1] staging

	// Registry of certificate-library registrations per slot: domain →
	// whitelist expiry (zero = while in flight, until a rebuild covers it).
	mu       sync.Mutex
	registry [2]map[string]time.Time

	// ensureMu serializes lazy slot construction (slotFor): two concurrent
	// first requests must not build two rival manager instances (the loser's
	// challenge tokens would live in a manager the data plane never routes
	// to). It is never taken on the handshake path.
	ensureMu sync.Mutex
}

// BaseDir returns the production cache directory base (staging certificates
// live in the sibling "-staging" directory).
func (h *ACMEHolder) BaseDir() string { return h.cacheDir }

// NewACMEHolder returns an empty holder persisting issued certificates in
// cacheDir.
func NewACMEHolder(cacheDir string) *ACMEHolder {
	h := &ACMEHolder{cacheDir: cacheDir}
	h.registry[0] = map[string]time.Time{}
	h.registry[1] = map[string]time.Time{}
	return h
}

// Prod returns the production slot manager, or nil when disabled.
func (h *ACMEHolder) Prod() *autocert.Manager { return h.slot(false).mgr }

// Staging returns the staging slot manager, or nil when disabled.
func (h *ACMEHolder) Staging() *autocert.Manager { return h.slot(true).mgr }

// slot returns the current slot state, or an empty one when never built.
func (h *ACMEHolder) slot(staging bool) *acmeSlot {
	if s := h.slots[slotIdx(staging)].Load(); s != nil {
		return s
	}
	return &acmeSlot{snap: emptySnapshot()}
}

// slotPolicy builds the dynamic HostPolicy of one slot: the rebuild-time
// snapshot plus the live registration registry (so a domain registered after
// this manager was built is immediately issuable without a rebuild).
func (h *ACMEHolder) slotPolicy(staging bool, snap *slotSnapshot) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		if snap.allows(host) || h.registered(staging, host) {
			return nil
		}
		return fmt.Errorf("acme/autocert: host %q not configured in HostWhitelist", host)
	}
}

// buildSlot assembles one slot from cfg: site ACME domains with the matching
// staging flag (first site email falling back to the global contact), the
// slot's cache directory contents, and the live registrations. The slot
// manager is nil when nothing belongs to the slot.
func (h *ACMEHolder) buildSlot(cfg *config.Config, globalEmail string, staging bool) *acmeSlot {
	snap := emptySnapshot()
	email := ""
	if cfg != nil {
		for i := range cfg.Sites {
			s := &cfg.Sites[i]
			if s.ACME == nil || s.ACME.Staging != staging {
				continue
			}
			for _, d := range s.Domains {
				snap.sites[normHost(d)] = struct{}{}
			}
			if email == "" {
				email = s.ACME.Email
			}
		}
	}
	if email == "" {
		email = globalEmail
	}
	for _, d := range CachedHosts(cacheDirFor(h.cacheDir, staging)) {
		snap.cached[normHost(d)] = struct{}{}
	}
	if len(snap.sites) == 0 && len(snap.cached) == 0 && !h.hasActive(staging) {
		return &acmeSlot{snap: snap}
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDirFor(h.cacheDir, staging)),
		HostPolicy: h.slotPolicy(staging, snap),
		Email:      email,
		Prompt:     autocert.AcceptTOS,
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: stagingDirectoryURL}
	}
	return &acmeSlot{mgr: m, snap: snap}
}

// Rebuild rebuilds both slot managers from cfg (the configuration just
// applied to the data plane) and swaps them in atomically. Returns the
// production and staging managers, either of which is nil when its slot has
// nothing to manage.
func (h *ACMEHolder) Rebuild(cfg *config.Config, globalEmail string) (prod, staging *autocert.Manager) {
	prodSlot := h.buildSlot(cfg, globalEmail, false)
	stagSlot := h.buildSlot(cfg, globalEmail, true)
	h.slots[0].Store(prodSlot)
	h.slots[1].Store(stagSlot)
	h.pruneRegistry(prodSlot.snap, stagSlot.snap)
	return prodSlot.mgr, stagSlot.mgr
}

// GetCertificate routes a TLS hello to the matching slot manager. It is the
// data-plane entry point (certSelector): TLS-ALPN-01 challenge hellos probe
// the production tokens first and fall through to staging on miss — token
// lookups are memory + cache reads only (autocert GetCertificate L277-289,
// x/crypto v0.57.0: the token branch never checks HostPolicy and never
// issues), so the double probe is safe. Regular hellos are routed by
// knowledge (routeManager) with exactly one manager consulted.
func (h *ACMEHolder) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
		return h.challengeCertificate(hello)
	}
	return h.routeCertificate(hello)
}

// challengeCertificate answers TLS-ALPN-01 token lookups across both slots:
// production first, staging on miss (or exclusively when the other slot is
// disabled). Neither probe can start an issuance.
func (h *ACMEHolder) challengeCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var firstErr error
	for _, m := range []*autocert.Manager{h.slot(false).mgr, h.slot(true).mgr} {
		if m == nil {
			continue
		}
		cert, err := m.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		return nil, ErrACMEDisabled
	}
	return nil, firstErr
}

// routeCertificate serves a regular handshake from exactly one manager.
func (h *ACMEHolder) routeCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m := h.routeManager(hello.ServerName)
	if m == nil {
		return nil, ErrACMEDisabled
	}
	return m.GetCertificate(hello)
}

// routeManager resolves the slot manager for a host by KNOWLEDGE only —
// never by try-then-fallback, because probing the wrong slot's regular path
// would start a real issuance against that slot's CA (production quota
// burn). Precedence, first match wins: active registrations per slot
// (in-flight / cooling-down certificate-library requests — the slot whose
// order is being issued answers its own challenges), then the site ACME
// domains of each slot (explicit operator intent), then cached certificates
// with production winning over staging when a domain exists in both
// directories. Unknown hosts go to production — or staging when production
// is disabled — whose HostPolicy rejects them with the familiar
// "host not configured" error.
func (h *ACMEHolder) routeManager(host string) *autocert.Manager {
	host = normHost(host)
	if h.registered(true, host) {
		if m := h.slot(true).mgr; m != nil {
			return m
		}
	}
	if h.registered(false, host) {
		if m := h.slot(false).mgr; m != nil {
			return m
		}
	}
	if s := h.slot(true); s.mgr != nil {
		if _, ok := s.snap.sites[host]; ok {
			return s.mgr
		}
	}
	if s := h.slot(false); s.mgr != nil {
		if _, ok := s.snap.sites[host]; ok {
			return s.mgr
		}
	}
	if s := h.slot(false); s.mgr != nil {
		if _, ok := s.snap.cached[host]; ok {
			return s.mgr
		}
	}
	if s := h.slot(true); s.mgr != nil {
		if _, ok := s.snap.cached[host]; ok {
			return s.mgr
		}
	}
	if m := h.slot(false).mgr; m != nil {
		return m
	}
	return h.slot(true).mgr
}

// HTTPHandler returns the port-80 challenge handler across both slots. Every
// non-challenge path falls through to the data plane unchanged; a challenge
// path is served by the manager knowledge routes it to — the manager whose
// order armed the token. autocert's HTTPHandler rejects hosts outside its
// own HostPolicy with 403 BEFORE the token lookup, so the routing must pick
// the right slot up front (unlike the TLS token branch, a blind
// prod-then-staging probe here would 403 staging-registered hosts). With
// both slots disabled the data plane is used directly.
func (h *ACMEHolder) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}
		if m := h.routeManager(r.Host); m != nil {
			m.HTTPHandler(fallback).ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

// ArmHTTP01 presets the http-01 challenge type on both live slot managers.
// The flag and the challenge tokens live per manager instance, so every
// manager swapped in by a rebuild must be armed again — or its first
// issuance offers http-01 only after some unrelated port-80 request happens
// to arm the challenge wrapper (a race the first issuance loses whenever DNS
// is not yet pointed at this host). Only the side effect is needed; the
// returned handler is discarded. Nil slots and a nil fallback are no-ops.
func (h *ACMEHolder) ArmHTTP01(fallback http.Handler) {
	if fallback == nil {
		return
	}
	for _, m := range []*autocert.Manager{h.slot(false).mgr, h.slot(true).mgr} {
		if m != nil {
			_ = m.HTTPHandler(fallback)
		}
	}
}

// slotFor returns the manager for the requested issuance mode (the default
// issueFn routes by the staging parameter, which the Service knows exactly).
// When the slot has no manager yet — the first library request on a fresh
// install: no site, no cached certificate — one is built lazily around the
// registration Service.Request made, so the domain is issuable immediately.
// A non-registered domain without a manager (renewal of a stale target)
// returns nil instead of building an inert manager.
func (h *ACMEHolder) slotFor(domain string, staging bool, email string) *autocert.Manager {
	if m := h.slot(staging).mgr; m != nil {
		return m
	}
	if !h.registered(staging, domain) {
		return nil
	}
	h.ensureMu.Lock()
	defer h.ensureMu.Unlock()
	if m := h.slot(staging).mgr; m != nil { // a concurrent ensure won
		return m
	}
	s := h.buildSlot(nil, email, staging)
	h.slots[slotIdx(staging)].Store(s)
	return s.mgr
}

// register marks domain as an in-flight issuance target of the slot: the
// dynamic HostPolicy allows it so request-first issuance passes even with no
// site and no cached certificate. The entry is settled by Service.run.
func (h *ACMEHolder) register(domain string, staging bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.registry[slotIdx(staging)][normHost(domain)] = time.Time{}
}

// settle transitions a registration after the issuance attempt: a failure
// keeps the domain whitelisted until the Service's failure cooldown ends (a
// retry re-registers after it, and meanwhile the domain keeps reaching its
// manager); a success keeps it without expiry so the data plane serves the
// freshly cached certificate immediately — the next Rebuild prunes it once
// CachedHosts covers the domain.
func (h *ACMEHolder) settle(domain string, staging bool, failed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	slot := h.registry[slotIdx(staging)]
	host := normHost(domain)
	if _, ok := slot[host]; !ok {
		return
	}
	if failed {
		slot[host] = time.Now().Add(failureCooldown)
		return
	}
	slot[host] = time.Time{}
}

// registered reports whether host has an active registration in the slot.
func (h *ACMEHolder) registered(staging bool, host string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	until, ok := h.registry[slotIdx(staging)][normHost(host)]
	if !ok {
		return false
	}
	return until.IsZero() || time.Now().Before(until)
}

// hasActive reports whether the slot has any active registration.
func (h *ACMEHolder) hasActive(staging bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for _, until := range h.registry[slotIdx(staging)] {
		if until.IsZero() || now.Before(until) {
			return true
		}
	}
	return false
}

// pruneRegistry garbage-collects the registration registry after a rebuild:
// expired cooldown entries are dropped, and succeeded registrations are
// dropped once the rebuilt snapshot covers their domain (cached certificates
// / site domains) — they stay in the whitelist through the snapshot from
// then on. Cooling-down and still-uncovered entries survive.
func (h *ACMEHolder) pruneRegistry(prodSnap, stagSnap *slotSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	snaps := [2]*slotSnapshot{prodSnap, stagSnap}
	for idx, snap := range snaps {
		for host, until := range h.registry[idx] {
			switch {
			case !until.IsZero() && !now.Before(until):
				delete(h.registry[idx], host) // cooldown over
			case until.IsZero() && snap.allows(host):
				delete(h.registry[idx], host) // covered by the rebuilt whitelist
			}
		}
	}
}
