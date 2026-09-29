package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/kingmoat/kingmoat/internal/certmgr"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func boolPtr(b bool) *bool { return &b }

func mainTestSite(domain string) config.Site {
	return config.Site{
		Domains:  []string{domain},
		Mode:     "intercept",
		WAF:      &config.WAFSettings{Enabled: boolPtr(false)}, // no CRS for speed
		Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: "127.0.0.1:1"}}},
	}
}

func acmeSite(domain string) config.Site {
	s := mainTestSite(domain)
	s.ACME = &config.ACMESettings{}
	return s
}

// TestCertSelectorSiteCertificatesFirst covers the selection chain with ACME
// enabled: a matching site certificate wins, and a request no site can answer
// falls through to the ACME layer (rejected by the manager's HostWhitelist
// here, which proves the fall-through without touching the network).
func TestCertSelectorSiteCertificatesFirst(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := certmgr.EnsureSelfSigned(dir, "site.local")
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}

	site := mainTestSite("site.local")
	site.TLSCert, site.TLSKey = certPath, keyPath
	cfg := &config.Config{Sites: []config.Site{site, acmeSite("acme.local")}}

	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(cfg, "")

	sel := certSelector(handler, holder, testLogger())

	cert, err := sel(&tls.ClientHelloInfo{ServerName: "site.local"})
	if err != nil || cert == nil {
		t.Fatalf("SNI site.local: cert=%v err=%v, want site certificate", cert, err)
	}

	_, err = sel(&tls.ClientHelloInfo{ServerName: "unknown.local"})
	if err == nil || strings.Contains(err.Error(), "site router") {
		t.Fatalf("SNI unknown.local err = %v, want ACME-layer rejection", err)
	}
}

// TestCertSelectorDegradesWithoutACME covers the nil-manager degradation:
// with no ACME sites the chain behaves exactly like the plain
// site-certificate path.
func TestCertSelectorDegradesWithoutACME(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{mainTestSite("nossl.local")}}
	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	if prod, staging := holder.Rebuild(cfg, ""); prod != nil || staging != nil {
		t.Fatalf("Rebuild = (%v, %v), want nil (no ACME sites)", prod, staging)
	}

	sel := certSelector(handler, holder, testLogger())
	_, err = sel(&tls.ClientHelloInfo{ServerName: "nossl.local"})
	if err == nil || !strings.Contains(err.Error(), "site router") {
		t.Fatalf("SNI nossl.local err = %v, want plain site-router error", err)
	}
}

// TestCertSelectorFollowsRebuild covers the publish-time dynamic: before the
// first ACME publish the chain is site-only, after publishing an ACME site
// it consults the (rebuilt) manager, and after publishing its removal it
// degrades back to site-only.
func TestCertSelectorFollowsRebuild(t *testing.T) {
	cfgNoACME := &config.Config{Sites: []config.Site{mainTestSite("nossl.local")}}
	handler, err := proxy.NewReloadableObserved(cfgNoACME, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(cfgNoACME, "")
	sel := certSelector(handler, holder, testLogger())

	_, err = sel(&tls.ClientHelloInfo{ServerName: "nossl.local"})
	if err == nil || !strings.Contains(err.Error(), "site router") {
		t.Fatalf("pre-publish err = %v, want site-router error", err)
	}

	// Publish an ACME site: data plane reload + holder rebuild, as the
	// hot-reload consumer performs them.
	cfgACME := &config.Config{Sites: []config.Site{mainTestSite("nossl.local"), acmeSite("acme.local")}}
	if err := handler.Reload(cfgACME, 2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if prod, staging := holder.Rebuild(cfgACME, ""); prod == nil && staging == nil {
		t.Fatal("Rebuild after publish = nil, want manager")
	}
	_, err = sel(&tls.ClientHelloInfo{ServerName: "unknown.local"})
	if err == nil || strings.Contains(err.Error(), "site router") {
		t.Fatalf("post-publish err = %v, want ACME-layer rejection", err)
	}

	// Publish the removal: back to the plain site-certificate path.
	if err := handler.Reload(cfgNoACME, 3); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if prod, staging := holder.Rebuild(cfgNoACME, ""); prod != nil || staging != nil {
		t.Fatalf("Rebuild after removal = (%v, %v), want nil", prod, staging)
	}
	_, err = sel(&tls.ClientHelloInfo{ServerName: "nossl.local"})
	if err == nil || !strings.Contains(err.Error(), "site router") {
		t.Fatalf("post-removal err = %v, want site-router error", err)
	}
}

// TestACMEChallengeHandlerPassthroughWhenDisabled covers the 80-port wrapper
// with ACME disabled: even challenge paths reach the data plane.
func TestACMEChallengeHandlerPassthroughWhenDisabled(t *testing.T) {
	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "DATA") })
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(&config.Config{}, "") // no ACME sites -> nil manager

	h := acmeChallengeHandler{acme: holder, data: data}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://nossl.local/.well-known/acme-challenge/token", nil))
	if rec.Body.String() != "DATA" {
		t.Fatalf("challenge with ACME disabled: body = %q, want data plane response", rec.Body.String())
	}
}

// TestACMEChallengeHandlerServesCurrentManager covers the wrapper with an
// active manager: plain paths reach the data plane, challenge paths are
// answered by the manager (x/crypto HTTPHandler: unknown token -> 404, host
// outside HostWhitelist -> 403).
func TestACMEChallengeHandlerServesCurrentManager(t *testing.T) {
	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "DATA") })
	cfg := &config.Config{Sites: []config.Site{acmeSite("acme.local")}}
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(cfg, "")

	h := acmeChallengeHandler{acme: holder, data: data}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://acme.local/", nil))
	if rec.Body.String() != "DATA" {
		t.Fatalf("plain request body = %q, want data plane response", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://acme.local/.well-known/acme-challenge/token", nil))
	if rec.Code != http.StatusNotFound || rec.Body.String() == "DATA" {
		t.Fatalf("whitelisted challenge: code=%d body=%q, want ACME 404", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://other.local/.well-known/acme-challenge/token", nil))
	if rec.Code != http.StatusForbidden || rec.Body.String() == "DATA" {
		t.Fatalf("non-whitelisted challenge: code=%d body=%q, want ACME 403", rec.Code, rec.Body.String())
	}
}

// TestACMEChallengeHandlerFollowsRebuild covers the trap the wrapper exists
// for: challenges must be served by the CURRENT manager, so the first ACME
// publish starts answering challenges immediately and its removal stops it,
// all without rebuilding the wrapper.
func TestACMEChallengeHandlerFollowsRebuild(t *testing.T) {
	data := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "DATA") })
	holder := certmgr.NewACMEHolder(t.TempDir())
	h := acmeChallengeHandler{acme: holder, data: data}

	holder.Rebuild(&config.Config{Sites: []config.Site{acmeSite("new.local")}}, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://new.local/.well-known/acme-challenge/token", nil))
	if rec.Code != http.StatusNotFound || rec.Body.String() == "DATA" {
		t.Fatalf("challenge after publish: code=%d body=%q, want ACME 404", rec.Code, rec.Body.String())
	}

	holder.Rebuild(&config.Config{}, "")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://new.local/.well-known/acme-challenge/token", nil))
	if rec.Body.String() != "DATA" {
		t.Fatalf("challenge after removal: body = %q, want data plane response", rec.Body.String())
	}
}

// TestTLSOverrideConfigKeepsCertChain covers the GetConfigForClient wrapper
// used by the HTTPS listener: a per-site override (http2 disabled or cipher
// profile) returns a fresh tls.Config and Go replaces the connection config
// with it wholesale, so the override must carry the same certificate chain
// as the listener - site SNI certificates first, then the ACME fallback.
// Without the re-attach, an ACME-only site with such settings can never
// complete a 443 handshake (the pre-fix bug). The override must also carry
// the TLS-ALPN-01 challenge proto: proxy.TLSConfigFor rebuilds NextProtos
// from scratch with only h2/http1.1.
func TestTLSOverrideConfigKeepsCertChain(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := certmgr.EnsureSelfSigned(dir, "cert.local")
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}

	withCert := mainTestSite("cert.local")
	withCert.TLSCert, withCert.TLSKey = certPath, keyPath
	withCert.HTTP2Enabled = boolPtr(false) // forces a per-site override config

	withoutCert := mainTestSite("nocert.local")
	withoutCert.HTTP2Enabled = boolPtr(false) // override + ACME-only SNI scenario

	cfg := &config.Config{Sites: []config.Site{withCert, withoutCert, acmeSite("acme.local")}}
	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(cfg, "")

	getCert := certSelector(handler, holder, testLogger())
	wrap := tlsConfigForWithFallback(handler, getCert)

	// Site with a static certificate: the override answers with the same
	// site certificate the listener chain would serve (site cert first).
	chi := &tls.ClientHelloInfo{ServerName: "cert.local"}
	oc, err := wrap(chi)
	if err != nil || oc == nil {
		t.Fatalf("TLSConfigFor(cert.local) = (%v, %v), want override config", oc, err)
	}
	if !slices.Contains(oc.NextProtos, acme.ALPNProto) {
		t.Fatalf("override NextProtos = %v, want %q present for TLS-ALPN-01", oc.NextProtos, acme.ALPNProto)
	}
	certOverride, errOverride := oc.GetCertificate(chi)
	certChain, errChain := getCert(chi)
	if errOverride != nil || certOverride == nil {
		t.Fatalf("override GetCertificate(cert.local) err=%v, want site certificate", errOverride)
	}
	if errChain != nil || certChain == nil || !bytes.Equal(certOverride.Certificate[0], certChain.Certificate[0]) {
		t.Fatalf("override certificate differs from listener chain result (chain err=%v)", errChain)
	}

	// ACME-only SNI through an override: the site router has no certificate,
	// so the override must fall through to the ACME layer exactly like the
	// listener chain - not stop at the site router (pre-fix behavior).
	chi = &tls.ClientHelloInfo{ServerName: "nocert.local"}
	oc, err = wrap(chi)
	if err != nil || oc == nil {
		t.Fatalf("TLSConfigFor(nocert.local) = (%v, %v), want override config", oc, err)
	}
	if !slices.Contains(oc.NextProtos, acme.ALPNProto) {
		t.Fatalf("override NextProtos = %v, want %q present for TLS-ALPN-01", oc.NextProtos, acme.ALPNProto)
	}
	_, wantErr := getCert(chi)
	_, gotErr := oc.GetCertificate(chi)
	if gotErr == nil || wantErr == nil || gotErr.Error() != wantErr.Error() {
		t.Fatalf("override GetCertificate(nocert.local) err=%v, want listener chain error %v", gotErr, wantErr)
	}
	if strings.Contains(gotErr.Error(), "site router") {
		t.Fatalf("override stopped at the site router, ACME fallback lost: %v", gotErr)
	}

	// Default site settings keep the listener default (no override config).
	oc, err = wrap(&tls.ClientHelloInfo{ServerName: "acme.local"})
	if err != nil || oc != nil {
		t.Fatalf("TLSConfigFor(acme.local) = (%v, %v), want nil override (listener default)", oc, err)
	}
}

// --- T-01: data-plane ACME challenge channel (R1 + R2 + R4) ---

// TestCertSelectorChallengeSplitBeforeSiteCert pins the R1 routing order: a
// TLS-ALPN-01 challenge connection (ALPN exactly "acme-tls/1", cf. autocert
// wantsTokenCert) must reach the ACME manager before any site certificate,
// while regular handshakes keep the unchanged site-certificates-first chain.
func TestCertSelectorChallengeSplitBeforeSiteCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := certmgr.EnsureSelfSigned(dir, "site.local")
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}

	site := mainTestSite("site.local")
	site.TLSCert, site.TLSKey = certPath, keyPath
	cfg := &config.Config{Sites: []config.Site{site, acmeSite("acme.local")}}

	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	holder.Rebuild(cfg, "")

	sel := certSelector(handler, holder, testLogger())

	// Challenge hello for the static-cert site: the manager answers first.
	// Its HostWhitelist does not include site.local, so the call must be
	// rejected by the ACME layer - a site certificate must never shadow the
	// challenge path (pre-fix behavior returned the site certificate here).
	chi := &tls.ClientHelloInfo{ServerName: "site.local", SupportedProtos: []string{acme.ALPNProto}}
	if cert, cerr := sel(chi); cerr == nil || cert != nil {
		t.Fatalf("challenge hello for site.local: cert=%v err=%v, want ACME-layer rejection", cert, cerr)
	} else if strings.Contains(cerr.Error(), "site router") {
		t.Fatalf("challenge hello stopped at the site router: %v", cerr)
	}

	// The same hello for the whitelisted ACME site reaches the manager's
	// token store: no token was issued, so autocert reports the miss.
	chi = &tls.ClientHelloInfo{ServerName: "acme.local", SupportedProtos: []string{acme.ALPNProto}}
	if _, cerr := sel(chi); cerr == nil || !strings.Contains(cerr.Error(), "no token cert") {
		t.Fatalf("challenge hello for acme.local: err=%v, want autocert token-cert miss", cerr)
	}

	// Regular handshakes are untouched: the static site certificate wins
	// with no ALPN, http/1.1-only and h2 ALPN alike.
	for _, protos := range [][]string{nil, {"http/1.1"}, {"h2", "http/1.1"}} {
		cert, cerr := sel(&tls.ClientHelloInfo{ServerName: "site.local", SupportedProtos: protos})
		if cerr != nil || cert == nil {
			t.Fatalf("regular hello protos=%v: cert=%v err=%v, want site certificate", protos, cert, cerr)
		}
	}
}

// TestDataPlaneTLSConfigChallengeALPN pins the R1 listener wiring: the 443
// TLS config carries the autocert-style ALPN set (h2, http/1.1, acme-tls/1)
// alongside the data-plane hardening values (MinVersion, moderate cipher
// suites) that autocert's own TLSConfig() does not set.
func TestDataPlaneTLSConfigChallengeALPN(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{mainTestSite("plain.local")}}
	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}
	holder := certmgr.NewACMEHolder(t.TempDir())
	getCert := certSelector(handler, holder, testLogger())

	tc := dataPlaneTLSConfig(handler, getCert)
	if want := []string{"h2", "http/1.1", acme.ALPNProto}; !slices.Equal(tc.NextProtos, want) {
		t.Fatalf("NextProtos = %v, want %v", tc.NextProtos, want)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2 (data-plane hardening lost)", tc.MinVersion)
	}
	if !slices.Equal(tc.CipherSuites, config.TLSCipherSuitesModerate) {
		t.Fatalf("CipherSuites = %v, want the moderate profile (data-plane hardening lost)", tc.CipherSuites)
	}
}

// autocertTryHTTP01 reads the manager's private tryHTTP01 flag: the only
// observable effect of the HTTP-01 preset. Test-only reflection into
// x/crypto (pinned at v0.57.0 by go.mod).
func autocertTryHTTP01(m *autocert.Manager) bool {
	f := reflect.ValueOf(m).Elem().FieldByName("tryHTTP01")
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Bool()
}

// TestArmHTTP01ArmsBothSlots pins the R2 preset at holder level: fresh
// slot managers start without http-01 armed and ArmHTTP01 arms BOTH slots; a
// rebuild swaps in NEW instances that start unarmed again (the
// instance-isolation root cause this fixes); nil fallback or nil slots are
// no-ops.
func TestArmHTTP01ArmsBothSlots(t *testing.T) {
	fallback := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	holder := certmgr.NewACMEHolder(t.TempDir())

	// No ACME sites -> nil managers: the preset is a no-op, not a panic.
	holder.Rebuild(&config.Config{}, "")
	if holder.Prod() != nil || holder.Staging() != nil {
		t.Fatal("expected nil managers without ACME sites")
	}
	holder.ArmHTTP01(nil)      // nil fallback: no-op on empty slots
	holder.ArmHTTP01(fallback) // still a no-op: nothing to arm

	cfg := &config.Config{Sites: []config.Site{
		acmeSite("new.local"),
		{Domains: []string{"stag.local"}, ACME: &config.ACMESettings{Staging: true}},
	}}
	holder.Rebuild(cfg, "")
	prod, staging := holder.Prod(), holder.Staging()
	if prod == nil || staging == nil {
		t.Fatalf("expected both slot managers after publish (prod=%v staging=%v)", prod, staging)
	}
	if autocertTryHTTP01(prod) || autocertTryHTTP01(staging) {
		t.Fatal("fresh managers must not have http-01 armed before the preset")
	}
	holder.ArmHTTP01(fallback)
	if !autocertTryHTTP01(prod) || !autocertTryHTTP01(staging) {
		t.Fatal("preset must arm http-01 on both slot managers")
	}

	// A rebuild swaps in NEW instances: they start unarmed and need their own
	// preset.
	holder.Rebuild(cfg, "")
	prod2, staging2 := holder.Prod(), holder.Staging()
	if prod2 == prod || staging2 == staging {
		t.Fatal("rebuild must produce fresh manager instances")
	}
	if autocertTryHTTP01(prod2) || autocertTryHTTP01(staging2) {
		t.Fatal("rebuilt managers must start unarmed")
	}
	holder.ArmHTTP01(fallback)
	if !autocertTryHTTP01(prod2) || !autocertTryHTTP01(staging2) {
		t.Fatal("preset must arm http-01 on the rebuilt managers")
	}
}

// TestArmHTTP01RebuildRace exercises the publish-time wiring under the race
// detector: one goroutine swaps managers and arms each new pair (as
// rebuildACME does), the other arms whatever is current (as the boot path
// and the challenge wrapper do).
func TestArmHTTP01RebuildRace(t *testing.T) {
	fallback := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	holder := certmgr.NewACMEHolder(t.TempDir())
	cfg := &config.Config{Sites: []config.Site{acmeSite("race.local")}}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // publisher: rebuild + arm
		defer wg.Done()
		for i := 0; i < 50; i++ {
			holder.Rebuild(cfg, "")
			holder.ArmHTTP01(fallback)
		}
		close(done)
	}()
	go func() { // data plane: arm the current managers
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				holder.ArmHTTP01(fallback)
			}
		}
	}()
	wg.Wait()
}

// TestACMEFailureLimiterWindow covers the R4 limiter mechanics with
// synthetic time: first failure logs, in-window failures are suppressed,
// the post-window failure logs with the suppressed count, and a success
// resets the window.
func TestACMEFailureLimiterWindow(t *testing.T) {
	l := &acmeFailureLimiter{window: time.Minute}
	base := time.Unix(1700000000, 0)

	if ok, sup := l.allow(base); !ok || sup != 0 {
		t.Fatalf("first failure: ok=%v suppressed=%d, want logged with no suppression", ok, sup)
	}
	for i := 1; i <= 5; i++ {
		if ok, _ := l.allow(base.Add(time.Duration(i) * time.Second)); ok {
			t.Fatalf("failure %d inside the window logged, want suppressed", i)
		}
	}
	if ok, sup := l.allow(base.Add(2 * time.Minute)); !ok || sup != 5 {
		t.Fatalf("post-window failure: ok=%v suppressed=%d, want logged with suppressed=5", ok, sup)
	}
	l.reset()
	if ok, sup := l.allow(base.Add(3 * time.Minute)); !ok || sup != 0 {
		t.Fatalf("post-success failure: ok=%v suppressed=%d, want logged immediately", ok, sup)
	}
}

// captureHandler is a slog handler recording every record for assertions.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

func (h *captureHandler) hasAttr(key, want string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key && a.Value.String() == want {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// TestCertSelectorFailureWarnRateLimited pins the R4 handshake-path logging:
// repeated ACME failures produce exactly one rate-limited warning carrying
// the SNI, and a success through the ACME layer resets the window so the
// next failure is logged again.
func TestCertSelectorFailureWarnRateLimited(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{mainTestSite("plain.local"), acmeSite("acme.local")}}
	handler, err := proxy.NewReloadableObserved(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("NewReloadableObserved: %v", err)
	}

	// Seed the manager's cache with a valid certificate for cached.local so
	// one SNI succeeds through the ACME layer (whitelist + DirCache hit).
	// autocert DirCache layout: private key block first, then certificates.
	cacheDir := t.TempDir()
	certPath, keyPath, err := certmgr.EnsureSelfSigned(t.TempDir(), "cached.local")
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "cached.local"), append(keyPEM, certPEM...), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	holder := certmgr.NewACMEHolder(cacheDir)
	holder.Rebuild(cfg, "")

	rec := &captureHandler{}
	sel := certSelector(handler, holder, slog.New(rec))

	fail := &tls.ClientHelloInfo{ServerName: "unknown.local"} // not whitelisted -> ACME error
	for i := 0; i < 10; i++ {
		if _, aerr := sel(fail); aerr == nil {
			t.Fatal("expected ACME failure for unknown.local")
		}
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("warn records after 10 failures = %d, want 1 (rate limited)", got)
	}
	if !rec.hasAttr("sni", "unknown.local") {
		t.Fatal("warn record does not carry the SNI")
	}

	// A success through the ACME layer resets the window. The hello must be
	// ECDSA-capable per autocert supportsECDSA (an ECDSA cipher suite, not
	// just a signature scheme): otherwise the cache key gets the "+rsa"
	// variant, misses the seeded entry, and the manager would attempt a real
	// issuance. With the right hello the lookup hits the seeded cache entry
	// and never leaves the process.
	ok := &tls.ClientHelloInfo{
		ServerName:       "cached.local",
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
	if cert, cerr := sel(ok); cerr != nil || cert == nil {
		t.Fatalf("cached.local: cert=%v err=%v, want ACME cache hit", cert, cerr)
	}
	if _, aerr := sel(fail); aerr == nil {
		t.Fatal("expected ACME failure for unknown.local")
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("warn records after success+failure = %d, want 2 (window reset)", got)
	}
}
