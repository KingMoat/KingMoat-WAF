package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	sel := certSelector(handler, holder)

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
	if m := holder.Rebuild(cfg, ""); m != nil {
		t.Fatalf("Rebuild = %v, want nil (no ACME sites)", m)
	}

	sel := certSelector(handler, holder)
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
	sel := certSelector(handler, holder)

	_, err = sel(&tls.ClientHelloInfo{ServerName: "nossl.local"})
	if err == nil || !strings.Contains(err.Error(), "site router") {
		t.Fatalf("pre-publish err = %v, want site-router error", err)
	}

	// Publish an ACME site: data plane reload + holder rebuild, as the
	// hot-reload consumer performs them.
	cfgACME := &config.Config{Sites: []config.Site{mainTestSite("nossl.local"), acmeSite("acme.local")}}
	if err := handler.Reload(cfgACME); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m := holder.Rebuild(cfgACME, ""); m == nil {
		t.Fatal("Rebuild after publish = nil, want manager")
	}
	_, err = sel(&tls.ClientHelloInfo{ServerName: "unknown.local"})
	if err == nil || strings.Contains(err.Error(), "site router") {
		t.Fatalf("post-publish err = %v, want ACME-layer rejection", err)
	}

	// Publish the removal: back to the plain site-certificate path.
	if err := handler.Reload(cfgNoACME); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m := holder.Rebuild(cfgNoACME, ""); m != nil {
		t.Fatalf("Rebuild after removal = %v, want nil", m)
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
// complete a 443 handshake (the pre-fix bug).
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

	getCert := certSelector(handler, holder)
	wrap := tlsConfigForWithFallback(handler, getCert)

	// Site with a static certificate: the override answers with the same
	// site certificate the listener chain would serve (site cert first).
	chi := &tls.ClientHelloInfo{ServerName: "cert.local"}
	oc, err := wrap(chi)
	if err != nil || oc == nil {
		t.Fatalf("TLSConfigFor(cert.local) = (%v, %v), want override config", oc, err)
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
