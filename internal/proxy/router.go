package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/intercept"
	"github.com/kingmoat/kingmoat/internal/dynamics"
	"github.com/kingmoat/kingmoat/internal/metrics"
	"github.com/kingmoat/kingmoat/internal/pipeline"
	"github.com/kingmoat/kingmoat/internal/stages"
)

// siteRuntime is the built runtime state for one configured site.
type siteRuntime struct {
	cfg  *config.Site
	pool *Pool
	tr   *http.Transport     // per-site upstream transport (owned by the router)
	px   *httputil.ReverseProxy
	cert *tls.Certificate // SNI certificate, nil when the site has none
	// certStamp fingerprints the tls_cert file (size:mtime) so a swapped
	// certificate file invalidates an otherwise identical site config.
	certStamp string
	hdr       *headerRewriteConfig // compiled Site.Headers plan, nil when unset
}

// SiteRouter resolves a request host (or SNI name) to its site runtime.
type SiteRouter struct {
	byDomain   map[string]*siteRuntime
	pools      []*Pool           // all pools, closed on reload
	transports []*http.Transport // per-site upstream transports, idle conns closed on reload
	// keep/keepTr mark resources adopted by the next router after an
	// incremental reload (unchanged sites): Close skips them so the adopted
	// runtime keeps its live pools, health probes and warm connections.
	keep   map[*Pool]bool
	keepTr map[*http.Transport]bool
}

// upstreamMaxIdleConnsPerHost bounds the per-origin keep-alive pool. Go's
// DefaultMaxIdleConnsPerHost is 2, which forces connection churn (TCP and
// upstream TLS handshakes) at WAF traffic levels; 100 keeps hot connections
// alive for bursts typical of reverse-proxy workloads.
const upstreamMaxIdleConnsPerHost = 100

// newUpstreamTransport builds the tuned transport used for upstream
// forwarding. It must NOT inherit http.DefaultTransport: the default keeps
// only 2 idle connections per host and honors HTTP(S)_PROXY environment
// variables, both wrong for a data-plane proxy. verifyTLS=false skips
// upstream certificate verification (default: forwarded traffic targets
// internal servers with private-CA/self-signed certificates).
func newUpstreamTransport(u config.Upstream) *http.Transport {
	tr := &http.Transport{
		// Upstream traffic is directed by site config and must bypass
		// HTTP(S)_PROXY environment settings.
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        0, // no global cap; per-host cap below bounds each origin
		MaxIdleConnsPerHost: upstreamMaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !u.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // product default: internal upstreams, per-site opt-in
	}
	switch {
	case u.SNIForward:
		tr.DialTLSContext = sniForwardDial(u.VerifyTLS)
	case u.SNIHost != "":
		tr.DialTLSContext = sniHostDial(u.SNIHost, u.VerifyTLS)
	}
	return tr
}

// sniForwardDial returns a TLS dial that forwards the client's original SNI
// (published on the request context by Handler.ServeHTTP) to the HTTPS
// upstream, instead of the upstream address host. Falls back to the address
// host when the request carries no SNI (plain HTTP hop). Upstream HTTP/2 is
// not negotiated (ReverseProxy speaks HTTP/1.1 upstream).
func sniForwardDial(verifyTLS bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg := &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: !verifyTLS} //nolint:gosec // per-site opt-in
		if sni, _ := ctx.Value(clientSNIKey{}).(string); sni != "" {
			cfg.ServerName = sni
		}
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
}

func sniHostDial(sniHost string, verifyTLS bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		name := sniHost
		if name == "" {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				name = host
			} else {
				name = addr
			}
		}
		cfg := &tls.Config{ServerName: name, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: !verifyTLS} //nolint:gosec // per-site opt-in
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
}

// buildRouter materializes sites, upstream pools, reverse proxies and
// optional SNI certificates from the config. respFilter may be nil.
//
// prev (the router being replaced) enables incremental reloads: a site whose
// configuration is byte-identical and whose certificate file did not change
// adopts its existing pool/transport — live health probes, warm upstream
// connections and in-flight connection counters survive untouched. The
// ReverseProxy itself is always rebuilt so per-request closures (response
// filter, observer) always see the current configuration.

// buildRouter materializes sites, upstream pools, reverse proxies and
// optional SNI certificates from the config. respFilter may be nil.
//
// prev (the router being replaced) enables incremental reloads: a site whose
// configuration is byte-identical and whose certificate file did not change
// adopts its existing pool/transport — live health probes, warm upstream
// connections and in-flight connection counters survive untouched. The
// ReverseProxy itself is always rebuilt so per-request closures (response
// filter, observer) always see the current configuration.
func buildRouter(cfg *config.Config, prev *SiteRouter, logger *slog.Logger, respFilter *stages.RespFilter, observer apiasset.TickSink, sampleRate float64) (*SiteRouter, error) {
	byDomain := make(map[string]*siteRuntime, len(cfg.Sites))
	router := &SiteRouter{byDomain: byDomain, keep: map[*Pool]bool{}, keepTr: map[*http.Transport]bool{}}
	adopted := 0
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		site := firstDomain(s)

		var pool *Pool
		var tr *http.Transport
		sr := &siteRuntime{cfg: s, hdr: compileHeaderRewrite(s.Headers)}

		if prev != nil {
			if old := prev.byDomain[site]; old != nil && siteUnchanged(old, s) {
				// Adopt the existing pool/transport; the ReverseProxy is
				// rebuilt below so its closures stay current.
				pool, tr = old.pool, old.tr
				sr.cert = old.cert
				sr.certStamp = old.certStamp
				prev.keep[pool] = true
				prev.keepTr[tr] = true
				adopted++
			}
		}
		if pool == nil {
			var err error
			pool, err = NewPool(s.Upstream, s.Health, site, logger)
			if err != nil {
				router.Close()
				return nil, fmt.Errorf("site router: site %d: %w", i, err)
			}
			tr = newUpstreamTransport(s.Upstream)
			if s.TLSCert != "" {
				certPEM, err := os.ReadFile(s.TLSCert)
				if err != nil {
					router.Close()
					return nil, fmt.Errorf("site router: read tls_cert: %w", err)
				}
				keyPEM, err := os.ReadFile(s.TLSKey)
				if err != nil {
					router.Close()
					return nil, fmt.Errorf("site router: read tls_key: %w", err)
				}
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					router.Close()
					return nil, fmt.Errorf("site router: parse keypair: %w", err)
				}
				sr.cert = &cert
				sr.certStamp = certFileStamp(s.TLSCert)
			}
		}
		router.pools = append(router.pools, pool)
		router.transports = append(router.transports, tr)
		sr.pool = pool
		sr.tr = tr
		sr.px = buildReverseProxy(sr, tr, logger, respFilter, observer, sampleRate)

		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if _, dup := byDomain[d]; dup {
				router.Close()
				return nil, fmt.Errorf("site router: duplicate domain %q", d)
			}
			byDomain[d] = sr
		}
	}
	if adopted > 0 {
		logger.Info("router incremental reload", "sites", len(cfg.Sites), "adopted", adopted)
	}
	return router, nil
}

// siteUnchanged reports whether the existing runtime can be adopted for the
// new site definition: byte-identical config and an unchanged certificate
// file stamp (path + size + mtime).
func siteUnchanged(old *siteRuntime, s *config.Site) bool {
	if old == nil || old.cfg == nil || old.pool == nil || old.tr == nil {
		return false
	}
	a, errA := json.Marshal(old.cfg)
	b, errB := json.Marshal(s)
	if errA != nil || errB != nil || string(a) != string(b) {
		return false
	}
	return certFileStamp(old.cfg.TLSCert) == old.certStamp
}

// certFileStamp fingerprints a certificate file so content swaps (same path)
// invalidate the adopted runtime. Empty for ACME-managed sites (no file).
func certFileStamp(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "err"
	}
	return fmt.Sprintf("%d:%d", fi.Size(), fi.ModTime().UnixNano())
}

// Close stops all pool health probers and closes idle upstream connections
// so a replaced configuration cannot leak keep-alive pools (implements
// io.Closer). In-flight requests keep their connections until they finish.
func (r *SiteRouter) Close() error {
	for _, p := range r.pools {
		if r.keep[p] {
			continue // adopted by the next router after an incremental reload
		}
		_ = p.Close()
	}
	for _, tr := range r.transports {
		if r.keepTr[tr] {
			continue
		}
		tr.CloseIdleConnections()
	}
	return nil
}

func buildReverseProxy(sr *siteRuntime, tr *http.Transport, logger *slog.Logger, respFilter *stages.RespFilter, observer apiasset.TickSink, sampleRate float64) *httputil.ReverseProxy {
	domain := firstDomain(sr.cfg)
	dynEnabled := sr.cfg.Security != nil && sr.cfg.Security.Dynamic != nil && sr.cfg.Security.Dynamic.Enabled
	var dynMin, dynMax int64
	if dynEnabled {
		dynMin, dynMax = sr.cfg.Security.Dynamic.MinBytes, sr.cfg.Security.Dynamic.MaxBytes
	}
	return &httputil.ReverseProxy{
		// Tuned upstream transport: without this the ReverseProxy falls back
		// to http.DefaultTransport (MaxIdleConnsPerHost=2) and re-handshakes
		// connections under load.
		Transport: tr,
		// Periodic flush keeps slow/streamed responses moving (SSE is already
		// flushed immediately by the proxy for Content-Length==-1 and
		// text/event-stream); 100ms bounds buffering for everything else.
		FlushInterval: 100 * time.Millisecond,
		Rewrite: func(pr *httputil.ProxyRequest) {
			node := sr.pool.pickNode()
			pr.SetURL(node.url)
			pr.SetXForwarded()
			pr.Out.Host = pr.In.Host // preserve the inbound Host for origin vhosts
			// Dynamic protection rewrites bodies downstream: ask the origin
			// for an uncompressed response so the transform is possible.
			if dynEnabled {
				pr.Out.Header.Del("Accept-Encoding")
			}
			// User-configured per-site header operations run last so explicit
			// site config wins over the built-in X-Forwarded-* handling.
			applyHeaderOps(pr.Out.Header, pr.In, sr.hdr)
			// Track the chosen node for success/failure feedback in the
			// response and error paths (passive circuit breaker); also record
			// the inbound TLS state for dynamic protection.
			if node != nil {
				ctx := withNode(pr.Out.Context(), node)
				ctx = dynamics.WithClientSecure(ctx, pr.In.TLS != nil)
				pr.Out = pr.Out.WithContext(ctx)
			}
			// Access-tick side channel: bundle request-side observation
			// fields for ModifyResponse; sampling drops ticks early.
			if observer != nil && sampleRate > 0 {
				if sampleRate >= 1 || rand.Float64() < sampleRate {
					ip, _, _ := net.SplitHostPort(pr.In.RemoteAddr)
					if ip == "" {
						ip = pr.In.RemoteAddr
					}
					if rip := pipeline.ClientIPFromContext(pr.In.Context()); rip != nil {
						ip = rip.String() // real client IP when resolution is on
					}
					info := &tickInfo{
						Site:      domain,
						ClientIP:  ip,
						UA:        pr.In.UserAgent(),
						HasAuth:   pr.In.Header.Get("Authorization") != "" || pr.In.Header.Get("Cookie") != "",
						TLS:       pr.In.TLS != nil,
						QueryKeys: apiasset.QueryKeys(pr.In.URL.RawQuery),
						BodyKeys:  bodyKeysFrom(pr.In.Context()),
					}
					if class, _ := pr.In.Context().Value(botClassKey).(string); class != "" {
						info.BotClass = class
					}
					pr.Out = pr.Out.WithContext(withTickInfo(pr.Out.Context(), info))
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if n := sr.pool.nodeFromResponse(resp); n != nil {
				sr.pool.ReportDone(n)
				if resp.StatusCode < 500 {
					sr.pool.ReportSuccess(n)
				} else {
					sr.pool.ReportFailure(n, fmt.Sprintf("upstream status %d", resp.StatusCode))
				}
			}
			if respFilter != nil {
				respFilter.Apply(domain, resp)
			}
			if dynEnabled && dynamics.Apply(dynMin, dynMax, resp) {
				logger.Debug("dynamic protection applied", "site", domain)
			}
			if observer != nil {
				if info := tickInfoFrom(resp.Request.Context()); info != nil {
					rb := resp.ContentLength
					if rb < 0 {
						rb = 0
					}
					ct := resp.Header.Get("Content-Type")
					if i := strings.IndexByte(ct, ';'); i >= 0 {
						ct = strings.TrimSpace(ct[:i])
					}
					observer.Submit(apiasset.AccessTick{
						Site: info.Site, Method: resp.Request.Method, Path: resp.Request.URL.Path,
						QueryKeys: info.QueryKeys, BodyKeys: info.BodyKeys,
						Status: resp.StatusCode, RespCT: ct, RespBytes: rb,
						UA: info.UA, ClientIP: info.ClientIP, TLS: info.TLS,
						HasAuth: info.HasAuth, BotClass: info.BotClass,
					})
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if n := sr.pool.nodeFromRequest(r); n != nil {
				sr.pool.ReportDone(n)
				sr.pool.ReportFailure(n, err.Error())
			}
			logger.Error("upstream request failed",
				"site", firstDomain(sr.cfg), "method", r.Method, "path", r.URL.Path, "err", err)
			metrics.UpstreamErrors.Inc(firstDomain(sr.cfg))
			w.Header().Set("X-KingMoat-Upstream-Error", "true")
			intercept.Render502(w, r)
		},
	}
}

// Match resolves the site for a request Host header value (host[:port]).
func (r *SiteRouter) Match(host string) *siteRuntime {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(h)
	}
	return r.byDomain[host]
}

// CertificateFor implements SNI certificate selection for the HTTPS listener.
func (r *SiteRouter) CertificateFor(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sr := r.Match(chi.ServerName)
	if sr == nil || sr.cert == nil {
		return nil, fmt.Errorf("site router: no certificate for SNI %q", chi.ServerName)
	}
	return sr.cert, nil
}
