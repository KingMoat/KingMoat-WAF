// Package proxy implements the KingMoat data plane core:
// site routing 鈫?body buffering 鈫?detection pipeline 鈫?reverse proxy,
// with atomic whole-state hot reload (docs/ARCHITECTURE.md 搂4.3).
package proxy

import (
	context "context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/coraza"
	"github.com/kingmoat/kingmoat/internal/intercept"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/metrics"
	"github.com/kingmoat/kingmoat/internal/penalty"
	"github.com/kingmoat/kingmoat/internal/pipeline"
	"github.com/kingmoat/kingmoat/internal/stages"
)

// planeState is the immutable per-configuration runtime: router, pipeline
// stages, response filter and their lifecycle handles. Reloads build a new
// state and swap the pointer; in-flight requests keep their old state.
type planeState struct {
	cfg        *config.Config
	router     *SiteRouter
	pipe       *pipeline.Pipeline
	respFilter *stages.RespFilter
	authSite   *stages.SiteAuth
	captcha    *stages.Captcha
	penalty    *penalty.Manager
	closers    []io.Closer
}

func (s *planeState) close() {
	for _, c := range s.closers {
		_ = c.Close()
	}
}

// Handler is the data plane request entry.
type Handler struct {
	state    atomic.Pointer[planeState]
	audit    logstore.Store
	logger   *slog.Logger
	observer apiasset.TickSink
	access   atomic.Pointer[accesslog.Sink] // nil → access logging off

	gmu   sync.Mutex
	ipmgr *ipgroups.Manager
	ipSig string
	// logSampler throttles per-request warning logs under attack storms
	// (audit records and the access log are never sampled).
	logSampler *logSampler
}

// SetAccessSink wires the full access-log pipeline (nil disables it). Call
// before serving traffic; the sink is process-wide, not per-config.
func (h *Handler) SetAccessSink(sink accesslog.Sink) {
	if sink == nil {
		return
	}
	h.access.Store(&sink)
}

// ensureGroups returns the IP-group provider for cfg, reusing the existing
// subscription manager when the group definitions did not change.
func (h *Handler) ensureGroups(cfg *config.Config) ipgroups.Provider {
	sig := groupSig(cfg.IPGroups)
	h.gmu.Lock()
	defer h.gmu.Unlock()
	if h.ipmgr != nil && h.ipSig == sig {
		return h.ipmgr
	}
	if h.ipmgr != nil {
		_ = h.ipmgr.Close()
	}
	h.ipmgr = ipgroups.NewManager(cfg, h.logger)
	h.ipSig = sig
	return h.ipmgr
}

func groupSig(groups []config.IPGroupSettings) string {
	if len(groups) == 0 {
		return ""
	}
	b, _ := json.Marshal(groups)
	return string(b)
}

// New builds the handler with an explicit pipeline (static / test / SDK
// mode). Protection stages from site security configs are NOT assembled
// here; use NewReloadable for managed mode.
func New(cfg *config.Config, pipe *pipeline.Pipeline, audit logstore.Store, logger *slog.Logger) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if pipe == nil {
		pipe = pipeline.New()
	}
	if audit == nil {
		audit = logstore.Noop()
	}
	router, err := buildRouter(cfg, nil, logger, nil, nil, 0)
	if err != nil {
		return nil, err
	}
	h := &Handler{audit: audit, logger: logger, logSampler: newLogSampler(logSampleLimitFromEnv())}
	h.state.Store(&planeState{cfg: cfg, router: router, pipe: pipe})
	return h, nil
}

// NewReloadable builds the handler from a full configuration, assembling all
// protection stages (ACL 鈫?Geo 鈫?BotDetect 鈫?Bot/Captcha 鈫?rate limit 鈫?
// semantic 鈫?Coraza/CRS) and the response filter. observer may be nil (the
// access-tick side channel is disabled). Use Reload to hot-swap
// configurations later.
func NewReloadable(cfg *config.Config, audit logstore.Store, logger *slog.Logger) (*Handler, error) {
	return NewReloadableObserved(cfg, audit, nil, logger)
}

// NewReloadableObserved is NewReloadable with the API-asset observer wired.
func NewReloadableObserved(cfg *config.Config, audit logstore.Store, observer apiasset.TickSink, logger *slog.Logger) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if audit == nil {
		audit = logstore.Noop()
	}
	h := &Handler{audit: audit, logger: logger, observer: observer, logSampler: newLogSampler(logSampleLimitFromEnv())}
	groups := h.ensureGroups(cfg)
	state, err := buildState(cfg, groups, observer, logger, nil)
	if err != nil {
		return nil, err
	}
	h.wirePenaltyHook(state.penalty)
	h.state.Store(state)
	return h, nil
}

// buildState materializes the whole runtime from a configuration. Any error
// (bad CIDR, bad regex, WAF compile failure) aborts before anything is
// published 鈥?the caller keeps the previous state (fail-static).
func buildState(cfg *config.Config, groups ipgroups.Provider, observer apiasset.TickSink, logger *slog.Logger, prevRouter *SiteRouter) (*planeState, error) {
	state := &planeState{cfg: cfg}

	acl, err := stages.NewACL(cfg, groups, logger)
	if err != nil {
		return nil, err
	}
	pen := penalty.New(penaltyPolicy(cfg), logger)
	geo, err := stages.NewGeo(cfg, logger)
	if err != nil {
		return nil, err
	}
	captcha, err := stages.NewCaptcha(cfg, logger)
	if err != nil {
		return nil, err
	}
	authSite, err := stages.NewSiteAuth(cfg, logger)
	if err != nil {
		return nil, err
	}
	rl, err := stages.NewRateLimit(cfg, logger)
	if err != nil {
		return nil, err
	}
	waf, err := coraza.New(cfg, logger)
	if err != nil {
		return nil, err
	}
	respFilter, err := stages.NewRespFilter(cfg, logger)
	if err != nil {
		return nil, err
	}
	// Wire the observe-only sensitive-data hook into the asset collector
	// (R1 signal) when the observer supports it.
	if obs, ok := observer.(apiasset.HitObserver); ok {
		respFilter.SetHitHook(obs.RespFilterHit)
	}
	semantic := stages.NewSemantic(cfg, logger)

	// Pipeline order: ACL 鈫?Geo 鈫?BotDetect 鈫?(Captcha | Bot) 鈫?RateLimit 鈫?
	// Semantic 鈫?CRS. BotDetect runs before the challenge stages so verified
	// good bots can bypass the JS challenge and bad bots can be denied early.
	var stageList []pipeline.Stage
	stageList = append(stageList, acl, stages.NewPenalty(pen, logger), geo, stages.NewExceptions(cfg))
	registry := stages.NewStageDisableRegistry()
	matcher, merr := stages.NewMatcher(cfg, registry, logger)
	if merr != nil {
		state.close()
		return nil, merr
	}
	stageList = append(stageList, matcher)
	var botStage *stages.BotChallenge
	if !captchaEnabled(cfg) {
		bot, err := stages.NewBotChallenge(cfg, logger)
		if err != nil {
			return nil, err
		}
		botStage = bot
	}
	if detectErr := func() error {
		detect, err := stages.NewBotDetect(cfg, botStage, logger)
		if err != nil {
			return err
		}
		stageList = append(stageList, detect)
		return nil
	}(); detectErr != nil {
		state.close()
		return nil, detectErr
	}
	if botStage != nil {
		stageList = append(stageList, botStage)
	} else if captcha != nil {
		stageList = append(stageList, captcha)
	}
	stageList = append(stageList, rl, semantic, waf)

	state.pipe = pipeline.New(stageList...)
	state.pipe.SetGate(registry)
	state.penalty = pen
	state.respFilter = respFilter
	state.authSite = authSite
	state.captcha = captcha
	state.closers = append(state.closers, rl)  // *RateLimit implements io.Closer
	state.closers = append(state.closers, geo) // closes mmdb handles

	sampleRate := 0.0
	if cfg.ApiAssets != nil && cfg.ApiAssets.Enabled {
		sampleRate = cfg.ApiAssets.Sample()
	}
	router, err := buildRouter(cfg, prevRouter, logger, respFilter, observer, sampleRate)
	if err != nil {
		state.close()
		return nil, err
	}
	state.router = router
	state.closers = append(state.closers, router) // stops pool health probers

	// Interception-page copy follows the active configuration (settings page).
	intercept.SetBlockPage(cfg.BlockPage)
	return state, nil
}

func captchaEnabled(cfg *config.Config) bool {
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Security != nil && s.Security.Captcha != nil && s.Security.Captcha.Enabled {
			return true
		}
	}
	return false
}

// wirePenaltyHook routes audit events into the penalty engine (SQLite store
// only; other sinks keep their default behaviour).
func (h *Handler) wirePenaltyHook(pen *penalty.Manager) {
	if pen == nil {
		return
	}
	if store, ok := h.audit.(*logstore.SQLiteStore); ok {
		store.SetWriteHook(pen.Observe)
	}
}

// penaltyPolicy extracts the penalty settings from the policy block.
func penaltyPolicy(cfg *config.Config) config.PenaltySettings {
	if cfg.Policy != nil && cfg.Policy.Penalty != nil {
		return *cfg.Policy.Penalty
	}
	return config.PenaltySettings{}
}

// Reload hot-swaps to a new configuration. On any build error the current
// state is kept untouched and the error is returned.
func (h *Handler) Reload(cfg *config.Config) error {
	groups := h.ensureGroups(cfg)
	var prevRouter *SiteRouter
	if old := h.state.Load(); old != nil && old.router != nil {
		prevRouter = old.router // enable incremental adoption of unchanged sites
	}
	state, err := buildState(cfg, groups, h.observer, h.logger, prevRouter)
	if err != nil {
		metrics.Reloads.Inc("failed")
		return err
	}
	h.wirePenaltyHook(state.penalty)
	old := h.state.Swap(state)
	if old != nil {
		old.close()
	}
	metrics.Reloads.Inc("ok")
	h.logger.Info("configuration reloaded",
		"sites", len(cfg.Sites), "revision_sites_prev", len(old.cfg.Sites))
	return nil
}

// CurrentConfig returns the active configuration snapshot (for the API).
func (h *Handler) CurrentConfig() *config.Config {
	return h.state.Load().cfg
}

// GetCertificate exposes SNI certificate selection for the HTTPS listener.
func (h *Handler) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return h.state.Load().router.CertificateFor(chi)
}

// TLSConfigFor applies per-site TLS behavior selected by SNI: the cipher
// suite profile (strong / compatible) and the HTTP/2 negotiation switch.
// Returning nil keeps the listener default (moderate profile, h2 + HTTP/1.1)
// so the common case pays nothing extra per handshake.
func (h *Handler) TLSConfigFor(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	sr := h.state.Load().router.Match(chi.ServerName)
	if sr == nil || sr.cfg == nil {
		return nil, nil
	}
	override := config.CipherSuitesOverride(sr.cfg.TLSProfile)
	h2 := sr.cfg.HTTP2Enabled == nil || *sr.cfg.HTTP2Enabled
	if !override && h2 {
		return nil, nil
	}
	out := &tls.Config{GetCertificate: h.GetCertificate}
	if h2 {
		out.NextProtos = []string{"h2", "http/1.1"}
	} else {
		out.NextProtos = []string{"http/1.1"}
	}
	if override {
		out.MinVersion = tls.VersionTLS12
		out.CipherSuites = config.CipherSuitesForProfile(sr.cfg.TLSProfile)
	}
	return out, nil
}

// clientSNIKey carries the original client SNI on the request context so an
// SNI-forwarding upstream dial can reuse it (see sniForwardDial).
type clientSNIKey struct{}

// http2Enabled reports whether the site negotiates HTTP/2 (default true).
func http2Enabled(s *config.Site) bool { return s.HTTP2Enabled == nil || *s.HTTP2Enabled }

// ServeHTTP implements the request lifecycle (docs/ARCHITECTURE.md 搂3.1):
// 鈶?site match 鈫?鈶?body buffering 鈫?鈶⑩懁鈶?pipeline 鈫?鈶?forward 鈫?鈶?response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := h.state.Load()

	traceID := newTraceID()
	r.Header.Set("X-KingMoat-Trace-Id", traceID)

	// Original client SNI: published on the request context so an
	// SNI-forwarding upstream dial can reuse it (config upstream.sni_forward).
	if r.TLS != nil && r.TLS.ServerName != "" {
		r = r.WithContext(context.WithValue(r.Context(), clientSNIKey{}, r.TLS.ServerName))
	}

	// Full access-log pipeline: capture status/bytes and emit one entry per
	// request. Hot-path cost is one wrapper plus a bounded-queue send.
	var accessSink *accesslog.Sink
	if s := h.access.Load(); s != nil {
		accessSink = s
	}
	var (
		accessSite    string
		accessOutcome = "forwarded"
		accessRule    string
	)
	var accessRec *accesslog.Recorder
	accessStart := time.Now()
	if accessSink != nil {
		accessRec = accesslog.NewRecorder(w)
		w = accessRec
	}
	defer func() {
		if accessSink == nil {
			return
		}
		clientIP := resolvedOrPeerIP(r)
		var status, nbytes int
		if accessRec != nil {
			status, nbytes = accessRec.Status(), accessRec.BytesWritten()
		}
		(*accessSink).Write(&accesslog.Entry{
			TS:        time.Now().Format(time.RFC3339Nano),
			TraceID:   traceID,
			Site:      accessSite,
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Query:     r.URL.RawQuery,
			Status:    status,
			Bytes:     nbytes,
			LatencyMS: time.Since(accessStart).Milliseconds(),
			UserAgent: r.UserAgent(),
			Outcome:   accessOutcome,
			Rule:      accessRule,
			AttackType: logstore.AttackTypeOf(accessRule),
		})
	}()

	sr := state.router.Match(r.Host)
	if sr == nil {
		accessOutcome, accessRule = "blocked", "router/no_site"
		if h.logSampler.Allow() {
			h.logger.Warn("no site matched",
				"host", r.Host, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		}
		v := pipeline.Deny("router/no_site", "no site matched for this host")
		h.audit.Write(h.newEvent(r, "", v, "blocked", 0, nil))
		metrics.RequestsTotal.Inc(r.Host, "blocked")
		metrics.DailyReqInc(r.Host, "blocked")
		metrics.StageHits.Inc("router")
		intercept.Deny(w, r, v, traceID)
		return
	}
	site := firstDomain(sr.cfg)
	accessSite = site

	// Disabled site: take it out of rotation with an explicit block page
	// (distinct from no_site so operators can tell the two apart).
	if sr.cfg.Disabled {
		v := pipeline.Deny("site/disabled", "site is disabled")
		h.audit.Write(h.newEvent(r, site, v, "blocked", 0, nil))
		metrics.RequestsTotal.Inc(r.Host, "blocked")
		metrics.DailyReqInc(r.Host, "blocked")
		metrics.StageHits.Inc("router")
		intercept.Deny(w, r, v, traceID)
		return
	}

	// Real-IP resolution (config.Site.RealIP): when the TCP peer is a
	// trusted proxy, take the client address from the forwarding header and
	// publish it on the request context. Every stage (ACL, GeoIP, rate
	// limit, bot, matcher, WAF) and all logging below then see the resolved
	// address instead of the LB/CDN peer.
	if ip := stages.ResolveRealIP(sr.cfg, r); ip != nil {
		r = r.WithContext(pipeline.WithClientIP(r.Context(), ip))
	}

	// Site-level HTTP鈫扝TTPS redirect: on the plain-HTTP listener, bounce to
	// the HTTPS URL before any inspection (redirects carry no body to check).
	// The ACME HTTP-01 path is exempt so certificate renewals keep working.
	if r.TLS == nil && sr.cfg.RedirectToHTTPS && !strings.HasPrefix(r.URL.Path, "/.well-known/") {
		accessOutcome, accessRule = "redirected", "redirect/https"
		target := httpsRedirectURL(state.cfg.ListenHTTPS, r)
		metrics.RequestsTotal.Inc(site, "redirected")
		metrics.DailyReqInc(site, "redirected")
		h.logger.Debug("http to https redirect", "site", site, "target", target, "trace", traceID)
		h.audit.Write(h.newEvent(r, site, pipeline.Allow(), "redirected", 0, nil))
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
		return
	}

	// Slider-captcha verification endpoint (handled before inspection so the
	// unverified client can reach it).
	if state.captcha != nil && strings.HasPrefix(r.URL.Path, stages.CaptchaVerifyPath) {
		if state.captcha.HandleVerify(w, r) {
			accessOutcome, accessRule = "challenged", "captcha/verify"
			metrics.RequestsTotal.Inc(site, "challenged")
			metrics.DailyReqInc(site, "challenged")
			return
		}
	}

	// Site-level Basic authentication (needs 401 + WWW-Authenticate, so it
	// runs outside the verdict pipeline).
	if state.authSite != nil {
		if !state.authSite.Authorize(r) {
			accessOutcome, accessRule = "blocked", "auth/basic"
			v := pipeline.Deny("auth/basic", "authentication required")
			v.Status = http.StatusUnauthorized
			state.authSite.Challenge(w, r)
			h.audit.Write(h.newEvent(r, site, v, "blocked", 0, nil))
			metrics.RequestsTotal.Inc(site, "blocked")
			metrics.DailyReqInc(site, "blocked")
			metrics.StageHits.Inc("auth")
			return
		}
	}

	rc := &pipeline.RequestContext{
		Request: r,
		Site:    pipeline.SiteView{Domain: site, Monitor: !sr.cfg.Intercept()},
		Values:  map[string]any{"trace_id": traceID},
	}

	// 鈶?Body buffering decision: buffer for inspection, reject, bypass
	// (stream through, header-phase detection only) or stream (inspect the
	// buffered prefix, forward the remainder untouched).
	var bodyBytes int
	if wantsBody(r) {
		data, over, pool, err := bufferBody(r, sr.cfg)
		if pool != nil {
			defer recycle(pool)
		}
		if err != nil {
			h.logger.Warn("request body read failed", "trace", traceID, "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if over && sr.cfg.WAF.RejectOverLimit() {
			v := pipeline.Deny("proxy/body_limit", "request body exceeds the inspection limit")
			h.logger.Warn("request body over limit",
				"site", site, "trace", traceID,
				"content_length", r.ContentLength, "limit", sr.cfg.WAF.BodyLimit())
			h.audit.Write(h.newEvent(r, site, v, "blocked", int(r.ContentLength), nil))
			metrics.RequestsTotal.Inc(site, "blocked")
			metrics.DailyReqInc(site, "blocked")
			metrics.StageHits.Inc("body_limit")
			intercept.Deny(w, r, v, traceID)
			return
		}
		if !over {
			rc.Body = data
			bodyBytes = len(data)
		} else if sr.cfg.WAF.StreamOverLimit() {
			// Stream policy: the buffered prefix participates in inspection
			// while the remainder forwards untouched (r.Body was rewound to
			// the full stream).
			rc.Body = data
			bodyBytes = len(data)
			h.logger.Warn("request body over limit, streaming remainder",
				"site", site, "trace", traceID,
				"content_length", r.ContentLength, "inspected", len(data))
		}
		// over && bypass: rc.Body stays nil; the stream was rewound intact.
	}

	// 鈶⑩懁 Detection pipeline: first non-allow verdict wins.
	v := state.pipe.Inspect(r.Context(), rc)
	switch v.Action {
	case pipeline.ActionDeny:
		accessRule = v.Rule
		outcome := "blocked"
		if sr.cfg.Intercept() {
			accessOutcome = "blocked"
			if h.logSampler.Allow() {
				h.logger.Warn("request blocked",
					"action", v.Action.String(), "rule", v.Rule, "reason", v.Reason,
					"site", site, "trace", traceID,
					"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			}
			if !trustedFlow(rc) {
				h.audit.Write(h.newEvent(r, site, v, "blocked", bodyBytes, rc))
			}
			metrics.RequestsTotal.Inc(site, "blocked")
			metrics.DailyReqInc(site, "blocked")
			metrics.StageHits.Inc(stageOf(v.Rule))
			intercept.Deny(w, r, v, traceID)
			return
		}
		outcome = "monitor_forwarded"
		accessOutcome = "monitor_forwarded"
		if h.logSampler.Allow() {
			h.logger.Info("monitor mode: deny verdict recorded, forwarding",
				"action", v.Action.String(), "rule", v.Rule, "reason", v.Reason,
				"site", site, "trace", traceID,
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		}
		if !trustedFlow(rc) {
			h.audit.Write(h.newEvent(r, site, v, "monitor", bodyBytes, rc))
		}
		metrics.RequestsTotal.Inc(site, outcome)
		metrics.DailyReqInc(site, outcome)
		metrics.StageHits.Inc(stageOf(v.Rule))

	case pipeline.ActionChallenge:
		accessRule = v.Rule
		if sr.cfg.Intercept() {
			accessOutcome = "challenged"
			cookieName, _ := rc.Values["challenge_cookie"].(string)
			if kind, _ := rc.Values["challenge_kind"].(string); kind == "slider" {
				pageHTML, _ := rc.Values["challenge_html"].(string)
				if h.logSampler.Allow() {
					h.logger.Info("slider challenge issued",
						"site", site, "trace", traceID, "remote", r.RemoteAddr)
				}
				if !trustedFlow(rc) {
					h.audit.Write(h.newEvent(r, site, v, "challenged", bodyBytes, rc))
				}
				metrics.RequestsTotal.Inc(site, "challenged")
				metrics.DailyReqInc(site, "challenged")
				metrics.StageHits.Inc("captcha")
				intercept.SliderChallenge(w, pageHTML)
				return
			}
			token, _ := rc.Values["challenge_token"].(string)
			if h.logSampler.Allow() {
				h.logger.Info("bot challenge issued",
					"site", site, "trace", traceID, "remote", r.RemoteAddr)
			}
			if !trustedFlow(rc) {
				h.audit.Write(h.newEvent(r, site, v, "challenged", bodyBytes, rc))
			}
			metrics.RequestsTotal.Inc(site, "challenged")
			metrics.DailyReqInc(site, "challenged")
			metrics.StageHits.Inc("bot")
			intercept.Challenge(w, cookieName, token)
			return
		}
		// Monitor mode: challenges are recorded but not enforced.
		accessOutcome = "monitor_forwarded"
		if !trustedFlow(rc) {
			h.audit.Write(h.newEvent(r, site, v, "monitor", bodyBytes, rc))
		}
		metrics.RequestsTotal.Inc(site, "monitor_forwarded")
		metrics.DailyReqInc(site, "monitor_forwarded")
	}

	// Forward upstream; response pipeline runs in ModifyResponse. The
	// access-tick side channel reads the bot label and buffered-body parameter
	// names from the request context (observer nil means no-op).
	if h.observer != nil {
		ctx := r.Context()
		if bc, _ := rc.Values["bot_class"].(string); bc != "" {
			ctx = context.WithValue(ctx, botClassKey, bc)
		}
		if rc.Body != nil {
			if keys := apiasset.JSONTopKeys(rc.Body, bodyKeyMaxBytes); len(keys) > 0 {
				ctx = context.WithValue(ctx, bodyKeysKey, keys)
			}
		}
		r = r.WithContext(ctx)
	}
	sr.px.ServeHTTP(w, r)
	metrics.RequestsTotal.Inc(site, "forwarded")
	metrics.DailyReqInc(site, "forwarded")
}

// resolvedOrPeerIP returns the real client IP when the proxy resolved one
// (config.Site.RealIP) for this request, otherwise the TCP peer address.
func resolvedOrPeerIP(r *http.Request) string {
	if ip := pipeline.ClientIPFromContext(r.Context()); ip != nil {
		return ip.String()
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	return clientIP
}

// trustedFlow reports whether an earlier pipeline stage marked the request
// as operator-allowed (ACL whitelist, matcher allow, whole-path exception,
// or geo whitelist with whitelist_trusted). Pipeline-derived audit events
// are skipped for trusted flows: writing them would recreate exactly the
// noise the operator silenced — and worse, denied events would re-feed the
// penalty counters, keeping the whitelisted IP banned indefinitely.
func trustedFlow(rc *pipeline.RequestContext) bool {
	if rc == nil {
		return false
	}
	trusted, ok := rc.Values["trusted"].(bool)
	return ok && trusted
}

func (h *Handler) newEvent(r *http.Request, site string, v pipeline.Verdict, action string, bodyBytes int, rc *pipeline.RequestContext) *logstore.Event {
	clientIP := resolvedOrPeerIP(r)
	ev := &logstore.Event{
		TraceID:    r.Header.Get("X-KingMoat-Trace-Id"),
		Site:       site,
		ClientIP:   clientIP,
		Method:     r.Method,
		Path:       r.URL.Path,
		URL:        r.Host + r.URL.RequestURI(),
		UserAgent:  r.UserAgent(),
		Action:     action,
		Rule:       v.Rule,
		AttackType: logstore.AttackTypeOf(v.Rule),
		Reason:     v.Reason,
		Status:     v.Status,
		BodyBytes:  bodyBytes,
	}
	if rc != nil {
		ev.BotClass, ev.BotName, ev.BotScore = stages.BotLabels(rc)
	}
	if action != "" && h.state.Load().cfg.CaptureRequests {
		captureInto(ev, r, rc)
	}
	return ev
}

// sensitiveHeaders are redacted before a request snapshot is stored.
var sensitiveHeaders = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true,
	"proxy-authorization": true, "x-api-key": true,
}

const bodySampleLimit = 2048

// bodyKeyMaxBytes caps JSON body key sampling for the asset side channel.
const bodyKeyMaxBytes = 64 << 10

func captureInto(ev *logstore.Event, r *http.Request, rc *pipeline.RequestContext) {
	headers := map[string]string{}
	for k, vs := range r.Header {
		val := strings.Join(vs, ", ")
		if sensitiveHeaders[strings.ToLower(k)] {
			val = "***"
		}
		headers[k] = val
	}
	ev.Headers = headers
	if rc != nil && len(rc.Body) > 0 {
		sample := rc.Body
		if len(sample) > bodySampleLimit {
			sample = sample[:bodySampleLimit]
		}
		ev.Body = redactSensitiveValues(string(sample))
	}
}

// sensitiveValueKeys are JSON/form keys whose values must never be stored in
// request-body snapshots (capture_requests enabled).
var sensitiveValueKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
	"access_key", "accesskey", "private_key", "credential", "session",
}

// redactSensitiveValues masks values of sensitive keys in a JSON or
// form-encoded body sample (privacy: capture_requests must never store
// credentials at rest).
func redactSensitiveValues(body string) string {
	// JSON: naive but safe value masking for known keys
	for _, key := range sensitiveValueKeys {
		for _, pat := range []string{
			`"` + key + `":"`,  // JSON key
			`"` + key + `": "`, // JSON key with space
			key + `=`,          // form-encoded key
		} {
			idx := strings.Index(strings.ToLower(body), strings.ToLower(pat))
			if idx < 0 {
				continue
			}
			start := idx + len(pat)
			end := start
			for end < len(body) {
				ch := body[end]
				if ch == '"' || ch == '&' || ch == ',' || ch == '}' || ch == '\n' {
					break
				}
				end++
			}
			if end > start {
				body = body[:start] + "***" + body[end:]
			}
		}
	}
	return body
}

func firstDomain(s *config.Site) string {
	if len(s.Domains) > 0 {
		return s.Domains[0]
	}
	return ""
}

// httpsRedirectURL builds the HTTPS target for a 308 redirect. The target
// keeps the request path and query; the host comes from the request and the
// port from the global listen_https (omitted when it is the default 443).
func httpsRedirectURL(listenHTTPS string, r *http.Request) string {
	port := ""
	if _, p, err := net.SplitHostPort(listenHTTPS); err == nil && p != "" && p != "443" {
		port = ":" + p
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	u := *r.URL
	u.Scheme = "https"
	u.Host = host + port
	return u.String()
}

// stageOf extracts the stage name from a rule identifier "<stage>/<rule>".
func stageOf(rule string) string {
	for i := 0; i < len(rule); i++ {
		if rule[i] == '/' {
			return rule[:i]
		}
	}
	return rule
}

func newTraceID() string {
	var b [8]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Groups exposes the live IP-group subscription manager (console IP-group
// management UI). Returns nil when no groups are configured.
func (h *Handler) Groups() *ipgroups.Manager {
	h.gmu.Lock()
	defer h.gmu.Unlock()
	return h.ipmgr
}
