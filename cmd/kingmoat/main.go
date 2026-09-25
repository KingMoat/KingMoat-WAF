// Command kingmoat runs the KingMoat WAF: a detection-pipeline fronted
// reverse proxy with the embedded OWASP CRS, in two modes:
//
//   - static:        -config file only, no console (M1 behavior)
//   - all-in-one:    -console-addr enables the embedded console/API/SQLite
//                    config store with hot reload (recommended)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kingmoat/kingmoat/internal/accesslog"
	"github.com/kingmoat/kingmoat/internal/ai"
	"github.com/kingmoat/kingmoat/internal/alerting"
	"github.com/kingmoat/kingmoat/internal/alerts"
	"github.com/kingmoat/kingmoat/internal/api"
	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/certmgr"
	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/consoletls"
	"github.com/kingmoat/kingmoat/internal/ipgroups"
	"github.com/kingmoat/kingmoat/internal/logshipper"
	"github.com/kingmoat/kingmoat/internal/logstore"
	"github.com/kingmoat/kingmoat/internal/metrics"
	"github.com/kingmoat/kingmoat/internal/proxy"
	"github.com/kingmoat/kingmoat/internal/stages"
	"github.com/kingmoat/kingmoat/internal/redact"
	"github.com/kingmoat/kingmoat/internal/telemetry"
	"github.com/kingmoat/kingmoat/internal/webui"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON config file (static seed / static mode)")
	consoleAddr := flag.String("console-addr", "", "enable the embedded console+API on this address (all-in-one mode)")
	consoleDB := flag.String("console-db", "kingmoat.db", "SQLite path for the embedded console config store")
	consoleListenHTTP := flag.String("console-listen-http", "", "optional additional plain-HTTP listen address for the embedded console (e.g. :8081); -console-addr serves HTTPS by default")
	aiDBPath := flag.String("ai-db", "", "SQLite path for the AI assistant store (default: <console-db base>-ai.db)")
	aiConfigPath := flag.String("ai-config", "", "JSON file with the \"ai\" section (default: read from -config)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("kingmoat", version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Resolve the initial configuration and the hot-reload source per mode.
	var (
		center *configcenter.Center
		seed   *config.Config
	)
	seed, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config failed", "err", err)
		os.Exit(1)
	}

	switch {
	case *consoleAddr != "":
		center, err = configcenter.Open(*consoleDB, seed, logger)
		if err != nil {
			logger.Error("open config center failed", "err", err)
			os.Exit(1)
		}
		defer func() { _ = center.Close() }()
	default:
		// static mode: config file only, no reloads
	}

	// Audit pipeline: embedded SQLite (FTS5) store always; webhook + log
	// shipper when configured. The proxy receives the fan-out store; the
	// console API and the AI assistant read the same store.
	auditDir := seed.AuditLogDir
	if auditDir == "" {
		auditDir = "logs"
	}
	// Retention/archive settings snapshot the effective config at boot;
	// hot reloads do not recreate the store (restart to apply).
	activeCfg := seed
	if center != nil {
		_, activeCfg = center.Current()
	}

	auditStore, err := logstore.NewSQLiteStore(filepath.Join(auditDir, "audit.db"), logger)
	if err != nil {
		logger.Error("open audit store failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = auditStore.Close() }()

	purgeDays := 0
	if d := activeCfg.AuditRetentionDaysOrDefault(); d > 0 {
		purgeDays = d
	}
	archiveEnabled := activeCfg.AuditArchive.IsEnabled()
	archiver := logstore.NewArchiver(auditStore, logstore.ArchiveOptions{
		Snapshot:      archiveEnabled,
		Dir:           filepath.Join(auditDir, "archive"),
		RetentionDays: activeCfg.AuditArchive.RetentionDaysOrDefault(),
		PurgeDays:     purgeDays,
		UploadPrefix:  "archives",
	}, logger)
	if archiveEnabled || purgeDays > 0 {
		go archiver.Run(ctx)
	}

	// Disk guard: when the data volume exceeds the high watermark (default
	// 90%), reclaim oldest-first (archive FIFO, then oldest live events)
	// until the low watermark (default 65%).
	logstore.StartDiskGuard(ctx, auditStore, auditDir, filepath.Join(auditDir, "archive"), seed.DiskGuard, logger)

	auditStores := []logstore.Store{auditStore}
	droppers := []logstore.Dropper{auditStore}
	var auditShipper *logshipper.Shipper
	if seed.Webhook != nil {
		wh := alerting.NewWebhook(*seed.Webhook, logger)
		auditStores = append(auditStores, wh)
		droppers = append(droppers, wh)
		defer func() { _ = wh.Close() }()
		logger.Info("webhook alerting enabled", "url", redact.URL(seed.Webhook.URL))
	}
	if seed.LogShipper != nil {
		sh, serr := logshipper.New(*seed.LogShipper, logger)
		if serr != nil {
			logger.Error("log shipper disabled", "err", serr)
		} else {
			auditStores = append(auditStores, sh)
			droppers = append(droppers, sh)
			auditShipper = sh
			defer func() { _ = sh.Close() }()
			logger.Info("log shipper enabled", "type", seed.LogShipper.Type)
			if seed.LogShipper.Type == "s3" && seed.LogShipper.UploadArchives {
				prefix := strings.Trim(seed.LogShipper.Prefix, "/")
				if prefix == "" {
					prefix = "kingmoat/audit"
				}
				archiver.SetUploader(func(localPath, _ string) error {
					return sh.UploadArchive(localPath, prefix+"/archives/"+filepath.Base(localPath))
				})
				logger.Info("audit archive off-box upload enabled", "bucket", seed.LogShipper.Bucket)
			}
		}
	}
	audit := logstore.Multi(auditStores...)

	auditDirAbs, _ := filepath.Abs(auditDir)
	// Cumulative request counters survive restarts (dashboard 累计请求).
	metrics.LoadRequestsBase(filepath.Join(auditDirAbs, "metrics-state.json"))
	go metrics.StartRequestsPersist(ctx, filepath.Join(auditDirAbs, "metrics-state.json"), 30*time.Second)
	// Per-site "today" counters survive restarts within the same day
	// (/api/stats/per-site 站点列表徽标).
	metrics.LoadDailyRequestsBase(filepath.Join(auditDirAbs, "requests_daily.json"))
	metrics.LoadRequestsHistory(filepath.Join(auditDirAbs, "requests_history.json"))
	go metrics.StartDailyRequestsPersist(ctx, filepath.Join(auditDirAbs, "requests_daily.json"), filepath.Join(auditDirAbs, "requests_history.json"), 30*time.Second)
	var accessSink *accesslog.Tee

	// Expose the audit drop counter (previously defined but never set).
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var sum int64
				for _, d := range droppers {
					sum += d.Dropped()
				}
				metrics.AuditDropped.Set(float64(sum))
				metrics.AuditQueueDepth.Set(float64(auditStore.Pending()))
				if auditShipper != nil {
					metrics.LogShipperDropped.Set(float64(auditShipper.Dropped()))
					metrics.LogShipperQueueDepth.Set(float64(auditShipper.Depth()))
				}
				if accessSink != nil {
					metrics.AccessLogDropped.Set(float64(accessSink.Dropped()))
					metrics.AccessLogQueueDepth.Set(float64(accessSink.Depth()))
				}
			}
		}
	}()

	// Full access-log pipeline (external storage only: ClickHouse/ES/Loki).
	var accessRing *accesslog.Ring
	if seed.AccessLog != nil && seed.AccessLog.Enabled {
		as, aerr := accesslog.New(*seed.AccessLog, logger)
		if aerr != nil {
			logger.Error("access log pipeline disabled", "err", aerr)
		} else {
			// Console live tail: keep the most recent entries in memory so the
			// access-log page works even when the pipeline only ships off-host.
			accessRing = accesslog.NewRing(5000)
			accessSink = accesslog.NewTee(accessRing, as)
			defer func() { _ = as.Close() }()
			logger.Info("access log pipeline enabled", "type", seed.AccessLog.Type, "url", redact.URL(seed.AccessLog.URL), "sample_pct", seed.AccessLog.SamplePctOrDefault())
		}
	}

	// Prometheus metrics push target (settings → feature toggles): the full
	// /metrics body is POSTed to the configured receiver on an interval.
	if seed.Metrics != nil && seed.Metrics.Enabled && seed.Metrics.Push != nil && seed.Metrics.Push.URL != "" {
		go metrics.StartPusher(ctx, seed.Metrics.Push.URL, seed.Metrics.Push.IntervalOrDefault(), seed.Metrics.Push.BearerToken, version, logger)
	}

	// WAF anomaly alert engine + risk engine: both hot-applied on publish.
	// stopAlerts cancels the old engine goroutine; buildEngines swaps a fresh
	// immutable AssetsOptions snapshot into assetsRef so the console API sees
	// the new risk engine without racing in-flight handlers.
	var (
		assetStore     *apiasset.Store
		assetCollector *apiasset.Collector
		assetsRef      *atomic.Pointer[api.AssetsOptions]
	)
	var stopAlerts context.CancelFunc = func() {}
	buildEngines := func(cfg *config.Config) {
		stopAlerts()
		if cfg.Alerts != nil && cfg.Alerts.Enabled {
			var emailN alerts.Notifier
			var whN alerts.Notifier
			if cfg.Email != nil && cfg.Email.Enabled {
				emailN = alerting.NewEmailNotifier(*cfg.Email)
			}
			if cfg.Webhook != nil && cfg.Webhook.URL != "" {
				whN = &alerts.WebhookNotifier{URL: cfg.Webhook.URL, Secret: cfg.Webhook.Secret, Keyword: cfg.Webhook.Keyword}
			}
			alerts.SetRecentProvider(func() []logstore.Event { return auditStore.Recent(2000) })
			auditDir := "logs"
			if cfg.AuditLogDir != "" {
				auditDir = cfg.AuditLogDir
			}
			eng := alerts.New(*cfg.Alerts, emailN, whN, metrics.RequestsTotal.Sum, logger).
				SetDeps(auditDir, auditStore.Aggregate)
			alertCtx, alertCancel := context.WithCancel(ctx)
			stopAlerts = alertCancel
			go eng.Run(alertCtx)
			logger.Info("waf alert engine enabled",
				"webhook", cfg.Alerts.NotifyWebhook, "email", cfg.Alerts.NotifyEmail)
		} else {
			logger.Info("waf alert engine disabled")
		}
		if assetCollector != nil {
			var riskEng *apiasset.Engine
			if cfg.Risks != nil && cfg.Risks.Enabled {
				riskEng = apiasset.NewEngine(assetStore,
					&apiasset.RisksConfig{ZombieDays: cfg.Risks.ZombieDays},
					apiasset.NewWebhookNotifier(cfg.Risks.NotifyWebhook, logger), logger)
				assetCollector.SetBruteForceHook(riskEng.OnBruteForce)
				logger.Info("risk engine enabled")
			} else {
				logger.Info("risk engine disabled")
			}
			assetsRef.Store(&api.AssetsOptions{Store: assetStore, Collector: assetCollector,
				Engine: riskEng, RisksEnabled: riskEng != nil})
		}
	}

	// API asset learning (all-in-one mode only: observes the local data
	// plane and persists to its own SQLite file). Variables are declared at
	// outer scope so buildEngines can rebuild the risk engine per-publish.
	// The first buildEngines call runs AFTER this block so the risk engine
	// is assembled at boot when config.risks.enabled is already set.
	{
		// Console mode: always wire the asset store/collector so the module
		// toggles (api_assets.enabled) hot-apply via config revisions without
		// a restart; sampling gates the actual data flow.
		dbPath := "kingmoat-assets.db"
		if seed.ApiAssets != nil && seed.ApiAssets.DbPath != "" {
			dbPath = seed.ApiAssets.DbPath
		} else if *consoleDB != "" {
			dbPath = strings.TrimSuffix(*consoleDB, ".db") + "-assets.db"
		}
		assetStore, err = apiasset.Open(dbPath)
		if err != nil {
			logger.Error("open api asset store failed", "err", err)
			os.Exit(1)
		}
		defer func() { _ = assetStore.Close() }()
		minHits := 5
		sampleRate := 1.0
		if seed.ApiAssets != nil {
			minHits = seed.ApiAssets.MinHitsOrDefault()
			sampleRate = seed.ApiAssets.Sample()
		}
		assetCollector = apiasset.NewCollector(assetStore, minHits, logger)
		defer func() { _ = assetCollector.Close() }()
		logger.Info("api asset learning enabled (observe)", "db", dbPath)
		_ = sampleRate
	}
	// Hot-rebuild container: console handlers load one immutable snapshot per
	// request; buildEngines swaps fresh snapshots in on every publish (the
	// engine-off path publishes Engine=nil the same way).
	assetsRef = &atomic.Pointer[api.AssetsOptions]{}
	assetsRef.Store(&api.AssetsOptions{Store: assetStore, Collector: assetCollector})
	buildEngines(activeCfg)

	// ACME automatic certificates (TLS-ALPN-01 on the HTTPS listener,
	// HTTP-01 challenge short-circuited on the HTTP listener). The holder is
	// rebuilt on every console publish (hot-reload consumer below) so ACME
	// sites added, edited or removed after boot take effect without a
	// restart. Boot state follows the ACTIVE config (console revisions),
	// not the disk seed, mirroring the listener addresses below.
	acmeHolder := certmgr.NewACMEHolder("acme-cache")
	if acmeHolder.Rebuild(activeCfg, activeCfg.AcmeEmail) != nil {
		logger.Info("ACME certificate management enabled", "hosts", len(certmgr.ACMEHosts(activeCfg)))
	}

	// Certificate-library ACME service: async issuance requests, status
	// queries and cert-library entries (API endpoints). It shares the
	// holder's cache base so requested certificates are immediately
	// servable by the data plane; the global-email fallback resolves the
	// ACTIVE config's AcmeEmail on every use (follows hot reload).
	acmeSvc := certmgr.NewService(acmeHolder, func() string {
		if center == nil {
			return activeCfg.AcmeEmail
		}
		_, c := center.Current()
		return c.AcmeEmail
	})

	// rebuildACME swaps the ACME manager to one built from the configuration
	// just applied to the data plane, keeping the HostWhitelist in sync with
	// the live site router (new domains issue on demand, removed domains
	// stop being answered). Called only after a successful data-plane reload;
	// on reload failure the previous manager stays so both layers agree.
	rebuildACME := func(cfg *config.Config) {
		prev := acmeHolder.Load()
		m := acmeHolder.Rebuild(cfg, cfg.AcmeEmail)
		if m == nil {
			if prev != nil {
				logger.Info("ACME certificate management disabled")
			}
			return
		}
		logger.Info("ACME certificate management reloaded", "hosts", len(certmgr.ACMEHosts(cfg)))
	}

	// Bootstrap self-signed certificate (10 years) so the certificate
	// library is usable out of the box (HTTPS sites without a CA cert).
	if center != nil && *consoleAddr != "" {
		host, _ := os.Hostname()
		if cp, _, cerr := certmgr.EnsureSelfSigned(filepath.Dir(*consoleDB), host); cerr != nil {
			logger.Warn("self-signed certificate generation failed", "err", cerr)
		} else {
			logger.Info("self-signed certificate ready", "cert", cp)
		}
	}

	handler, err := proxy.NewReloadableObserved(activeCfg, audit, assetCollector, logger)
	if err != nil {
		logger.Error("build data plane failed", "err", err)
		os.Exit(1)
	}
	if accessSink != nil {
		handler.SetAccessSink(accessSink)
	}

	var aiBuilder func(cfg *config.Config)

	// Telemetry wiring (state + builder) lives at this scope so the hot-reload
	// goroutine below can call it; the client itself is only created in
	// all-in-one mode where the console (and thus the switch) exists.
	var (
		telMu        sync.Mutex
		telClient    *telemetry.Telemetry
		telPrev      bool
		buildTelemetry func(cfg *config.Config)
	)

	// Hot reload wiring per mode.
	switch {
	case center != nil:
		go func() {
			ch, cancel := center.Subscribe()
			defer cancel()
			for {
				select {
				case <-ctx.Done():
					return
				case rev := <-ch:
					_, cfg := center.Current()
					applyErr := handler.Reload(cfg)
					center.SetApplyStatus(rev, applyErr) // surface reload outcome to publish callers
					if applyErr != nil {
						logger.Error("hot reload failed, keeping previous config", "revision", rev, "err", applyErr)
					} else {
						logger.Info("hot reload applied", "revision", rev)
						rebuildACME(cfg) // ACME sites hot-apply on publish
					}
					if aiBuilder != nil {
						aiBuilder(cfg) // ai toggle hot-applies (close+rebuild)
					}
					telMu.Lock()
					bt := buildTelemetry
					telMu.Unlock()
					if bt != nil {
						bt(cfg) // telemetry switch hot-applies
					}
					buildEngines(cfg) // alerts + risks toggle hot-applies
				}
			}
		}()
	}

	// Embedded console (all-in-one mode): API + WebUI + Prometheus metrics.
	if center != nil && *consoleAddr != "" {
		// Console TLS: self-signed bootstrap into the certificate library,
		// hot-swappable from the UI.
		chost, _ := os.Hostname()
		cdir := filepath.Dir(*consoleDB)
		ctlMgr, cerr := consoletls.New(consoletls.Options{
			LibraryRoot: filepath.Join(cdir, "uploads", "certs"),
			StateDir:    cdir,
			Listen:      *consoleAddr,
			Host:        chost,
			Logger:      logger,
		})
		if cerr != nil {
			logger.Error("console tls init failed", "err", cerr)
			os.Exit(1)
		}

		// AI assistant (read-only; hot-rebuilt when the ai config toggles).
		// Assembly and rebuild share the same Supervisor + ResolveSettings
		// path from internal/ai.
		aicfgPath := *aiConfigPath
		if aicfgPath == "" {
			aicfgPath = *configPath
		}
		aiDB := *aiDBPath
		if aiDB == "" {
			aiDB = strings.TrimSuffix(*consoleDB, ".db") + "-ai.db"
		}
				// Shared builder: identical field set for the community assembly
		// point; new DataSources fields are wired once in internal/ai.
		aiSources := ai.NewCenterSources(center, auditStore, version, func() map[string]any { return computeStats(auditStore, center) })
				aiSup := ai.NewSupervisor(logger)
		// KEK guards the stored provider API key; it lives next to the console
		// DB (same StateDir pattern as the console TLS state).
		aiSup.SetKEKPath(filepath.Join(cdir, "ai-kek.key"))
		defer aiSup.Close()
		buildAI := func(cfg *config.Config) {
			email := config.EmailSettings{}
			if cfg.Email != nil {
				email = *cfg.Email
			}
			aiSup.Rebuild(ai.ResolveSettings(cfg.AI, aicfgPath, filepath.Join(cdir, "ai-kek.key"), logger), aiSources, aiDB, email)
		}
		buildAI(activeCfg)
		aiBuilder = buildAI

		// Anonymous install statistics (opt-in via config telemetry.enabled;
		// hot-applied on publish). Three consecutive unreachable endpoints stop
		// reporting for this install (persisted); toggling the switch off→on
		// resets that marker. Nothing is sent while the switch is off.
		telMethod := strings.TrimSpace(os.Getenv("KINGMOAT_INSTALL_METHOD"))
		if telMethod == "" {
			if _, err := os.Stat("/.dockerenv"); err == nil {
				telMethod = "docker"
			} else if runtime.GOOS == "windows" {
				telMethod = "windows"
			} else {
				telMethod = "binary"
			}
		}
		telMu.Lock()
		oldTel := telClient
		telClient = nil
		telMu.Unlock()
		if oldTel != nil {
			oldTel.Stop()
		}
		telMu.Lock()
		buildTelemetry = func(cfg *config.Config) {
			enabled := cfg.Telemetry != nil && cfg.Telemetry.Enabled
			telMu.Lock()
			old := telClient
			telClient = nil
			telMu.Unlock()
			if old != nil {
				old.Stop()
			}
			if !enabled {
				telMu.Lock()
				telPrev = false
				telMu.Unlock()
				return
			}
			tc := telemetry.New(telemetry.Config{
				Endpoint:      "https://tele.aiuc.cc/api/check",
				Version:       version,
				AppName:       "kingmoat",
				Product:       "kingmoat-waf",
				InstallMethod: telMethod,
				IDFile:        filepath.Join(cdir, "telemetry_id"),
			})
			telMu.Lock()
			prev := telPrev
			telMu.Unlock()
			if !prev {
				tc.ResetStopFlag() // 开关 关→开：清除 3 次不可达标记，给一次重新尝试
			}
			tc.Start()
			telMu.Lock()
			telClient = tc
			telPrev = true
			telMu.Unlock()
		}
		telMu.Unlock()
		buildTelemetry(activeCfg)
		defer func() {
			telMu.Lock()
			tc := telClient
			telMu.Unlock()
			if tc != nil {
				tc.Stop()
			}
		}()

		mux := http.NewServeMux()
		logsStorage := &api.LogsStorageInfo{
			Store:                "sqlite",
			RetentionDays:        purgeDays,
			ArchiveEnabled:       archiveEnabled,
			ArchiveRetentionDays: activeCfg.AuditArchive.RetentionDaysOrDefault(),
		}
		apiSrv := api.New(api.Options{
			Center: center,
			Logs:   auditStore,
			LogsStorage: logsStorage,
			ConsoleTLS:       ctlMgr,
			Auth:        api.NewAuth(os.Getenv("KINGMOAT_ADMIN_HASH")).SetTOTP(os.Getenv("KINGMOAT_ADMIN_TOTP")).SetSessionTTL(activeCfg.Security.SessionTTLOrDefault()),
			Version: version,
			WebUI:   webui.Handler(version),
			AccessRing: accessRing,
			AIFn:    func() *ai.Service { return aiSup.Ref() },
			AIKEKFn: func() []byte {
				k, kerr := aiSup.KEK()
				if kerr != nil {
					logger.Warn("ai kek load failed", "err", kerr)
					return nil
				}
				return k
			},
			AssetsRef: assetsRef,
			ACME:      acmeSvc,
			PProf:   os.Getenv("KINGMOAT_PPROF") != "", // /debug/pprof behind console auth
			GroupsFn: func() *ipgroups.Manager { return handler.Groups() },
			DisableStateFn: func() *stages.StageDisableRegistry { return handler.DisableState() },
		GeoDBFn:  geoDBPath(center),
		})
		mux.Handle("/", apiSrv.Handler())
		csrv := &http.Server{
			Addr: *consoleAddr, Handler: mux,
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 1 << 20,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return ctlMgr.Certificate(), nil // hot-swappable console certificate
				},
			},
		}
		if *consoleListenHTTP != "" {
			plain := &http.Server{
				Addr: *consoleListenHTTP, Handler: mux,
				ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
				MaxHeaderBytes: 1 << 20,
			}
			go func() {
				logger.Info("console plain-http listener started", "addr", *consoleListenHTTP)
				if err := plain.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("console plain-http listener exited", "err", err)
				}
			}()
			defer func() { _ = plain.Close() }()
		}
		go func() {
			if os.Getenv("KINGMOAT_ADMIN_HASH") == "" {
				logger.Warn("console auth not anchored by KINGMOAT_ADMIN_HASH; the built-in kmadmin bootstrap account forces a password change at first login")
			}
			logger.Info("console started", "addr", *consoleAddr, "tls", true)
			if err := csrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("console exited", "err", err)
			}
		}()
		defer func() { _ = csrv.Close() }()
	}

	// Listener addresses follow the ACTIVE configuration (console revisions),
	// not the disk seed: operators change listen_http/listen_https in the
	// console and expect them to survive a restart. Static mode keeps the
	// seed as-is (activeCfg == seed there).
	listenCfg := seed
	if center != nil {
		_, listenCfg = center.Current()
	}
	startServers(ctx, handler, listenCfg, acmeHolder, logger)
}

// certSelector returns the TLS certificate selection chain for the HTTPS
// listener: site SNI certificates first, then the current ACME manager
// (issue/renew on demand). The manager is re-resolved from the holder on
// every handshake so console publishes take effect without a restart; with
// ACME disabled the chain degrades to the plain site-certificate path.
func certSelector(handler *proxy.Handler, acme *certmgr.ACMEHolder) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := handler.GetCertificate(chi)
		if err == nil {
			return cert, nil
		}
		if m := acme.Load(); m != nil {
			return m.GetCertificate(chi)
		}
		return nil, err
	}
}

// acmeChallengeHandler serves ACME HTTP-01 challenges ahead of the data
// plane. It re-resolves the current ACME manager on every request: a wrapper
// built once at boot would pin the manager's HostWhitelist, so challenges
// for domains published later would be rejected and domains removed from the
// config would keep being answered. With ACME disabled the request goes
// straight to the data plane.
type acmeChallengeHandler struct {
	acme *certmgr.ACMEHolder
	data http.Handler
}

func (h acmeChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m := h.acme.Load(); m != nil {
		m.HTTPHandler(h.data).ServeHTTP(w, r)
		return
	}
	h.data.ServeHTTP(w, r)
}

// computeStats mirrors the console /api/stats aggregation for AI tools.
func computeStats(logs logstore.Queryable, center *configcenter.Center) map[string]any {
	now := time.Now()
	blockedToday, challengedToday, monitorToday := 0, 0, 0
	for _, ev := range logs.Recent(1000) {
		ts, err := time.Parse(time.RFC3339Nano, ev.TS)
		if err == nil && ts.Before(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())) {
			continue
		}
		switch ev.Action {
		case "blocked":
			blockedToday++
		case "challenged":
			challengedToday++
		case "monitor":
			monitorToday++
		}
	}
	rev, cfg := center.Current()
	return map[string]any{
		"revision": rev, "sites": len(cfg.Sites),
		"blocked_today": blockedToday, "challenged_today": challengedToday, "monitor_today": monitorToday,
	}
}

// tlsConfigForWithFallback wraps the per-site TLS override so it always
// carries the listener's certificate chain: TLSConfigFor returns a fresh
// tls.Config when a site disables HTTP/2 or overrides the cipher profile,
// and Go then replaces the connection config wholesale - without this, the
// override's site-router-only GetCertificate would bypass the ACME fallback
// and an ACME-only site with such settings could never complete a handshake.
func tlsConfigForWithFallback(handler *proxy.Handler, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		oc, err := handler.TLSConfigFor(chi)
		if oc != nil {
			oc.GetCertificate = getCert
		}
		return oc, err
	}
}

func startServers(ctx context.Context, handler *proxy.Handler, cfg *config.Config, acme *certmgr.ACMEHolder, logger *slog.Logger) {
	var (
		srvHTTP *http.Server
		srvTLS  *http.Server
		errCh   = make(chan error, 2)
	)

	// Certificate selection: site SNI certificates first, then the ACME
	// manager (issue/renew on demand). certSelector re-resolves the current
	// manager on every handshake so publishes take effect without a restart.
	getCert := certSelector(handler, acme)

	if cfg.ListenHTTP != "" {
		// Serve ACME HTTP-01 challenges from the CURRENT manager before the
		// data plane (the wrapper re-resolves it per request).
		httpHandler := http.Handler(acmeChallengeHandler{acme: acme, data: handler})
		srvHTTP = &http.Server{
			Addr:              cfg.ListenHTTP,
			Handler:           httpHandler,
			ReadHeaderTimeout: 10 * time.Second,
			// No ReadTimeout/WriteTimeout: a reverse proxy must tolerate slow
			// uploads and long responses; header/idle bounds stop the
			// slowloris-style attacks instead.
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		lnHTTP, lerr := net.Listen("tcp", cfg.ListenHTTP)
		if lerr != nil {
			logger.Error("http listener bind failed", "addr", cfg.ListenHTTP, "err", lerr)
			os.Exit(1)
		}
		go func() { errCh <- srvHTTP.Serve(proxy.NewLimitedListener(lnHTTP)) }()
	}

	if cfg.ListenHTTPS != "" {
		srvTLS = &http.Server{
			Addr:              cfg.ListenHTTPS,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
			TLSConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				CipherSuites:       config.TLSCipherSuitesModerate,
				GetCertificate:     getCert,
				GetConfigForClient: tlsConfigForWithFallback(handler, getCert), // per-site override must keep the ACME fallback
			},
		}
		lnTLS, lerr := net.Listen("tcp", cfg.ListenHTTPS)
		if lerr != nil {
			logger.Error("https listener bind failed", "addr", cfg.ListenHTTPS, "err", lerr)
			os.Exit(1)
		}
		go func() { errCh <- srvTLS.ServeTLS(proxy.NewLimitedListener(lnTLS), "", "") }()
	}

	if srvHTTP == nil && srvTLS == nil {
		logger.Error("no listener configured")
		os.Exit(1)
	}

	logger.Info("kingmoat data plane started",
		"version", version,
		"http", cfg.ListenHTTP, "https", cfg.ListenHTTPS, "sites", len(cfg.Sites))

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited unexpectedly", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range []*http.Server{srvHTTP, srvTLS} {
		if srv != nil {
			_ = srv.Shutdown(shutdownCtx)
		}
	}
	logger.Info("kingmoat data plane stopped")
}

// geoDBPath returns a closure resolving the active GeoIP mmdb path from the
// current configuration (follows hot reload).
func geoDBPath(center *configcenter.Center) func() string {
	return func() string {
		_, c := center.Current()
		for i := range c.Sites {
			if s := &c.Sites[i]; s.Security != nil && s.Security.Geo != nil && s.Security.Geo.Enabled {
				return s.Security.Geo.DBPath
			}
		}
		return ""
	}
}
