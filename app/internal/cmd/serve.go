package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/admin"
	"github.com/codeswhat/sockguard/internal/banner"
	"github.com/codeswhat/sockguard/internal/clientacl"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/ownership"
	"github.com/codeswhat/sockguard/internal/policybundle"
	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/ratelimit"
	"github.com/codeswhat/sockguard/internal/reload"
	"github.com/codeswhat/sockguard/internal/responsefilter"
	"github.com/codeswhat/sockguard/internal/version"
	"github.com/codeswhat/sockguard/internal/visibility"
)

const readHeaderTimeout = 5 * time.Second
const idleTimeout = 120 * time.Second
const maxHeaderBytes = 1 << 20

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the proxy server",
	Long:  "Start the sockguard proxy, listening for Docker API requests and filtering them according to configured rules.",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("listen-socket", "", "proxy socket path (overrides config)")
	serveCmd.Flags().String("upstream-socket", "", "Docker socket path (overrides config)")
	serveCmd.Flags().String("log-level", "", "log level (overrides config)")
	serveCmd.Flags().String("log-format", "", "log format (overrides config)")
	serveCmd.Flags().String("deny-response-verbosity", "", "deny response verbosity: verbose or minimal (overrides config)")
}

func runServe(cmd *cobra.Command, args []string) error {
	return runServeWithDeps(cmd, args, newServeDeps())
}

func runServeWithDeps(cmd *cobra.Command, args []string, deps *serveDeps) error {
	if err := requireExplicitConfigFile(cmd, cfgFile); err != nil {
		return fmt.Errorf("config preflight: %w", err)
	}

	cfg, err := deps.loadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	if err := applyFlagOverrides(cmd, cfg); err != nil {
		return fmt.Errorf("apply flag overrides: %w", err)
	}

	logger, logOutputCloser, err := deps.newLogger(cfg.Log.Level, cfg.Log.Format, cfg.Log.Output)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if logOutputCloser == nil {
			return
		}
		if closeErr := logOutputCloser.Close(); closeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to close log output: %v\n", closeErr)
		}
	}()

	var auditLogger *logging.AuditLogger
	var auditLogOutputCloser io.Closer
	if cfg.Log.Audit.Enabled {
		auditLogger, auditLogOutputCloser, err = deps.newAuditLogger(cfg.Log.Audit.Format, cfg.Log.Audit.Output)
		if err != nil {
			return fmt.Errorf("audit logger: %w", err)
		}
		defer func() {
			if auditLogOutputCloser == nil {
				return
			}
			if closeErr := auditLogOutputCloser.Close(); closeErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to close audit log output: %v\n", closeErr)
			}
		}()
	}

	// Tecnativa compatibility mode expands legacy env vars like CONTAINERS=1
	// into explicit allow/deny rules before normal validation and compilation.
	compatActive := config.ApplyCompat(cfg, logger)

	rules, err := deps.validateRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}
	if err := deps.verifyUpstreamReachable(cfg.Upstream.Socket, logger); err != nil {
		return err
	}

	// Bundle verification, when configured, runs BEFORE the proxy starts
	// taking traffic. A startup that cannot verify the signature is fatal:
	// sockguard would otherwise be serving rules an attacker may have
	// tampered with on disk. The verifier itself is reload-immutable
	// (trust material is in [[reload-immutable-fields]]) so the same
	// instance is reused for SIGHUP/fsnotify reloads.
	bundleVerifier, err := deps.buildBundleVerifier(cfg.PolicyBundle)
	if err != nil {
		return fmt.Errorf("policy bundle verifier: %w", err)
	}
	bundleResult, err := verifyPolicyBundleAtStartup(cfg, cfgFile, deps, bundleVerifier, logger)
	if err != nil {
		return fmt.Errorf("policy bundle: %w", err)
	}

	// Versioner publishes the initial generation BEFORE the chain is built so
	// the admin policy-version endpoint and the sockguard_policy_version
	// gauge are populated as soon as the server starts taking traffic.
	versioner := admin.NewPolicyVersioner()
	initialSnapshot := admin.PolicySnapshot{
		LoadedAt:     deps.now(),
		Rules:        len(rules),
		Profiles:     len(cfg.Clients.Profiles),
		CompatActive: compatActive,
		Source:       "startup",
		ConfigSHA256: policyConfigHash(cfg),
	}
	if bundleResult != nil {
		initialSnapshot.BundleSource = filepath.Base(cfg.PolicyBundle.SignaturePath)
		initialSnapshot.BundleSigner = bundleResult.Signer
		initialSnapshot.BundleDigest = bundleResult.DigestHex
	}
	initialVersion := versioner.Update(initialSnapshot)

	runtime := newServeRuntime(cfg, logger, deps)
	runtime.metrics.SetPolicyVersion(initialVersion)
	handler, chainTeardown := buildServeHandlerChainWithRuntime(cfg, logger, auditLogger, rules, deps, runtime, versioner)
	swappable := reload.NewSwappableHandler(handler)
	coordinator := newReloadCoordinator(cfg, cfgFile, swappable, chainTeardown, logger, auditLogger, deps, runtime, versioner, bundleVerifier)
	defer coordinator.stop()

	listener, err := deps.createServeListener(cfg)
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	defer func() {
		// http.Server.Shutdown closes the listener as part of its
		// normal teardown, so by the time this defer runs the FD is
		// usually already gone and Close returns net.ErrClosed. That
		// is the healthy shutdown path — don't surface it as a WARN.
		closeErr := listener.Close()
		if closeErr == nil || errors.Is(closeErr, net.ErrClosed) {
			return
		}
		logger.Warn("failed to close listener", "error", closeErr)
	}()

	server := newHTTPServer(swappable)
	listen := listenerAddr(cfg)
	warnOnInsecureRemoteTCPBind(logger, cfg)
	banner.Render(cmd.ErrOrStderr(), banner.Info{
		Listen:    listen,
		Upstream:  cfg.Upstream.Socket,
		Rules:     len(cfg.Rules),
		LogFormat: cfg.Log.Format,
		LogLevel:  cfg.Log.Level,
		AccessLog: cfg.Log.AccessLog,
	})
	logger.Info("sockguard started",
		"version", version.Version,
		"listen", listen,
		"upstream", cfg.Upstream.Socket,
		"rules", len(cfg.Rules),
		"log_level", cfg.Log.Level,
	)

	errCh := make(chan error, 1)
	stopWatchdog := runtime.startWatchdog(context.Background(), cfg)
	defer stopWatchdog()
	go deps.startServing(server, listener, errCh)

	adminServer, adminErrCh, stopAdmin, err := startAdminServer(cfg, logger, auditLogger, versioner, deps)
	if err != nil {
		return err
	}
	defer stopAdmin()

	stopReload := func() {}
	if cfg.Reload.Enabled && cfgFile != "" {
		debounce := time.Duration(cfg.Reload.DebounceMs) * time.Millisecond
		if cfg.Reload.DebounceMs == 0 {
			debounce = reload.DefaultDebounce
		}
		pollInterval := time.Duration(cfg.Reload.PollIntervalMs) * time.Millisecond
		var startErr error
		stopReload, startErr = startReloader(context.Background(), cfgFile, debounce, pollInterval, coordinator, logger)
		if startErr != nil {
			logger.Error("config hot-reload disabled: failed to start watcher",
				"error", startErr,
				"path", cfgFile,
			)
			stopReload = func() {}
		}
	}
	defer stopReload()

	sigCh := make(chan os.Signal, 1)
	deps.notifySignals(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
	case err := <-adminErrCh:
		// An admin Serve() return is always fatal: the operator enabled
		// admin.listen specifically so they could rely on the admin
		// endpoints, so a silent admin-only outage would be worse than
		// taking the whole proxy down and surfacing the cause.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("admin server error: %w", err)
		}
	}
	stopWatchdog()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.shutdownGracePeriod)
	defer cancel()

	if adminServer != nil {
		if err := deps.shutdownServer(adminServer, shutdownCtx); err != nil {
			logger.Error("admin shutdown error", "error", err)
		}
	}
	if err := deps.shutdownServer(server, shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	if cfg.Listen.Socket != "" {
		if err := deps.removePath(cfg.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "socket", cfg.Listen.Socket, "error", err)
		}
	}
	if cfg.Admin.Enabled && cfg.Admin.Listen.Socket != "" {
		if err := deps.removePath(cfg.Admin.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove admin socket error", "socket", cfg.Admin.Listen.Socket, "error", err)
		}
	}
	logger.Info("sockguard stopped")
	return nil
}

// startAdminServer brings up the dedicated admin http.Server when
// admin.listen is configured. Returns the server (so the caller can
// Shutdown it), an error channel that yields the Serve return value, and
// a stop function the caller must defer to close the admin listener.
//
// When admin.listen is unconfigured the function is a no-op: it returns
// (nil, a permanently-blocked channel, no-op stop, nil) so the caller's
// select still has an entry to read from without having to special-case
// the unconfigured path.
//
// An adminErrCh receive of a non-nil error other than http.ErrServerClosed
// is a fatal condition the caller surfaces as a process-exit error — see
// the comment in runServeWithDeps.
func startAdminServer(
	cfg *config.Config,
	logger *slog.Logger,
	auditLogger *logging.AuditLogger,
	versioner *admin.PolicyVersioner,
	deps *serveDeps,
) (*http.Server, <-chan error, func(), error) {
	if !cfg.Admin.Enabled || !cfg.Admin.Listen.Configured() {
		// A nil-returning channel would block forever in select; that is
		// exactly what we want when there's no admin server to watch.
		return nil, make(chan error), func() {}, nil
	}

	adminListener, err := deps.createAdminListener(cfg)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("admin listener: %w", err)
	}

	adminHandler := buildAdminHandlerChain(cfg, logger, auditLogger, versioner)
	adminServer := newAdminHTTPServer(adminHandler)
	adminErrCh := make(chan error, 1)

	go deps.startServing(adminServer, adminListener, adminErrCh)

	logger.Info("admin listener started",
		"listen", adminListenerAddr(cfg),
		"validate_path", cfg.Admin.Path,
		"policy_version_path", cfg.Admin.PolicyVersionPath,
	)

	stop := func() {
		closeErr := adminListener.Close()
		if closeErr == nil || errors.Is(closeErr, net.ErrClosed) {
			return
		}
		logger.Warn("failed to close admin listener", "error", closeErr)
	}
	return adminServer, adminErrCh, stop, nil
}

func buildServeHandlerWithRuntime(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, runtime *serveRuntime) http.Handler {
	handler, _ := buildServeHandlerChainWithRuntime(cfg, logger, auditLogger, rules, deps, runtime, nil)
	return handler
}

// buildServeHandlerChainWithRuntime is the production / reload entry point:
// it returns both the composed http.Handler and a teardown closure that stops
// every chain-scoped goroutine (the rate-limit sampler and per-profile
// Limiter eviction loops). Callers must invoke the returned teardown when
// the handler is replaced (hot reload) or when the server shuts down,
// otherwise the rate-limit goroutines tied to the previous chain leak.
//
// The versioner is process-scoped (its pointer is captured into the admin
// policy-version handler), so reloads pass the SAME versioner used at
// startup — the snapshot it returns is whatever the reload coordinator
// last published. Tests that don't care about the policy-version endpoint
// pass nil; in that case the layer is skipped.
//
// Tests that don't care about teardown should continue calling
// buildServeHandler / buildServeHandlerWithRuntime which discard it — the
// goroutines die with the test process anyway.
func buildServeHandlerChainWithRuntime(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, runtime *serveRuntime, versioner *admin.PolicyVersioner) (http.Handler, func()) {
	clientProfiles, err := buildServeClientProfiles(cfg)
	if err != nil {
		logger.Error("invalid client profile config", "error", err)
		return invalidClientProfileHandler(), func() {}
	}

	handler := newServeUpstreamHandler(cfg, logger)
	layers, teardown := buildServeHandlerLayersWithRuntime(cfg, logger, auditLogger, rules, deps, clientProfiles, runtime, versioner)
	for _, layer := range layers {
		handler = layer.with(handler)
	}
	return handler, teardown
}

// serveRuntime holds process-scoped objects whose lifetime spans the whole
// run: the metrics registry and the upstream-health monitor. Both survive
// hot reloads — they are tied to immutable config fields, so a reload that
// would change them is rejected by the immutable-field gate before any
// rebuild happens. Chain-scoped goroutines (rate-limit sampler, per-profile
// Limiter eviction) are tracked separately by reloadCoordinator.
type serveRuntime struct {
	metrics *metrics.Registry
	health  *health.Monitor
}

func newServeRuntime(cfg *config.Config, logger *slog.Logger, deps *serveDeps) *serveRuntime {
	runtime := &serveRuntime{}
	if cfg.Metrics.Enabled {
		runtime.metrics = metrics.NewRegistry()
	}
	if cfg.Health.Enabled || cfg.Health.Watchdog.Enabled {
		runtime.health = health.NewMonitor(cfg.Upstream.Socket, deps.now(), logger)
	}
	return runtime
}

func (r *serveRuntime) startWatchdog(ctx context.Context, cfg *config.Config) func() {
	if r == nil || r.health == nil || !cfg.Health.Watchdog.Enabled {
		return func() {}
	}
	interval, err := time.ParseDuration(cfg.Health.Watchdog.Interval)
	if err != nil || interval <= 0 {
		return func() {}
	}

	watchdogCtx, cancel := context.WithCancel(ctx)
	r.health.StartWatchdog(watchdogCtx, interval, func(state health.WatchdogState) {
		if r.metrics == nil {
			return
		}
		r.metrics.ObserveUpstreamWatchdog(state.Up)
		r.metrics.SetUpstreamSocketState(state.Up)
	})
	return cancel
}

type serveHandlerLayer struct {
	name string
	with func(http.Handler) http.Handler
}

func invalidClientProfileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.SetDeniedWithCode(w, r, "client_profile_config_invalid", "client profile config invalid", filter.NormalizePath)
		_ = httpjson.Write(w, http.StatusInternalServerError, httpjson.ErrorResponse{Message: "client profile config invalid"})
	})
}

func buildServeClientProfiles(cfg *config.Config) (map[string]filter.Policy, error) {
	clientProfiles, err := compileClientProfiles(cfg)
	if err != nil {
		return nil, err
	}
	for name, profile := range clientProfiles {
		exec := profile.Exec
		exec.InspectStart = filter.NewDockerExecInspector(cfg.Upstream.Socket)
		profile.Exec = exec
		clientProfiles[name] = profile
	}
	return clientProfiles, nil
}

func newServeUpstreamHandler(cfg *config.Config, logger *slog.Logger) http.Handler {
	return proxy.NewWithOptions(cfg.Upstream.Socket, logger, proxy.Options{
		ModifyResponse: responsefilter.New(serveResponseFilterOptions(cfg)).ModifyResponse,
	})
}

func buildServeHandlerLayersWithRuntime(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, clientProfiles map[string]filter.Policy, runtime *serveRuntime, versioner *admin.PolicyVersioner) ([]serveHandlerLayer, func()) {
	layers := []serveHandlerLayer{
		namedServeHandlerLayer("withHijack", withHijack(cfg, logger)),
		namedServeHandlerLayer("withOwnership", withOwnership(cfg, logger)),
		namedServeHandlerLayer("withVisibility", withVisibility(cfg, logger)),
		namedServeHandlerLayer("withFilter", withFilter(cfg, logger, rules, clientProfiles)),
	}

	// Admin endpoints sit inside filter (so the filter never sees admin paths)
	// but outside rate-limit and clientacl (so CIDR allowlists and per-profile
	// limits still apply to /admin/* callers — they are not exempt from abuse
	// controls). Layers earlier in this slice are wrapped by layers added
	// later, so an admin layer appended here runs AFTER ratelimit / clientacl
	// in the request flow but BEFORE filter.
	//
	// The policy-version endpoint is appended before the validate endpoint so
	// a GET to /admin/policy/version is matched first; method-mismatched
	// requests still fall through to the next admin interceptor (which sees
	// a different path), and ultimately to filter where unrelated traffic
	// continues normally.
	//
	// When admin.listen is configured the admin endpoints move to a dedicated
	// http.Server (see startAdminServer); the main chain must NOT also mount
	// them, otherwise the same path resolves on both listeners and operators
	// lose the isolation they explicitly opted in to.
	if cfg.Admin.Enabled && !cfg.Admin.Listen.Configured() {
		if versioner != nil {
			layers = append(layers, namedServeHandlerLayer("withPolicyVersionEndpoint", withPolicyVersionEndpoint(cfg, logger, versioner)))
		}
		layers = append(layers, namedServeHandlerLayer("withAdminEndpoint", withAdminEndpoint(cfg, logger)))
	}

	// Rate limiting and concurrency caps sit after client identity is resolved
	// (clientacl) but before rule evaluation (filter), so a request denied by
	// the filter still consumes its rate-limit quota — rule-probing cannot
	// happen at line rate. The teardown closure halts the sampler + Limiter
	// eviction goroutines bound to this chain — callers must invoke it when
	// the chain is replaced (hot reload) or torn down at shutdown.
	teardown := func() {}
	if rlMiddleware, stop := buildRateLimitMiddleware(cfg, logger, runtime); rlMiddleware != nil {
		teardown = stop
		layers = append(layers, namedServeHandlerLayer("withRateLimit", rlMiddleware))
	}

	if cfg.Health.Enabled {
		layers = append(layers, namedServeHandlerLayer("withHealth", withHealth(cfg, logger, deps, runtime)))
	}
	if runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetricsEndpoint", withMetricsEndpoint(cfg, runtime.metrics)))
	}
	layers = append(layers,
		namedServeHandlerLayer("withClientACL", withClientACL(cfg, logger)),
	)
	if runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetrics", withMetrics(runtime.metrics)))
	}
	layers = append(layers,
		namedServeHandlerLayer("withTraceContext", withTraceContext()),
		namedServeHandlerLayer("withRequestID", withRequestID()),
	)
	if cfg.Log.Audit.Enabled && auditLogger != nil {
		layers = append(layers, namedServeHandlerLayer("withAuditLog", withAuditLog(auditLogger, cfg)))
	}
	if cfg.Log.AccessLog {
		layers = append(layers, namedServeHandlerLayer("withAccessLog", withAccessLog(logger)))
	}
	return layers, teardown
}

// buildRateLimitMiddleware constructs the per-profile rate-limit+concurrency
// middleware and its audit sampler. Returns (nil, nil) when no profile has
// limits and no global concurrency cap is configured. The second return value
// is a stop function that halts the sampler eviction goroutine and every
// per-profile Limiter eviction goroutine; callers must call it on shutdown.
func buildRateLimitMiddleware(cfg *config.Config, logger *slog.Logger, runtime *serveRuntime) (func(http.Handler) http.Handler, func()) {
	profiles := make(map[string]ratelimit.ProfileOptions)
	for _, profile := range cfg.Clients.Profiles {
		opts := configLimitsToRateLimitOptions(profile.Limits)
		if opts.Rate != nil || opts.Concurrency != nil || opts.Priority != ratelimit.PriorityNormal {
			profiles[profile.Name] = opts
		}
	}

	var globalConc *ratelimit.GlobalConcurrencyOptions
	if cfg.Clients.GlobalConcurrency != nil && cfg.Clients.GlobalConcurrency.MaxInflight > 0 {
		globalConc = &ratelimit.GlobalConcurrencyOptions{
			MaxInflight: cfg.Clients.GlobalConcurrency.MaxInflight,
		}
	}

	if len(profiles) == 0 && globalConc == nil {
		return nil, nil
	}

	warnAssignedProfilesWithoutLimits(cfg, profiles, logger)

	sampler, stopSampler := ratelimit.NewAuditSampler()
	mw, stopLimiters := ratelimit.Middleware(logger, runtime.metrics, sampler, ratelimit.MiddlewareOptions{
		Profiles:          profiles,
		ResolveProfile:    clientacl.RequestProfile,
		GlobalConcurrency: globalConc,
	})
	stop := func() {
		stopLimiters()
		stopSampler()
	}
	return mw, stop
}

// warnAssignedProfilesWithoutLimits flags profiles that operators bound to a
// caller identity (mTLS, source IP, unix peer, default) but did not give any
// rate or concurrency configuration. Once any profile has limits configured,
// an unlimited assigned profile is almost always a config oversight, not an
// intentional carve-out — surface it at startup so operators notice before
// the proxy ships traffic.
func warnAssignedProfilesWithoutLimits(cfg *config.Config, limitedProfiles map[string]ratelimit.ProfileOptions, logger *slog.Logger) {
	assigned := make(map[string]struct{})
	if cfg.Clients.DefaultProfile != "" {
		assigned[cfg.Clients.DefaultProfile] = struct{}{}
	}
	for _, a := range cfg.Clients.SourceIPProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.ClientCertificateProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for _, a := range cfg.Clients.UnixPeerProfiles {
		if a.Profile != "" {
			assigned[a.Profile] = struct{}{}
		}
	}
	for name := range assigned {
		if _, ok := limitedProfiles[name]; ok {
			continue
		}
		logger.Warn(
			"client profile is assigned to callers but has no rate or concurrency limits configured",
			slog.String("profile", name),
			slog.String("recommendation",
				"add clients.profiles[...].limits.rate, .concurrency, or .priority — or remove the assignment if unlimited access is intended"),
		)
	}
}

// configLimitsToRateLimitOptions converts a per-profile LimitsConfig to the
// ratelimit package's ProfileOptions. Returns zero-valued options (both nil)
// when no limits are configured.
func configLimitsToRateLimitOptions(cfg config.LimitsConfig) ratelimit.ProfileOptions {
	var opts ratelimit.ProfileOptions
	if cfg.Priority != "" {
		// Unknown values were rejected by the validator; ignore the ok flag
		// here so a config that slipped past validation falls back to normal
		// rather than panicking the proxy at runtime.
		opts.Priority, _ = ratelimit.ParsePriority(cfg.Priority)
	}
	if cfg.Rate != nil {
		burst := cfg.Rate.Burst
		if burst == 0 {
			burst = cfg.Rate.TokensPerSecond
		}
		var costs []ratelimit.EndpointCost
		if len(cfg.Rate.EndpointCosts) > 0 {
			costs = make([]ratelimit.EndpointCost, 0, len(cfg.Rate.EndpointCosts))
			for _, ec := range cfg.Rate.EndpointCosts {
				costs = append(costs, ratelimit.EndpointCost{
					PathGlob: ec.Path,
					Methods:  ec.Methods,
					Cost:     ec.Cost,
				})
			}
		}
		opts.Rate = &ratelimit.RateOptions{
			TokensPerSecond: cfg.Rate.TokensPerSecond,
			Burst:           burst,
			EndpointCosts:   costs,
		}
	}
	if cfg.Concurrency != nil {
		opts.Concurrency = &ratelimit.ConcurrencyOptions{
			MaxInflight: cfg.Concurrency.MaxInflight,
		}
	}
	return opts
}

func namedServeHandlerLayer(name string, with func(http.Handler) http.Handler) serveHandlerLayer {
	return serveHandlerLayer{name: name, with: with}
}

func withHijack(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Hijack handler: intercepts attach/exec endpoints for native bidirectional
		// streaming with optimized buffers and TCP half-close signaling.
		return proxy.HijackHandler(cfg.Upstream.Socket, logger, next)
	}
}

func withOwnership(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return ownership.Middleware(cfg.Upstream.Socket, logger, ownership.Options{
		Owner:              cfg.Ownership.Owner,
		LabelKey:           cfg.Ownership.LabelKey,
		AllowUnownedImages: cfg.Ownership.AllowUnownedImages,
	})
}

func withVisibility(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return visibility.Middleware(cfg.Upstream.Socket, logger, visibility.Options{
		VisibleResourceLabels: cfg.Response.VisibleResourceLabels,
		NamePatterns:          cfg.Response.NamePatterns,
		ImagePatterns:         cfg.Response.ImagePatterns,
		Profiles:              clientVisibilityProfiles(cfg.Clients.Profiles),
		ResolveProfile:        clientacl.RequestProfile,
	})
}

func withFilter(cfg *config.Config, logger *slog.Logger, rules []*filter.CompiledRule, clientProfiles map[string]filter.Policy) func(http.Handler) http.Handler {
	return filter.MiddlewareWithOptions(rules, logger, serveFilterOptions(cfg, clientProfiles))
}

func withHealth(cfg *config.Config, logger *slog.Logger, deps *serveDeps, runtime *serveRuntime) func(http.Handler) http.Handler {
	monitor := health.NewMonitor(cfg.Upstream.Socket, deps.now(), logger)
	if runtime.health != nil {
		monitor = runtime.health
	}
	healthHandler := monitor.Handler()
	return func(next http.Handler) http.Handler {
		return healthInterceptor(cfg.Health.Path, healthHandler, next)
	}
}

func withMetricsEndpoint(cfg *config.Config, registry *metrics.Registry) func(http.Handler) http.Handler {
	metricsHandler := registry.Handler()
	return func(next http.Handler) http.Handler {
		return metricsInterceptor(cfg.Metrics.Path, metricsHandler, next)
	}
}

func withMetrics(registry *metrics.Registry) func(http.Handler) http.Handler {
	return registry.Middleware()
}

func withClientACL(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return clientacl.Middleware(cfg.Upstream.Socket, logger, serveClientACLOptions(cfg))
}

func withAdminEndpoint(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return admin.NewValidateInterceptor(admin.Options{
		Path:         cfg.Admin.Path,
		MaxBodyBytes: cfg.Admin.MaxBodyBytes,
		Validate:     buildAdminValidator(logger),
		Logger:       logger,
	})
}

// withPolicyVersionEndpoint mounts the read-only GET admin.policy_version_path
// handler. The versioner pointer is captured by reference so updates the
// reload coordinator publishes after a successful swap are observable to the
// next caller without re-wrapping the chain.
func withPolicyVersionEndpoint(cfg *config.Config, logger *slog.Logger, versioner *admin.PolicyVersioner) func(http.Handler) http.Handler {
	return admin.NewPolicyVersionInterceptor(admin.PolicyVersionOptions{
		Path:   cfg.Admin.PolicyVersionPath,
		Source: versioner.Snapshot,
		Logger: logger,
	})
}

// verifyPolicyBundleAtStartup runs the bundle verifier against the raw
// YAML bytes of the on-disk config file. Returns (nil, nil) when
// policy_bundle is disabled so the caller can skip stamping bundle
// metadata onto the initial snapshot. Otherwise returns (*VerifyResult,
// nil) on success or (nil, err) on any failure — startup must abort in
// that case because the trust gate is the whole point of the feature.
func verifyPolicyBundleAtStartup(
	cfg *config.Config,
	cfgFile string,
	deps *serveDeps,
	verifier policybundle.Verifier,
	logger *slog.Logger,
) (*policybundle.VerifyResult, error) {
	if !cfg.PolicyBundle.Enabled {
		return nil, nil
	}
	if cfgFile == "" {
		return nil, errors.New("policy_bundle.enabled=true but no --config file was supplied; sockguard cannot verify an in-memory default")
	}
	if cfg.PolicyBundle.SignaturePath == "" {
		return nil, errors.New("policy_bundle.signature_path is required when policy_bundle.enabled=true")
	}

	yamlBytes, err := deps.readConfigBytes(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("read config YAML for verification: %w", err)
	}
	entity, err := deps.loadBundleEntity(cfg.PolicyBundle.SignaturePath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), bundleVerifyDeadline(cfg.PolicyBundle))
	defer cancel()
	result, err := verifier.Verify(ctx, yamlBytes, entity)
	if err != nil {
		return nil, err
	}
	logger.Info("policy bundle verified",
		"signature_path", cfg.PolicyBundle.SignaturePath,
		"signer", result.Signer,
		"digest", result.DigestHex,
		"elapsed_ms", result.ElapsedMS,
	)
	return &result, nil
}

// bundleVerifyDeadline returns the wall-clock budget for one verification
// attempt. The policybundle.BuildConfig parser is the authoritative source
// for the timeout but this helper avoids a second parse at the call site
// and degrades to the package default if the value is unset.
func bundleVerifyDeadline(pb config.PolicyBundleConfig) time.Duration {
	if pb.VerifyTimeout == "" {
		return policybundle.VerifyTimeout
	}
	d, err := time.ParseDuration(pb.VerifyTimeout)
	if err != nil || d <= 0 {
		return policybundle.VerifyTimeout
	}
	return d
}

// policyConfigHash returns a hex SHA-256 of the JSON encoding of the
// effective config. JSON marshaling of our config structs is deterministic
// because field order is fixed and no map[string]any leaks into the shape;
// that makes the hash a stable fingerprint operators can compare across
// scrapes to confirm two snapshots really represent the same config. An
// encoding failure is non-fatal — we return the empty string so the rest
// of the snapshot still publishes.
func policyConfigHash(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// buildAdminValidator returns the parse+validate+compile callback wired into
// the admin /admin/validate endpoint. It mirrors the offline `sockguard
// validate` command's pipeline (config.LoadBytes → ApplyCompat →
// validateAndCompileRules → compileClientProfiles) so an operator's CI gate
// and the running proxy reach the same verdict for the same YAML.
//
// ApplyCompat uses a discard logger here because compat-expansion log noise
// belongs to the proxy's own startup, not to a candidate-config validation
// request. The returned response still carries CompatActive so callers see
// whether legacy env aliases would have fired.
func buildAdminValidator(parentLogger *slog.Logger) admin.Validator {
	return func(yamlBody []byte) admin.ValidateResponse {
		cfg, err := config.LoadBytes(yamlBody)
		if err != nil {
			return admin.ValidateResponse{OK: false, Errors: []string{"parse: " + err.Error()}}
		}

		discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
		compatActive := config.ApplyCompat(cfg, discardLogger)

		compiled, compileErr := validateAndCompileRules(cfg)
		if compileErr != nil {
			return admin.ValidateResponse{
				OK:           false,
				Errors:       splitValidationError(compileErr),
				CompatActive: compatActive,
			}
		}

		return admin.ValidateResponse{
			OK:           true,
			Rules:        len(compiled),
			Profiles:     len(cfg.Clients.Profiles),
			CompatActive: compatActive,
		}
	}
}

// splitValidationError unwraps a *config.ValidationError into its
// per-issue lines so the admin endpoint can return a structured list
// instead of one wrapped string. Non-validation errors (e.g. rule-compile
// failures from filter.CompileRule) fall through as a single-element slice.
func splitValidationError(err error) []string {
	var vErr *config.ValidationError
	if errors.As(err, &vErr) {
		out := make([]string, 0, len(vErr.Errors))
		out = append(out, vErr.Errors...)
		return out
	}
	return []string{err.Error()}
}

func withRequestID() func(http.Handler) http.Handler {
	return logging.RequestIDMiddleware()
}

func withTraceContext() func(http.Handler) http.Handler {
	return logging.TraceContextMiddleware()
}

func withAccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return logging.AccessLogMiddleware(logger)
}

func withAuditLog(auditLogger *logging.AuditLogger, cfg *config.Config) func(http.Handler) http.Handler {
	return logging.AuditLogMiddleware(auditLogger, logging.AuditOptions{
		Listener:          auditListener(cfg),
		OwnershipOwner:    cfg.Ownership.Owner,
		OwnershipLabelKey: cfg.Ownership.LabelKey,
	})
}

func auditListener(cfg *config.Config) string {
	if cfg != nil && cfg.Listen.Socket != "" {
		return "unix"
	}
	return "tcp"
}

func serveResponseFilterOptions(cfg *config.Config) responsefilter.Options {
	return responsefilter.Options{
		RedactContainerEnv:    cfg.Response.RedactContainerEnv,
		RedactMountPaths:      cfg.Response.RedactMountPaths,
		RedactNetworkTopology: cfg.Response.RedactNetworkTopology,
		RedactSensitiveData:   cfg.Response.RedactSensitiveData,
	}
}

func serveFilterOptions(cfg *config.Config, clientProfiles map[string]filter.Policy) filter.Options {
	return filter.Options{
		PolicyConfig:   servePolicyConfig(cfg),
		Profiles:       clientProfiles,
		ResolveProfile: clientacl.RequestProfile,
	}
}

func servePolicyConfig(cfg *config.Config) filter.PolicyConfig {
	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.ParseDenyResponseVerbosity(cfg.Response.DenyVerbosity)
	policy.Exec.InspectStart = filter.NewDockerExecInspector(cfg.Upstream.Socket)
	return policy
}

func serveClientACLOptions(cfg *config.Config) clientacl.Options {
	return clientacl.Options{
		AllowedCIDRs: cfg.Clients.AllowedCIDRs,
		ContainerLabels: clientacl.ContainerLabelOptions{
			Enabled:     cfg.Clients.ContainerLabels.Enabled,
			LabelPrefix: cfg.Clients.ContainerLabels.LabelPrefix,
		},
		Profiles: clientacl.ProfileOptions{
			DefaultProfile: cfg.Clients.DefaultProfile,
			SourceIPs:      clientSourceIPProfiles(cfg.Clients.SourceIPProfiles),
			ClientCertificates: clientCertificateProfiles(
				cfg.Clients.ClientCertificateProfiles,
			),
			UnixPeers: clientUnixPeerProfiles(cfg.Clients.UnixPeerProfiles),
		},
		ProfileModes: clientProfileModes(cfg.Clients.Profiles),
	}
}

// clientProfileModes flattens cfg.Clients.Profiles into the
// (profileName -> rolloutMode) map clientacl uses to stamp meta.RolloutMode
// when a profile is selected. Modes that fail to parse fall back to enforce;
// the config validator already rejects unknown values at startup, so the
// fallback is a defense-in-depth no-op under normal operation.
func clientProfileModes(profiles []config.ClientProfileConfig) map[string]string {
	if len(profiles) == 0 {
		return nil
	}
	modes := make(map[string]string, len(profiles))
	for _, p := range profiles {
		mode, _ := config.ParseRolloutMode(p.Mode)
		modes[p.Name] = mode.String()
	}
	return modes
}

func clientSourceIPProfiles(values []config.ClientSourceIPProfileAssignmentConfig) []clientacl.SourceIPProfileAssignment {
	assignments := make([]clientacl.SourceIPProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.SourceIPProfileAssignment{
			Profile: value.Profile,
			CIDRs:   value.CIDRs,
		})
	}
	return assignments
}

func clientCertificateProfiles(values []config.ClientCertificateProfileAssignmentConfig) []clientacl.ClientCertificateProfileAssignment {
	assignments := make([]clientacl.ClientCertificateProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.ClientCertificateProfileAssignment{
			Profile:             value.Profile,
			CommonNames:         value.CommonNames,
			DNSNames:            value.DNSNames,
			IPAddresses:         value.IPAddresses,
			URISANs:             value.URISANs,
			SPIFFEIDs:           value.SPIFFEIDs,
			PublicKeySHA256Pins: value.PublicKeySHA256Pins,
		})
	}
	return assignments
}

func clientUnixPeerProfiles(values []config.ClientUnixPeerProfileAssignmentConfig) []clientacl.UnixPeerProfileAssignment {
	assignments := make([]clientacl.UnixPeerProfileAssignment, 0, len(values))
	for _, value := range values {
		assignments = append(assignments, clientacl.UnixPeerProfileAssignment{
			Profile: value.Profile,
			UIDs:    value.UIDs,
			GIDs:    value.GIDs,
			PIDs:    value.PIDs,
		})
	}
	return assignments
}

func clientVisibilityProfiles(values []config.ClientProfileConfig) map[string]visibility.Policy {
	profiles := make(map[string]visibility.Policy, len(values))
	for _, value := range values {
		profiles[value.Name] = visibility.Policy{
			VisibleResourceLabels: value.Response.VisibleResourceLabels,
			NamePatterns:          value.Response.NamePatterns,
			ImagePatterns:         value.Response.ImagePatterns,
		}
	}
	return profiles
}

// buildAdminHandlerChain composes the http.Handler used by the dedicated
// admin listener (admin.listen configured). It mounts the validate and
// policy-version interceptors over a 404 terminator and wraps the result in
// the observability layers (request-id, trace context, optional audit log,
// optional access log) so the admin surface still emits the same kind of
// telemetry as the main listener.
//
// Note: rate-limit, client ACL, ownership, visibility, hijack, and the
// Docker-API filter are intentionally NOT applied — the admin listener is a
// distinct trust boundary whose access control is the bind target plus
// admin.listen.tls, not the per-profile policy that gates Docker-API
// traffic on the main listener.
func buildAdminHandlerChain(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, versioner *admin.PolicyVersioner) http.Handler {
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any request on the dedicated admin listener that did not match an
		// admin path lands here. We surface it as a 404 with the same
		// SetDeniedWithCode call used elsewhere so the access/audit logs
		// carry a consistent reason_code.
		logging.SetDeniedWithCode(w, r, "admin_unknown_path", "unknown admin path", nil)
		_ = httpjson.Write(w, http.StatusNotFound, httpjson.ErrorResponse{Message: "not found"})
	})

	var h http.Handler = terminal
	h = withAdminEndpoint(cfg, logger)(h)
	if versioner != nil {
		h = withPolicyVersionEndpoint(cfg, logger, versioner)(h)
	}
	if cfg.Log.Audit.Enabled && auditLogger != nil {
		h = withAuditLog(auditLogger, cfg)(h)
	}
	h = withRequestID()(h)
	h = withTraceContext()(h)
	if cfg.Log.AccessLog {
		h = withAccessLog(logger)(h)
	}
	return h
}

// newAdminHTTPServer returns the http.Server for the dedicated admin
// listener. Unlike the main server it sets explicit Read/Write timeouts:
// admin endpoints never stream and never hijack, so a runaway client cannot
// be allowed to hold a goroutine open forever. The timeout has to be generous
// enough that the validator (which compiles regex/glob inputs and parses TLS
// material) still finishes on a contented box — 30s is comfortably above
// observed validation latencies.
func newAdminHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ConnContext:       clientacl.ConnContext,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// adminListenerAddr returns a human-readable address for the dedicated admin
// listener so logging can show operators where the admin endpoints are
// bound. Mirrors listenerAddr.
func adminListenerAddr(cfg *config.Config) string {
	if cfg.Admin.Listen.Socket != "" {
		return "unix:" + cfg.Admin.Listen.Socket
	}
	return "tcp://" + cfg.Admin.Listen.Address
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:     handler,
		ConnContext: clientacl.ConnContext,
		// Docker attach/logs/events can hold request/response bodies open for long periods.
		// A non-zero ReadTimeout breaks those streaming APIs, so we intentionally leave it disabled.
		// WriteTimeout stays disabled for the same reason: long-lived streamed responses and hijacked
		// upgrade sessions must not be cut off by a generic response-write deadline.
		// ReadHeaderTimeout still bounds header parsing time, which partially mitigates slowloris
		// attacks on TCP listeners without affecting long-lived upgraded/streaming requests.
		// IdleTimeout reaps keep-alive connections that go quiescent after a response completes;
		// it does not terminate active response bodies or hijacked upgrade streams.
		// MaxHeaderBytes is pinned to 1 MiB explicitly so the stdlib default does not become
		// a silent, unreviewed part of Sockguard's network hardening posture.
		ReadTimeout:       0,
		WriteTimeout:      0,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// applyFlagOverrides applies CLI flags that were explicitly set.
func applyFlagOverrides(cmd *cobra.Command, cfg *config.Config) error {
	return applyStringFlagOverrides(cmd, []stringFlagOverride{
		{
			name: "listen-socket",
			set: func(v string) {
				cfg.Listen.Socket = v
			},
		},
		{
			name: "upstream-socket",
			set: func(v string) {
				cfg.Upstream.Socket = v
			},
		},
		{
			name: "log-level",
			set: func(v string) {
				cfg.Log.Level = v
			},
		},
		{
			name: "log-format",
			set: func(v string) {
				cfg.Log.Format = v
			},
		},
		{
			name: "deny-response-verbosity",
			set: func(v string) {
				cfg.Response.DenyVerbosity = v
			},
		},
	})
}

type stringFlagOverride struct {
	name string
	set  func(string)
}

func applyStringFlagOverrides(cmd *cobra.Command, overrides []stringFlagOverride) error {
	for _, override := range overrides {
		if err := applyStringFlagOverride(cmd, override.name, override.set); err != nil {
			return err
		}
	}
	return nil
}

func applyStringFlagOverride(cmd *cobra.Command, name string, set func(string)) error {
	if !cmd.Flags().Changed(name) {
		return nil
	}

	v, err := cmd.Flags().GetString(name)
	if err != nil {
		return fmt.Errorf("get %s flag: %w", name, err)
	}
	set(v)
	return nil
}

// createListener creates a Unix socket or TCP listener based on config.
func socketCreateUmask(mode os.FileMode) int {
	return int(0o777 &^ mode.Perm())
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.EADDRINUSE)
}

// healthInterceptor short-circuits health check requests before they hit the filter.
//
// /health intentionally runs before the CIDR allowlist so external uptime
// probes (Kubernetes liveness, load-balancer health checks) can reach it
// without being added to clients.allowed_cidrs. Treat health as
// always-public. Operators who need authenticated health checks should disable
// health.enabled and use /metrics behind the listener's mTLS instead.
func healthInterceptor(path string, healthHandler http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == path {
			healthHandler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// metricsInterceptor short-circuits metrics scrape requests before they hit Docker API filtering.
func metricsInterceptor(path string, metricsHandler http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == path {
			metricsHandler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// listenerAddr returns a human-readable address for logging.
func listenerAddr(cfg *config.Config) string {
	if cfg.Listen.Socket != "" {
		return "unix:" + cfg.Listen.Socket
	}
	return "tcp://" + cfg.Listen.Address
}

func warnOnInsecureRemoteTCPBind(logger *slog.Logger, cfg *config.Config) {
	if cfg.Listen.Socket != "" || !cfg.Listen.InsecureAllowPlainTCP || cfg.Listen.TLS.Complete() || !config.IsNonLoopbackTCPAddress(cfg.Listen.Address) {
		return
	}

	logger.Warn("plaintext TCP listener is exposed beyond loopback",
		"listen", listenerAddr(cfg),
		"recommendation", "configure listen.tls for mTLS, bind 127.0.0.1:<port>, or use listen.socket",
	)
}
