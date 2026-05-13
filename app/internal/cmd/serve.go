package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/banner"
	"github.com/codeswhat/sockguard/internal/clientacl"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/metrics"
	"github.com/codeswhat/sockguard/internal/ownership"
	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/ratelimit"
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
	config.ApplyCompat(cfg, logger)

	rules, err := deps.validateRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}
	if err := deps.verifyUpstreamReachable(cfg.Upstream.Socket, logger); err != nil {
		return err
	}

	runtime := newServeRuntime(cfg, logger, deps)
	handler := buildServeHandlerWithRuntime(cfg, logger, auditLogger, rules, deps, runtime)
	if runtime.stopRateLimit != nil {
		defer runtime.stopRateLimit()
	}
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

	server := newHTTPServer(handler)
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

	sigCh := make(chan os.Signal, 1)
	deps.notifySignals(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
	}
	stopWatchdog()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.shutdownGracePeriod)
	defer cancel()

	if err := deps.shutdownServer(server, shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	if cfg.Listen.Socket != "" {
		if err := deps.removePath(cfg.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "socket", cfg.Listen.Socket, "error", err)
		}
	}
	logger.Info("sockguard stopped")
	return nil
}

func buildServeHandler(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps) http.Handler {
	return buildServeHandlerWithRuntime(cfg, logger, auditLogger, rules, deps, newServeRuntime(cfg, logger, deps))
}

func buildServeHandlerWithRuntime(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, runtime *serveRuntime) http.Handler {
	clientProfiles, err := buildServeClientProfiles(cfg)
	if err != nil {
		logger.Error("invalid client profile config", "error", err)
		return invalidClientProfileHandler()
	}

	handler := newServeUpstreamHandler(cfg, logger)
	for _, layer := range buildServeHandlerLayersWithRuntime(cfg, logger, auditLogger, rules, deps, clientProfiles, runtime) {
		handler = layer.with(handler)
	}
	return handler
}

type serveRuntime struct {
	metrics       *metrics.Registry
	health        *health.Monitor
	stopRateLimit func()
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

func buildServeHandlerLayers(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, clientProfiles map[string]filter.Policy) []serveHandlerLayer {
	return buildServeHandlerLayersWithRuntime(cfg, logger, auditLogger, rules, deps, clientProfiles, newServeRuntime(cfg, logger, deps))
}

func buildServeHandlerLayersWithRuntime(cfg *config.Config, logger *slog.Logger, auditLogger *logging.AuditLogger, rules []*filter.CompiledRule, deps *serveDeps, clientProfiles map[string]filter.Policy, runtime *serveRuntime) []serveHandlerLayer {
	layers := []serveHandlerLayer{
		namedServeHandlerLayer("withHijack", withHijack(cfg, logger)),
		namedServeHandlerLayer("withOwnership", withOwnership(cfg, logger)),
		namedServeHandlerLayer("withVisibility", withVisibility(cfg, logger)),
		namedServeHandlerLayer("withFilter", withFilter(cfg, logger, rules, clientProfiles)),
	}

	// Rate limiting and concurrency caps sit after client identity is resolved
	// (clientacl) but before rule evaluation (filter). The sampler stop
	// function is stored on the runtime so the caller can clean it up on
	// server shutdown.
	if rlMiddleware, stopSampler := buildRateLimitMiddleware(cfg, logger, runtime); rlMiddleware != nil {
		if runtime != nil {
			runtime.stopRateLimit = stopSampler
		}
		layers = append(layers, namedServeHandlerLayer("withRateLimit", rlMiddleware))
	}

	if cfg.Health.Enabled {
		layers = append(layers, namedServeHandlerLayer("withHealth", withHealth(cfg, logger, deps, runtime)))
	}
	if runtime != nil && runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetricsEndpoint", withMetricsEndpoint(cfg, runtime.metrics)))
	}
	layers = append(layers,
		namedServeHandlerLayer("withClientACL", withClientACL(cfg, logger)),
	)
	if runtime != nil && runtime.metrics != nil {
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
	return layers
}

// buildRateLimitMiddleware constructs the per-profile rate-limit+concurrency
// middleware and its audit sampler. Returns nil, nil if no profile has limits
// configured. The second return value is the stop function for the sampler's
// background goroutine; callers must call it on shutdown to prevent goroutine
// leaks in tests and graceful shutdowns.
//
// ratelimit.Middleware can technically return a compile error if an
// endpoint-cost path glob is malformed, but the config validator rejects
// those at startup. If one slips through, we log and skip the middleware
// rather than build a proxy with broken limits.
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

	var reg *metrics.Registry
	if runtime != nil {
		reg = runtime.metrics
	}

	sampler, stopSampler := ratelimit.NewAuditSampler()
	mw, err := ratelimit.Middleware(logger, reg, sampler, ratelimit.MiddlewareOptions{
		Profiles:          profiles,
		ResolveProfile:    clientacl.RequestProfile,
		GlobalConcurrency: globalConc,
	})
	if err != nil {
		logger.Error("rate-limit middleware compile failed; validator should have caught this",
			slog.String("error", err.Error()))
		stopSampler()
		return nil, nil
	}
	return mw, stopSampler
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
	if runtime != nil && runtime.health != nil {
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
	}
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
