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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/app/internal/admin"
	"github.com/codeswhat/sockguard/app/internal/banner"
	"github.com/codeswhat/sockguard/app/internal/buildkitproxy"
	"github.com/codeswhat/sockguard/app/internal/clientacl"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/health"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/inbound"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/metrics"
	"github.com/codeswhat/sockguard/app/internal/ownership"
	"github.com/codeswhat/sockguard/app/internal/policybundle"
	"github.com/codeswhat/sockguard/app/internal/proxy"
	"github.com/codeswhat/sockguard/app/internal/ratelimit"
	"github.com/codeswhat/sockguard/app/internal/reload"
	"github.com/codeswhat/sockguard/app/internal/responsefilter"
	"github.com/codeswhat/sockguard/app/internal/upstream"
	"github.com/codeswhat/sockguard/app/internal/version"
	"github.com/codeswhat/sockguard/app/internal/visibility"
)

const readHeaderTimeout = 5 * time.Second
const idleTimeout = 120 * time.Second
const maxHeaderBytes = 1 << 20

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the proxy server",
	Long: `Start the sockguard proxy, listening for Docker API requests and filtering them according to configured rules.

Configuration sources (highest precedence first):
  1. CLI flags
  2. SOCKGUARD_* env vars (e.g. SOCKGUARD_LISTEN_SOCKET, SOCKGUARD_LOG_LEVEL)
  3. Tecnativa-compat env vars (SOCKET_PATH, LOG_LEVEL) — accepted as aliases
     for backward compatibility; lower precedence than the SOCKGUARD_* form
  4. YAML config file (--config)
  5. Built-in defaults`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("listen-socket", "", "proxy socket path (overrides config)")
	serveCmd.Flags().String("upstream-socket", "", "Docker socket path (overrides config)")
	serveCmd.Flags().String("log-level", "", "log level (overrides config)")
	serveCmd.Flags().String("log-format", "", "log format (overrides config)")
	serveCmd.Flags().String("deny-verbosity", "", "deny response verbosity: verbose or minimal (overrides config)")
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

	// Startup diagnostics before policy verification and validation always go
	// to stderr. Opening a path requested by an unverified or invalid config
	// would let that config create or truncate arbitrary files before the
	// process rejects it.
	bootstrapLogger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))

	trustPath := policyBundleTrustConfigPath(cmd)
	var bundleVerifier policybundle.Verifier
	var bundleResult *policybundle.VerifyResult
	signedMode := trustPath != ""
	if !signedMode && cfg.PolicyBundle.Enabled {
		return errors.New("policy_bundle.enabled in the candidate config cannot authenticate itself; provide --policy-bundle-trust-config with out-of-band trust material")
	}
	if signedMode {
		if samePolicyConfigFile(deps, cfgFile, trustPath) {
			return errors.New("policy bundle trust config must be a different file from the signed candidate config")
		}
		pinnedTrust, loadErr := loadPolicyBundleTrustConfig(deps, trustPath)
		if loadErr != nil {
			return fmt.Errorf("policy bundle trust config: %w", loadErr)
		}
		pinPolicyBundleTrust(cfg, pinnedTrust)
		bundleVerifier, err = deps.buildBundleVerifier(pinnedTrust)
		if err != nil {
			return fmt.Errorf("policy bundle verifier: %w", err)
		}
		var signedCfg *config.Config
		bundleResult, signedCfg, err = verifyPolicyBundleAtStartup(cmd.Context(), cfg, cfgFile, deps, bundleVerifier, bootstrapLogger)
		if err != nil {
			return fmt.Errorf("policy bundle: %w", err)
		}
		if err := applyFlagOverrides(cmd, signedCfg); err != nil {
			return fmt.Errorf("apply flag overrides: %w", err)
		}
		cfg = signedCfg
	}

	// Tecnativa compatibility mode expands legacy env vars like CONTAINERS=1
	// into explicit allow/deny rules before normal validation and compilation.
	if signedMode {
		if vars := config.CompatEnvironmentVariables(); len(vars) > 0 {
			return fmt.Errorf("signed policy cannot be combined with rule-generating compatibility environment variables: %s", strings.Join(vars, ", "))
		}
	}
	compatActive := config.ApplyCompat(cfg, bootstrapLogger)

	rules, err := deps.validateRules(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
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
	warnIfDefaultProfileExcluded(cfg, logger)
	runtime, err := newServeRuntime(cfg, logger, deps)
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	if err := verifyUpstreamReachableForRuntime(cmd.Context(), deps, runtime, cfg, logger); err != nil {
		return err
	}

	// listenerStatusBoard (#149) tracks every configured listener's
	// lifecycle state for the /health response; wired into both monitors
	// before any listener binds so ListenersFunc is never nil once traffic
	// could possibly reach it.
	board := newListenerStatusBoard()
	if runtime.health != nil {
		runtime.health.ListenersFunc = board.snapshot
	}
	if runtime.readiness != nil {
		runtime.readiness.ListenersFunc = board.snapshot
	}

	// Versioner publishes the initial generation BEFORE the chain is built so
	// the admin policy-version endpoint and the sockguard_policy_version
	// gauge are populated as soon as the server starts taking traffic.
	versioner := admin.NewPolicyVersioner()
	initialVersion := versioner.Update(buildInitialPolicySnapshot(deps, cfg, rules, compatActive, bundleResult))

	runtime.metrics.SetPolicyVersion(initialVersion)
	handler, chainTeardown, limiterStateActive := buildServeHandlerChainWithRuntime(serveHandlerBuild{
		Cfg:         cfg,
		Logger:      logger,
		AuditLogger: auditLogger,
		Rules:       rules,
		Deps:        deps,
		Runtime:     runtime,
		Versioner:   versioner,
	})
	swappable := reload.NewSwappableHandler(handler)
	coordinator := newReloadCoordinator(reloadCoordinatorParams{
		RootCtx:                   cmd.Context(),
		Cfg:                       cfg,
		CfgFile:                   cfgFile,
		Swappable:                 swappable,
		InitialTeardown:           chainTeardown,
		InitialLimiterStateActive: limiterStateActive,
		Logger:                    logger,
		AuditLogger:               auditLogger,
		Deps:                      deps,
		Runtime:                   runtime,
		Versioner:                 versioner,
		BundleVerifier:            bundleVerifier,
		// Same overrides startup applied above, replayed on every reload
		// candidate. cmd's flags are parsed before RunE and never mutated
		// afterwards, so the reloader goroutine only reads frozen state.
		ApplyFlagOverrides: func(candidate *config.Config) error {
			return applyFlagOverrides(cmd, candidate)
		},
	})
	defer coordinator.stop()

	// Two-phase bind (#149): every effective main listener is bound here,
	// before anything starts serving. A bind failure on any one of them
	// closes every member already bound (reverse order) and returns —
	// there is never an instant where a strict non-empty subset of the
	// configured main listeners is live.
	members, err := bindMainListeners(cfg, deps, swappable, board)
	if err != nil {
		return err
	}
	adminMember, err := bindAdminServer(cfg, logger, auditLogger, versioner, deps, board)
	if err != nil {
		closeMembersReverse(deps, members)
		return err
	}
	allMembers := append([]*listenerMember(nil), members...)
	if adminMember != nil {
		allMembers = append(allMembers, adminMember)
	}
	defer func() {
		// http.Server.Shutdown closes each listener as part of its normal
		// teardown, so by the time this defer runs the FD is usually
		// already gone and Close returns net.ErrClosed. That is the
		// healthy shutdown path — don't surface it as a WARN.
		for i := len(allMembers) - 1; i >= 0; i-- {
			member := allMembers[i]
			closeErr := member.listener.Close()
			if closeErr == nil || errors.Is(closeErr, net.ErrClosed) {
				continue
			}
			logger.Warn("failed to close listener", "listener", member.identity.Name, "error", closeErr)
		}
	}()

	// Pre-register every configured listener gauge at zero while the complete
	// group is bound but not yet published. The series is therefore present
	// even if an operator scrapes during the startup transition.
	setListenersUp(runtime.metrics, members, false)
	if adminMember != nil {
		runtime.metrics.SetListenerUp(adminMember.identity.Name, string(adminMember.identity.Role), string(adminMember.identity.Network), false)
	}

	fanIn := make(chan listenerResult, len(allMembers))
	publishMainListeners(deps, members, fanIn, board)
	if adminMember != nil {
		publishListenerMember(deps, adminMember, fanIn, board)
	}
	setListenersUp(runtime.metrics, members, true)
	if adminMember != nil {
		runtime.metrics.SetListenerUp(adminMember.identity.Name, string(adminMember.identity.Role), string(adminMember.identity.Network), true)
		logger.Info("admin listener started",
			"listen", adminListenerAddr(cfg),
			"validate_path", cfg.Admin.Path,
			"policy_version_path", cfg.Admin.PolicyVersionPath,
		)
	}

	upstreamName := upstreamLabel(runtime.resolver)
	stopResolver := runtime.startResolver(cmd.Context())
	defer stopResolver()
	stopWatchdog := runtime.startWatchdog(cmd.Context(), cfg)
	defer stopWatchdog()
	stopReadiness := runtime.startReadiness(cmd.Context(), cfg)
	defer stopReadiness()

	bannerLines := bannerListenerLines(members, cfg.EffectiveListeners())
	if adminMember != nil {
		bannerLines = append(bannerLines, "admin "+adminListenerAddr(cfg))
	}
	banner.Render(cmd.ErrOrStderr(), banner.Info{
		Listeners: bannerLines,
		Upstream:  upstreamName,
		Rules:     len(cfg.Rules),
		LogFormat: cfg.Log.Format,
		LogLevel:  cfg.Log.Level,
		AccessLog: cfg.Log.AccessLog,
	})
	logger.Info("sockguard started",
		"version", version.Version,
		"listeners", bannerLines,
		"upstream", upstreamName,
		"rules", len(cfg.Rules),
		"log_level", cfg.Log.Level,
		"upstream_request_timeout", upstreamRequestTimeoutLogValue(cfg),
	)

	stopReload := startConfigReload(cmd.Context(), cfg, cfgFile, coordinator, logger)
	defer stopReload()

	sigCh := make(chan os.Signal, 1)
	deps.notifySignals(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var serveFailure error
	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case result := <-fanIn:
		// Any Serve return before an intentional drain is fatal, including nil
		// and http.ErrServerClosed: neither can occur while the listener group
		// is healthy. Record the failure, then drain the complete group before
		// returning a non-nil process error.
		board.setState(result.name, health.ListenerStateFailed)
		cause := result.err
		if cause == nil {
			cause = errors.New("serve returned nil before group shutdown")
		} else if errors.Is(cause, http.ErrServerClosed) {
			cause = fmt.Errorf("serve exited before group shutdown: %w", cause)
		}
		if result.role == inbound.RoleAdmin {
			serveFailure = fmt.Errorf("admin server error: %w", cause)
		} else {
			serveFailure = fmt.Errorf("listener %q server error: %w", result.name, cause)
		}
	}
	stopWatchdog()

	shutdownServers(cmd.Context(), deps, cfg, members, adminMember, runtime.metrics, board, logger)
	logger.Info("sockguard stopped")
	return serveFailure
}

// bindAdminServer prepares the dedicated admin listener as the final member
// of the all-or-none bind transaction. It deliberately does not call Serve;
// the caller publishes it only after every main and admin bind succeeded.
func bindAdminServer(
	cfg *config.Config,
	logger *slog.Logger,
	auditLogger *logging.AuditLogger,
	versioner *admin.PolicyVersioner,
	deps *serveDeps,
	board *listenerStatusBoard,
) (*listenerMember, error) {
	if !cfg.Admin.Enabled || !cfg.Admin.Listen.Configured() {
		return nil, nil
	}
	ln, err := deps.createAdminListener(cfg)
	if err != nil {
		return nil, fmt.Errorf("admin listener: %w", err)
	}
	warnIfAdminListenerWideOpen(cfg, logger)
	identity := inbound.Identity{Name: config.AdminListenerName, Role: inbound.RoleAdmin, Network: networkFor(cfg.Admin.Listen.ListenConfig)}
	server := newAdminHTTPServer(buildAdminHandlerChain(cfg, logger, auditLogger, versioner))
	server.ConnContext = inbound.ConnContext(identity, server.ConnContext)
	member := &listenerMember{
		identity:   identity,
		listener:   ln,
		server:     server,
		socketPath: cfg.Admin.Listen.Socket,
	}
	if member.socketPath != "" {
		member.socketIdentity = statSocketIdentity(deps.lstatPath, member.socketPath)
	}
	board.register(identity, health.ListenerStateBound)
	return member, nil
}

// shutdownServers gracefully stops every main listener and the admin
// http.Server, concurrently, within the configured grace period, and
// removes any unix sockets sockguard owns. Errors from each step are
// logged but do not block subsequent steps — shutdown must always make
// progress so a partial failure can't leave a stale listener behind.
func shutdownServers(ctx context.Context, deps *serveDeps, cfg *config.Config, members []*listenerMember, adminMember *listenerMember, registry *metrics.Registry, board *listenerStatusBoard, logger *slog.Logger) {
	// The command context has normally already been canceled by SIGTERM. A
	// fresh background-derived deadline gives every server the promised grace
	// period instead of entering Shutdown with an already-canceled context.
	_ = ctx
	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.shutdownGracePeriod)
	defer cancel()

	// Mark every listener down as soon as draining begins, before the actual
	// Shutdown calls below: the gauge means "safe to route new traffic here",
	// not "still finishing in-flight requests" — see Registry.SetListenerUp.
	setListenersUp(registry, members, false)
	if adminMember != nil {
		registry.SetListenerUp("admin", string(inbound.RoleAdmin), string(networkFor(cfg.Admin.Listen.ListenConfig)), false)
		board.setState("admin", health.ListenerStateDraining)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		shutdownMainListeners(shutdownCtx, deps, members, board, logger)
	}()

	if adminMember != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := deps.shutdownServer(adminMember.server, shutdownCtx); err != nil {
				logger.Error("admin shutdown error", "error", err)
				if shutdownCtx.Err() != nil {
					_ = adminMember.server.Close()
					_ = adminMember.listener.Close()
				}
			}
		}()
	}
	wg.Wait()

	if adminMember != nil {
		board.setState("admin", health.ListenerStateStopped)
	}

	if adminMember != nil && adminMember.socketPath != "" {
		if err := removeSocketIfOwned(deps, adminMember.socketPath, adminMember.socketIdentity); err != nil && !os.IsNotExist(err) {
			logger.Error("remove admin socket error", "socket", cfg.Admin.Listen.Socket, "error", err)
		}
	}
}

// buildInitialPolicySnapshot captures the per-startup metadata that the
// admin policy-version endpoint and the policy-version gauge surface to
// operators. Bundle fields stay zero unless verification succeeded.
func buildInitialPolicySnapshot(deps *serveDeps, cfg *config.Config, rules []*filter.CompiledRule, compatActive bool, bundleResult *policybundle.VerifyResult) admin.PolicySnapshot {
	snap := admin.PolicySnapshot{
		LoadedAt:     deps.now(),
		Rules:        len(rules),
		Profiles:     len(cfg.Clients.Profiles),
		CompatActive: compatActive,
		Source:       "startup",
		ConfigSHA256: policyConfigHash(cfg),
	}
	if bundleResult != nil {
		snap.BundleSource = filepath.Base(cfg.PolicyBundle.SignaturePath)
		snap.BundleSigner = bundleResult.Signer
		snap.BundleDigest = bundleResult.DigestHex
	}
	return snap
}

// startConfigReload wires up the SIGHUP / fsnotify reload loop. Returns a
// stop closure the caller must defer; the closure is a no-op when reload is
// disabled or the watcher fails to start (logged at Error so an operator can
// see the degradation without taking the proxy down).
func startConfigReload(ctx context.Context, cfg *config.Config, cfgFile string, coordinator *reloadCoordinator, logger *slog.Logger) func() {
	if !cfg.Reload.Enabled || cfgFile == "" {
		return func() {}
	}
	debounce := reload.DefaultDebounce
	if cfg.Reload.Debounce != "" {
		if d, err := time.ParseDuration(cfg.Reload.Debounce); err == nil {
			debounce = d
		}
	}
	var pollInterval time.Duration
	if cfg.Reload.PollInterval != "" {
		if d, err := time.ParseDuration(cfg.Reload.PollInterval); err == nil {
			pollInterval = d
		}
	}
	stop, err := startReloader(ctx, cfgFile, debounce, pollInterval, coordinator, logger)
	if err != nil {
		logger.Error("config hot-reload disabled: failed to start watcher",
			"error", err,
			"path", cfgFile,
		)
		return func() {}
	}
	return stop
}

// serveHandlerBuild bundles the inputs the buildServeHandler* family needs.
// The chain pulls together config, rules, every per-process singleton, and
// the optional admin versioner; grouping them avoids 6-8 positional params
// at every call site.
type serveHandlerBuild struct {
	Cfg            *config.Config
	Logger         *slog.Logger
	AuditLogger    *logging.AuditLogger
	Rules          []*filter.CompiledRule
	Deps           *serveDeps
	Runtime        *serveRuntime
	Versioner      *admin.PolicyVersioner
	ClientProfiles map[string]filter.Policy
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
// buildServeHandler which discards it — the goroutines die with the test
// process anyway.
//
// The third return value reports whether the built chain holds discardable
// limiter state (a token bucket or a concurrency tracker), not merely whether
// the rate-limit middleware is installed; see
// buildServeHandlerLayersWithRuntime.
func buildServeHandlerChainWithRuntime(b serveHandlerBuild) (http.Handler, func(), bool) {
	resolver := runtimeResolver(b.Runtime, b.Cfg)
	clientProfiles, err := buildServeClientProfiles(b.Cfg, resolver)
	if err != nil {
		b.Logger.Error("invalid client profile config", "error", err)
		return invalidClientProfileHandler(), func() {}, false
	}

	handler := newServeUpstreamHandler(b.Cfg, resolver, b.Logger)
	b.ClientProfiles = clientProfiles
	layers, teardown, limiterStateActive := buildServeHandlerLayersWithRuntime(b)
	for _, layer := range layers {
		handler = layer.with(handler)
	}
	return handler, teardown, limiterStateActive
}

// serveRuntime holds process-scoped objects whose lifetime spans the whole
// run: the metrics registry and the upstream-health monitor. Both survive
// hot reloads — they are tied to immutable config fields, so a reload that
// would change them is rejected by the immutable-field gate before any
// rebuild happens. Chain-scoped goroutines (rate-limit sampler, per-profile
// Limiter eviction) are tracked separately by reloadCoordinator.
type serveRuntime struct {
	metrics   *metrics.Registry
	health    *health.Monitor
	readiness *health.Monitor
	// resolver is the shared upstream dial seam (endpoint selection, pooling,
	// TLS, failover). All request paths and side channels route through it so
	// failover is coherent across the proxy, hijack, and inspect calls.
	resolver *upstream.Resolver
	// legacyUpstreamSocket records that the upstream is the single local socket
	// (no endpoints, no DOCKER_HOST), so startup keeps the original fail-fast
	// reachability check.
	legacyUpstreamSocket bool
}

func newServeRuntime(cfg *config.Config, logger *slog.Logger, deps *serveDeps) (*serveRuntime, error) {
	runtime := &serveRuntime{}
	if cfg.Metrics.Enabled {
		runtime.metrics = metrics.NewRegistry()
	}

	resolver, legacy, err := buildUpstreamResolver(cfg, logger, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	runtime.resolver = resolver
	runtime.legacyUpstreamSocket = legacy
	label := upstreamLabel(resolver)

	if cfg.Health.Enabled || cfg.Health.Watchdog.Enabled {
		runtime.health = health.NewMonitorWithDialer(label, resolver, deps.now(), logger)
	}
	if cfg.Health.Readiness.Enabled {
		timeout, _ := time.ParseDuration(cfg.Health.Readiness.Timeout)
		runtime.readiness = health.NewReadinessMonitorWithRoundTripper(label, resolver, deps.now(), logger, timeout)
	}
	return runtime, nil
}

// startResolver launches the resolver's background health/failover probe loop.
// It returns a stop func; the loop also exits when ctx is canceled.
func (r *serveRuntime) startResolver(ctx context.Context) func() {
	if r == nil || r.resolver == nil {
		return func() {}
	}
	resolverCtx, cancel := context.WithCancel(ctx)
	r.resolver.Start(resolverCtx)
	return cancel
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

func (r *serveRuntime) startReadiness(ctx context.Context, cfg *config.Config) func() {
	if r == nil || r.readiness == nil || !cfg.Health.Readiness.Enabled {
		return func() {}
	}
	interval, err := time.ParseDuration(cfg.Health.Readiness.Interval)
	if err != nil || interval <= 0 {
		return func() {}
	}

	readinessCtx, cancel := context.WithCancel(ctx)
	r.readiness.StartWatchdog(readinessCtx, interval, func(state health.WatchdogState) {
		if r.metrics == nil {
			return
		}
		r.metrics.ObserveUpstreamReadiness(state.Up)
		r.metrics.SetUpstreamAPIState(state.Up)
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

func buildServeClientProfiles(cfg *config.Config, res *upstream.Resolver) (map[string]filter.Policy, error) {
	clientProfiles, err := compileClientProfiles(cfg)
	if err != nil {
		return nil, err
	}
	for name, profile := range clientProfiles {
		profile.PolicyConfig = attachRuntimeInspectors(cfg, res, profile.PolicyConfig)
		clientProfiles[name] = profile
	}
	return clientProfiles, nil
}

// attachRuntimeInspectors wires runtime-only policy inputs onto a PolicyConfig
// shaped by config translation. The Docker-compat and libpod exec-start
// inspectors issue their GET through the shared upstream resolver so identity
// lookups follow the same active endpoint as the request they guard. The global
// blind-write acknowledgment is attached here too because it is not part of a
// profile's request_body block. Keeping this centralized gives the default
// policy and every client profile the same runtime wiring.
func attachRuntimeInspectors(cfg *config.Config, res *upstream.Resolver, policy filter.PolicyConfig) filter.PolicyConfig {
	policy.Exec.InspectStart = filter.NewDockerExecInspectorWithRoundTripper(upstreamResolverFor(res, cfg))
	// libpod's POST /libpod/exec/{id}/start re-check queries a different
	// upstream URL family (GET /libpod/exec/{id}/json) than the Docker-compat
	// path above, even though both are checked against the SAME execPolicy
	// (#148 design doc decision C3) — see ExecOptions.InspectStartLibpod.
	policy.Exec.InspectStartLibpod = filter.NewLibpodExecInspectorWithRoundTripper(upstreamResolverFor(res, cfg))
	// insecure_allow_body_blind_writes is a global, not-per-profile setting
	// (validateBodyBlindWriteRulesForPolicy in rules.go says as much), so it
	// is wired here rather than through RequestBodyConfig.ToFilterOptions —
	// the same as every client profile's PolicyConfig, since this function
	// runs for both the default policy and every named profile.
	policy.Exec.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	policy.Build.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	// Image load needs it for the same reason build does: Podman's
	// POST /libpod/local/images/load names its archive by daemon-host path,
	// so there is no body to inspect and only the acknowledgment admits it.
	policy.ImageLoad.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	policy.ContainerUpdate.AllowBlindWrites = cfg.InsecureAllowBodyBlindWrites
	return policy
}

func newServeUpstreamHandler(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) http.Handler {
	rp := proxy.NewWithTransport(upstreamResolverFor(res, cfg), logger, proxy.Options{
		ModifyResponse: responsefilter.New(serveResponseFilterOptions(cfg)).ModifyResponse,
	})
	// Bound finite upstream requests with a total deadline when configured.
	// Wrapping the proxy itself (rather than adding a chain layer) keeps the
	// deadline off the hijack path: HijackHandler short-circuits before this
	// handler runs.
	return proxy.WithRequestTimeout(rp, effectiveUpstreamRequestTimeout(cfg))
}

// effectiveUpstreamRequestTimeout resolves cfg.Upstream.RequestTimeout to the
// time.Duration proxy.WithRequestTimeout consumes. RequestTimeoutDisabled is
// the single source of truth for the "off"/legacy-empty disabled spelling,
// shared with config.validateUpstream so the two call sites can't drift.
// request_timeout is validated at config load, so a parse failure here
// degrades to "disabled" (0) rather than aborting the chain rebuild.
func effectiveUpstreamRequestTimeout(cfg *config.Config) time.Duration {
	if cfg.Upstream.RequestTimeoutDisabled() {
		return 0
	}
	d, err := time.ParseDuration(cfg.Upstream.RequestTimeout)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// upstreamRequestTimeoutLogValue renders the effective upstream.request_timeout
// for the "sockguard started" log line: "off" when the deadline is disabled
// (including a degraded invalid value, which is validated away at load time
// in normal operation), otherwise the configured duration string verbatim.
func upstreamRequestTimeoutLogValue(cfg *config.Config) string {
	if effectiveUpstreamRequestTimeout(cfg) <= 0 {
		return "off"
	}
	return cfg.Upstream.RequestTimeout
}

// The third return value reports whether this chain holds discardable
// limiter state — at least one token bucket or one concurrency tracker,
// per-profile or global. It is NOT "the rate-limit middleware is
// installed": a profile carrying only limits.priority installs the
// middleware but compiles no bucket and no tracker, so there is nothing
// for a chain swap to throw away. Callers that swap chains on hot reload
// use this to decide whether a discard is worth telling the operator
// about.
func buildServeHandlerLayersWithRuntime(b serveHandlerBuild) ([]serveHandlerLayer, func(), bool) {
	cfg, logger, auditLogger := b.Cfg, b.Logger, b.AuditLogger
	runtime, versioner := b.Runtime, b.Versioner
	rules, clientProfiles := b.Rules, b.ClientProfiles
	resolver := runtimeResolver(runtime, cfg)
	layers := []serveHandlerLayer{
		// withBuildkitMediator sits even closer to the final proxy handler
		// than withHijack: append order builds the chain inside-out (later
		// appends wrap/execute before earlier ones — see the #152 comment
		// below), so this is the innermost layer, running only for requests
		// hijack's own attach/exec matcher ignores. The two middlewares'
		// path sets are disjoint (attach/exec vs. session/grpc), so their
		// relative order doesn't affect correctness, only which one a
		// reader sees "closer to the wire" in this slice.
		namedServeHandlerLayer("withBuildkitMediator", withBuildkitMediator(cfg, resolver, logger)),
		namedServeHandlerLayer("withHijack", withHijack(cfg, resolver, logger)),
		// #152: inserted between hijack and ownership in APPEND order. Later
		// appends wrap (execute before) earlier ones, so this yields runtime
		// order ...filter -> visibility -> ownership -> resource-limit guard
		// -> hijack -> proxy — ownership decides before any resource-state
		// lookup, and the guard still runs before hijack/proxy for every
		// request ownership allowed.
		namedServeHandlerLayer("withResourceLimitGuard", withResourceLimitGuard(cfg, resolver, logger, clientProfiles)),
		namedServeHandlerLayer("withOwnership", withOwnership(cfg, resolver, logger)),
		namedServeHandlerLayer("withVisibility", withVisibility(cfg, resolver, logger)),
		namedServeHandlerLayer("withFilter", withFilter(cfg, resolver, logger, rules, clientProfiles)),
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
	// http.Server (see bindAdminServer); the main chain must NOT also mount
	// them, otherwise the same path resolves on both listeners and operators
	// lose the isolation they explicitly opted in to.
	if cfg.Admin.Enabled && !cfg.Admin.Listen.Configured() {
		if versioner != nil {
			layers = append(layers, namedServeHandlerLayer("withPolicyVersionEndpoint", mountOnGate(cfg, withPolicyVersionEndpoint(cfg, logger, versioner))))
		}
		layers = append(layers, namedServeHandlerLayer("withAdminEndpoint", mountOnGate(cfg, withAdminEndpoint(cfg, logger))))
	}

	// Rate limiting and concurrency caps sit after client identity is resolved
	// (clientacl) but before rule evaluation (filter), so a request denied by
	// the filter still consumes its rate-limit quota — rule-probing cannot
	// happen at line rate. The teardown closure halts the sampler + Limiter
	// eviction goroutines bound to this chain — callers must invoke it when
	// the chain is replaced (hot reload) or torn down at shutdown.
	teardown := func() {}
	limiterStateActive := false
	if rlMiddleware, stop, hasLimiterState := buildRateLimitMiddleware(cfg, logger, runtime); rlMiddleware != nil {
		teardown = stop
		limiterStateActive = hasLimiterState
		layers = append(layers, namedServeHandlerLayer("withRateLimit", rlMiddleware))
	}

	if cfg.Health.Enabled {
		layers = append(layers, namedServeHandlerLayer("withHealth", withHealth(cfg, runtime)))
	}
	if runtime.readiness != nil {
		layers = append(layers, namedServeHandlerLayer("withReadiness", withReadiness(cfg, runtime)))
	}
	if runtime.metrics != nil {
		layers = append(layers, namedServeHandlerLayer("withMetricsEndpoint", withMetricsEndpoint(cfg, runtime.metrics)))
	}
	// withListenerAdmission is appended BEFORE withClientACL so it executes
	// AFTER it: append order is reversed at composition time (see
	// buildServeHandlerChainWithRuntime), and admission needs
	// clientacl.RequestProfile to already be resolved.
	layers = append(layers, namedServeHandlerLayer("withListenerAdmission", withListenerAdmission(cfg)))
	layers = append(layers,
		namedServeHandlerLayer("withClientACL", withClientACL(cfg, resolver, logger)),
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
	return layers, teardown, limiterStateActive
}

// buildRateLimitMiddleware constructs the per-profile rate-limit+concurrency
// middleware and its audit sampler. Returns (nil, nil, false) when no profile
// has limits and no global concurrency cap is configured. The second return
// value is a stop function that halts the sampler eviction goroutine and every
// per-profile Limiter eviction goroutine; callers must call it on shutdown.
//
// The third return value reports whether the middleware actually owns
// discardable counters: a token bucket (limits.rate), a per-profile inflight
// tracker (limits.concurrency), or the global inflight tracker
// (clients.global_concurrency). A profile carrying only limits.priority puts
// the middleware in the chain — ratelimit.compileProfile keeps it so the
// profile's tier is known to the global gate — but compiles neither a bucket
// nor a tracker, so a chain swap that replaces it throws nothing away. Keep
// this derived from the same predicates compileProfile uses; middleware
// presence alone is not the same question.
func buildRateLimitMiddleware(cfg *config.Config, logger *slog.Logger, runtime *serveRuntime) (func(http.Handler) http.Handler, func(), bool) {
	limiterState := false
	profiles := make(map[string]ratelimit.ProfileOptions)
	for _, profile := range cfg.Clients.Profiles {
		opts := configLimitsToRateLimitOptions(profile.Name, profile.Limits, logger)
		if opts.Rate != nil || opts.Concurrency != nil || opts.Priority != ratelimit.PriorityNormal {
			profiles[profile.Name] = opts
		}
		if opts.Rate != nil || opts.Concurrency != nil {
			limiterState = true
		}
	}

	var globalConc *ratelimit.GlobalConcurrencyOptions
	if cfg.Clients.GlobalConcurrency != nil && cfg.Clients.GlobalConcurrency.MaxInflight > 0 {
		globalConc = &ratelimit.GlobalConcurrencyOptions{
			MaxInflight: cfg.Clients.GlobalConcurrency.MaxInflight,
		}
		limiterState = true
	}

	if len(profiles) == 0 && globalConc == nil {
		return nil, nil, false
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
	return mw, stop, limiterState
}

func namedServeHandlerLayer(name string, with func(http.Handler) http.Handler) serveHandlerLayer {
	return serveHandlerLayer{name: name, with: with}
}

func withHijack(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Hijack handler: intercepts attach/exec endpoints for native bidirectional
		// streaming with optimized buffers and TCP half-close signaling. Dials the
		// same active upstream endpoint as the rest of the proxy.
		return proxy.HijackHandlerWithDialer(res, effectiveHijackInactivityTimeout(cfg), logger, next)
	}
}

// effectiveHijackInactivityTimeout resolves cfg.Upstream.HijackInactivityTimeout
// to the time.Duration proxy.HijackHandlerWithDialer consumes, mirroring
// effectiveUpstreamRequestTimeout. Unlike request_timeout there is no "off"
// spelling here — hijack_inactivity_timeout is validated at config load to
// always be a positive duration, so a parse failure degrades to the package
// default (10m) rather than disabling the deadline outright.
func effectiveHijackInactivityTimeout(cfg *config.Config) time.Duration {
	d, err := time.ParseDuration(cfg.Upstream.HijackInactivityTimeout)
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}

// withBuildkitMediator intercepts POST /session and POST /grpc once
// request_body.buildkit is configured for the request's effective policy
// (global, or the client profile clientacl resolved), handing them to
// internal/buildkitproxy.Mediator instead of letting them reach the plain
// ReverseProxy. filter.buildkitPolicy.inspect (see internal/filter/buildkit.go)
// already admitted these two paths at rule-evaluation time whenever
// TunnelConfigured was true; this layer is the actual h2c termination point,
// downstream of that admission — mirroring how withHijack is the real
// bidirectional-copy point for attach/exec, downstream of filter's own
// admission of those paths.
//
// When the resolved policy is NOT configured (the legacy
// insecure_accept_opaque_buildkit_tunnels path, or a request that reached
// here without either flag somehow — filter's admission gate makes that
// combination unreachable in practice), this layer is a no-op and the
// request falls through to next unchanged, exactly like Phase 1.
func withBuildkitMediator(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	warnIfOpaqueBuildkitTunnelDeprecated(cfg, logger)
	defaultPolicy := cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build)
	profilePolicies := make(map[string]buildkitproxy.Policy, len(cfg.Clients.Profiles))
	for _, profile := range cfg.Clients.Profiles {
		profilePolicies[profile.Name] = profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build)
	}
	mediator := buildkitproxy.NewMediator(res, logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normPath := filter.NormalizePath(r.URL.Path)
			if r.Method != http.MethodPost || !filter.IsBuildkitTunnelPath(normPath) {
				next.ServeHTTP(w, r)
				return
			}

			profileName, hasProfile := clientacl.RequestProfile(r)
			policy := defaultPolicy
			if hasProfile {
				if p, ok := profilePolicies[profileName]; ok {
					policy = p
				}
			}
			if !policy.Configured() {
				next.ServeHTTP(w, r)
				return
			}

			principal, err := clientacl.RequestPrincipal(r)
			if err != nil {
				logger.ErrorContext(r.Context(), "BuildKit client identity lookup failed", "error", err)
				logging.SetDeniedWithCode(w, r, "client_identity_lookup_failed", "client identity lookup failed", filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "client identity lookup failed"})
				return
			}

			key := buildkitproxy.SessionKey{ClientIdentity: principal, Profile: profileName}
			switch normPath {
			case "/grpc":
				mediator.ServeGRPC(w, r, policy, key)
			case "/session":
				mediator.ServeSession(w, r, policy, key)
			}
		})
	}
}

// opaqueBuildkitTunnelWarnOnce gates warnIfOpaqueBuildkitTunnelDeprecated to a
// single emission per process, like bodyBlindWritesWarnOnce — withBuildkitMediator
// is a chain-build site rebuilt on every config hot-reload (the flag is not
// in reload.ImmutableFields), so an unguarded warning here would repeat on
// each reload.
var opaqueBuildkitTunnelWarnOnce sync.Once

// warnIfOpaqueBuildkitTunnelDeprecated surfaces the deprecation of
// insecure_accept_opaque_buildkit_tunnels now that request_body.buildkit
// (issue #185) provides full per-message mediation of the same POST
// /session and POST /grpc endpoints the flag wholesale-admits with zero
// inspection. validateBuildkitAckMutualExclusion (config/validate.go)
// already rejects the flag combined with a configured request_body.buildkit
// block, and validateAndCompileRules runs before the handler chain is ever
// built, so by the time this fires request_body.buildkit is guaranteed
// unconfigured everywhere — this warning and that validation error never
// fire for the same config.
func warnIfOpaqueBuildkitTunnelDeprecated(cfg *config.Config, logger *slog.Logger) {
	warnOpaqueBuildkitTunnelDeprecatedOnce(cfg, logger, &opaqueBuildkitTunnelWarnOnce)
}

// warnOpaqueBuildkitTunnelDeprecatedOnce is the testable core of
// warnIfOpaqueBuildkitTunnelDeprecated: the Once is injected so tests can
// verify both the enable-check and the once-per-process gating without
// racing other tests for the package-level guard.
func warnOpaqueBuildkitTunnelDeprecatedOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	//nolint:staticcheck // SA1019: this is the deprecation warning's own enable-check
	if !cfg.InsecureAcceptOpaqueBuildkitTunnels {
		return
	}
	once.Do(func() {
		logger.Warn("insecure_accept_opaque_buildkit_tunnels is deprecated: it admits POST /session and POST /grpc with zero inspection now that request_body.buildkit provides full per-message BuildKit mediation (issue #185); migrate to request_body.buildkit — this flag will be removed in a future major release")
	})
}

func withOwnership(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return ownership.MiddlewareWithRoundTripper(res, logger, ownership.Options{
		Owner:                           cfg.Ownership.Owner,
		LabelKey:                        cfg.Ownership.LabelKey,
		AllowUnownedImages:              cfg.Ownership.AllowUnownedImages,
		AllowCrossOwnerNamespaceSharing: cfg.Ownership.AllowCrossOwnerNamespaceSharing,
	})
}

func withVisibility(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	return visibility.MiddlewareWithRoundTripper(res, logger, visibility.Options{
		VisibleResourceLabels: cfg.Response.VisibleResourceLabels,
		NamePatterns:          cfg.Response.NamePatterns,
		ImagePatterns:         cfg.Response.ImagePatterns,
		Profiles:              clientVisibilityProfiles(cfg.Clients.Profiles),
		ResolveProfile:        clientacl.RequestProfile,
	})
}

func withFilter(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger, rules []*filter.CompiledRule, clientProfiles map[string]filter.Policy) func(http.Handler) http.Handler {
	warnIfBodyBlindWritesEnabled(cfg, logger)
	warnIfReadExfiltrationEnabled(cfg, rules, clientProfiles, logger)
	return filter.MiddlewareWithOptions(rules, logger, serveFilterOptions(cfg, res, clientProfiles))
}

// bodyBlindWritesWarnOnce gates warnIfBodyBlindWritesEnabled to a single
// emission per process, like labelACLWarnOnce — the handler chain is rebuilt
// on every config hot-reload, so an unguarded warning at the chain-build site
// would repeat on each reload.
var bodyBlindWritesWarnOnce sync.Once

// warnIfBodyBlindWritesEnabled surfaces the runtime consequence of
// insecure_allow_body_blind_writes: true at chain-build time (startup or
// hot-reload). The startup validator (validateBodyBlindWriteRulesForPolicy in
// rules.go) already refuses to start without this acknowledgment when a
// body-blind endpoint is reachable; this is the loud runtime echo of that same
// acknowledgment, visible in the running process's logs rather than only at
// validate time.
func warnIfBodyBlindWritesEnabled(cfg *config.Config, logger *slog.Logger) {
	warnBodyBlindWritesOnce(cfg, logger, &bodyBlindWritesWarnOnce)
}

func warnIfDefaultProfileExcluded(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil || cfg.Clients.DefaultProfile == "" || len(cfg.Listeners) == 0 {
		return
	}
	for _, listener := range cfg.Listeners {
		if listener.Wildcard() || allowedProfileContains(listener.AllowedProfiles, cfg.Clients.DefaultProfile) {
			continue
		}
		logger.Warn("default profile is not allowed on listener; unmatched clients will be denied",
			"listener", listener.Name,
			"default_profile", cfg.Clients.DefaultProfile,
		)
	}
}

// warnBodyBlindWritesOnce is the testable core of warnIfBodyBlindWritesEnabled:
// the Once is injected so tests can verify both the enable-check and the
// once-per-process gating without racing other tests for the package-level
// guard.
func warnBodyBlindWritesOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	if !cfg.InsecureAllowBodyBlindWrites {
		return
	}
	once.Do(func() {
		logger.Warn("insecure_allow_body_blind_writes is enabled: body-sensitive write endpoints with no request-body allowlist configured (e.g. exec with an empty allowed_commands) are reachable without that allowlist check — other configured gates (allow_privileged, allow_root_user, allowed_env_vars/denied_env_vars, allowed_join_remote_addrs, allowed_set_env_prefixes) still apply in full")
	})
}

// readExfiltrationWarnOnce gates warnIfReadExfiltrationEnabled to a single
// emission per process, like bodyBlindWritesWarnOnce — the handler chain is
// rebuilt on every config hot-reload, so an unguarded warning at the
// chain-build site would repeat on each reload.
var readExfiltrationWarnOnce sync.Once

// warnIfReadExfiltrationEnabled surfaces the runtime consequence of
// insecure_allow_read_exfiltration: true at chain-build time (startup or
// hot-reload), the read-side counterpart of warnIfBodyBlindWritesEnabled. The
// startup validator (validateReadExfiltrationRulesForPolicy in rules.go)
// already refuses to start without this acknowledgment when an
// exfiltration-capable endpoint is reachable; this is the loud runtime echo of
// that same acknowledgment, visible in the running process's logs rather than
// only at validate time. It matters more here than for the write-side flag,
// because the README quick start and the Tecnativa migration path both ship
// the acknowledgment set, so the documented happy path had no ongoing signal
// at all.
func warnIfReadExfiltrationEnabled(cfg *config.Config, rules []*filter.CompiledRule, clientProfiles map[string]filter.Policy, logger *slog.Logger) {
	warnReadExfiltrationOnce(cfg, rules, clientProfiles, logger, &readExfiltrationWarnOnce)
}

// warnReadExfiltrationOnce is the testable core of
// warnIfReadExfiltrationEnabled: the Once is injected so tests can verify both
// the enable-check and the once-per-process gating without racing other tests
// for the package-level guard.
//
// Both endpoint lists come from allowedSensitiveExfilEndpoints, the same probe
// the startup validator uses to build its refusal message, so the warning names
// exactly what the acknowledgment is currently buying rather than restating the
// whole catalog. Named client profiles are reported separately because their
// rules are evaluated in place of the top-level set: the acknowledgment is
// global, so a profile can be the only reason it has to be set, and the
// per-profile refusal that would otherwise name it never fires once it is.
// Both fields are stable across runs (see allowedSensitiveExfilEndpointsByProfile
// for the sort that makes the profile half so).
//
// Two empty lists are still worth logging: that means the acknowledgment is set
// while no rule needs it, which is a standing permission the operator can
// remove.
func warnReadExfiltrationOnce(cfg *config.Config, rules []*filter.CompiledRule, clientProfiles map[string]filter.Policy, logger *slog.Logger, once *sync.Once) {
	if !cfg.InsecureAllowReadExfiltration {
		return
	}
	exposed := allowedSensitiveExfilEndpoints(cfg.Rules, rules)
	profileExposed := allowedSensitiveExfilEndpointsByProfile(cfg.Clients.Profiles, clientProfiles)
	once.Do(func() {
		logger.Warn("insecure_allow_read_exfiltration is enabled: rules matching raw archive/export, log/attach streaming, checkpoint export, container rootfs mount, or registry push endpoints are admitted instead of refused at startup. A caller allowed those paths can read container files, container memory, images, plugins, environment variables, secrets, and daemon-host filesystem paths, or push local artifacts to a registry it chooses",
			"exposed_endpoints", exposed,
			"exposed_profile_endpoints", profileExposed,
		)
	})
}

// withHealth wires the /health endpoint onto the runtime monitor.
//
// Precondition: cfg.Health.Enabled is true, so newServeRuntime has already
// allocated runtime.health. The caller must guarantee this — a nil monitor
// here is a programming error and will panic on Handler() rather than be
// papered over with a silently-allocated fallback.
func withHealth(cfg *config.Config, runtime *serveRuntime) func(http.Handler) http.Handler {
	healthHandler := runtime.health.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Health.Path, healthHandler, next)
	}
}

// withReadiness wires the readiness endpoint onto the runtime's readiness
// monitor. Precondition: runtime.readiness is non-nil (cfg.Health.Readiness
// .Enabled), guaranteed by the caller as with withHealth.
func withReadiness(cfg *config.Config, runtime *serveRuntime) func(http.Handler) http.Handler {
	readinessHandler := runtime.readiness.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Health.Readiness.Path, readinessHandler, next)
	}
}

func withMetricsEndpoint(cfg *config.Config, registry *metrics.Registry) func(http.Handler) http.Handler {
	metricsHandler := registry.Handler()
	return func(next http.Handler) http.Handler {
		return pathInterceptor(cfg.Metrics.Path, metricsHandler, next)
	}
}

func withMetrics(registry *metrics.Registry) func(http.Handler) http.Handler {
	return registry.Middleware()
}

func withClientACL(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger) func(http.Handler) http.Handler {
	warnIfLabelACLEnabled(cfg, logger)
	warnIfRulesHaveVersionPrefix(cfg, logger)
	return clientacl.MiddlewareWithRoundTripper(upstreamResolverFor(res, cfg), logger, serveClientACLOptions(cfg))
}

// rulesVersionPrefixWarnOnce gates warnIfRulesHaveVersionPrefix to a single
// emission per process, like labelACLWarnOnce. The guard before once.Do means
// the Once is only consumed when there is actually a prefixed rule to warn
// about, so a hot reload that introduces one still warns.
var rulesVersionPrefixWarnOnce sync.Once

// warnIfRulesHaveVersionPrefix flags rule patterns that begin with a Docker API
// version prefix (e.g. "/v1.45/..."). NormalizePath strips version prefixes from
// the request path before matching, so such a pattern can never match real
// traffic — the rule is silently dead, an intent gap worth surfacing.
func warnIfRulesHaveVersionPrefix(cfg *config.Config, logger *slog.Logger) {
	warnRulesVersionPrefixOnce(cfg, logger, &rulesVersionPrefixWarnOnce)
}

func warnRulesVersionPrefixOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	var prefixed []string
	for _, r := range cfg.Rules {
		if filter.HasVersionPrefix(r.Match.Path) {
			prefixed = append(prefixed, r.Match.Path)
		}
	}
	if len(prefixed) == 0 {
		return
	}
	once.Do(func() {
		logger.Warn("one or more rule patterns begin with a Docker API version prefix (e.g. /v1.45/...); "+
			"sockguard strips version prefixes before matching, so these patterns never match real traffic — write the unversioned path",
			"patterns", prefixed,
		)
	})
}

// labelACLWarnOnce gates warnIfLabelACLEnabled to a single emission per
// process. The handler chain is rebuilt on every config hot-reload, so an
// unguarded warning at the chain-build site would repeat on each reload.
var labelACLWarnOnce sync.Once

// warnIfLabelACLEnabled reminds operators that container-label ACLs are only
// trustworthy when sockguard is the exclusive path to the Docker socket: a
// workload that can reach the raw socket can create a container carrying
// arbitrary <label_prefix>* permission labels and self-grant access the
// policy never approved. Sockguard cannot detect other socket consumers, so
// the invariant is stated rather than enforced — once per process, on the
// first chain build (startup or hot-reload) that has the feature enabled.
func warnIfLabelACLEnabled(cfg *config.Config, logger *slog.Logger) {
	warnLabelACLOnce(cfg, logger, &labelACLWarnOnce)
}

// warnLabelACLOnce is the testable core of warnIfLabelACLEnabled: the Once is
// injected so tests can verify both the enable-check and the once-per-process
// gating without racing other tests for the package-level guard.
func warnLabelACLOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	if !cfg.Clients.ContainerLabels.Enabled {
		return
	}
	once.Do(func() {
		logger.Warn("container-label ACLs are enabled: label grants are only trustworthy if sockguard is the ONLY consumer of the Docker socket — any workload with raw socket access can self-grant permissions via labels",
			"label_prefix", cfg.Clients.ContainerLabels.LabelPrefix,
		)
	})
}

// withAdminClientACL applies ONLY the client CIDR allowlist to the dedicated
// admin listener. The dedicated admin chain intentionally omits the full
// clientacl middleware — container-label ACLs and per-profile selection are
// Docker-API concepts with no meaning for admin endpoints — but a TCP admin
// listener must still enforce the same clients.allowed_cidrs gate the main
// listener applies (#21). Passing only AllowedCIDRs yields a CIDR-only
// middleware; when no CIDRs are configured clientacl.Middleware compiles to a
// pass-through, so this is a no-op until an operator sets clients.allowed_cidrs.
//
// Because container-label ACLs are never enabled here, the middleware never
// resolves a client by source IP and so never dials the upstream — the socket
// argument is inert (it is not the shared resolver, by design, and is never
// used to reach Docker). It stays on the single-socket constructor deliberately
// so the admin trust boundary carries no dependency on the upstream resolver.
func withAdminClientACL(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return clientacl.Middleware(cfg.Upstream.Socket, logger, clientacl.Options{
		AllowedCIDRs: cfg.Clients.AllowedCIDRs,
	})
}

// mountOnGate restricts an in-band admin middleware (#149) to fire only on
// the listener named by cfg.Admin.MountOn. Every main listener shares ONE
// handler chain (reload.SwappableHandler), so without this gate an in-band
// admin endpoint mounted anywhere would be reachable from every main
// listener regardless of MountOn — silently widening the admin attack
// surface in proportion to listener count.
//
// The restriction is active exactly when config.validateAdminMountOn
// requires (and therefore guarantees, once Validate has passed) a non-empty,
// listener-matching MountOn: admin rides a main listener (no dedicated
// admin.listen) and there are 2+ effective main listeners. With <=1
// effective listener — every configuration that predates #149 — mw is
// returned unwrapped, preserving today's zero-config "admin rides the sole
// main listener" behavior byte-for-byte, including not requiring inbound
// identity to be present in request context.
func mountOnGate(cfg *config.Config, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if cfg.Admin.Listen.Configured() {
		return func(next http.Handler) http.Handler { return next }
	}
	if len(cfg.EffectiveListeners()) <= 1 {
		return mw
	}
	mountOn := cfg.Admin.MountOn
	return func(next http.Handler) http.Handler {
		gated := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := inbound.FromContext(r.Context())
			if ok && identity.Name == mountOn {
				gated.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func withAdminEndpoint(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return admin.NewValidateInterceptor(admin.Options{
		Path:            cfg.Admin.Path,
		MaxRequestBytes: cfg.Admin.MaxRequestBytes,
		Validate:        buildAdminValidator(logger),
		Logger:          logger,
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

// verifyPolicyBundleAtStartup verifies the signed policy bundle and, on success,
// returns the authoritative *config.Config parsed from the exact bytes that were
// verified. cfg carries trust pinned by the out-of-band trust config; only the
// signature path is read from the candidate YAML. The signed YAML is read once:
// the same byte slice is both checked and parsed without an environment overlay.
// The supplied context also cancels an in-flight verifier during shutdown.
func verifyPolicyBundleAtStartup(
	parent context.Context,
	cfg *config.Config,
	cfgFile string,
	deps *serveDeps,
	verifier policybundle.Verifier,
	logger *slog.Logger,
) (*policybundle.VerifyResult, *config.Config, error) {
	if !cfg.PolicyBundle.Enabled {
		return nil, nil, nil
	}
	if cfgFile == "" {
		return nil, nil, errors.New("policy_bundle.enabled=true but no --config file was supplied; sockguard cannot verify an in-memory default")
	}

	yamlBytes, err := deps.readConfigBytes(cfgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read config YAML for verification: %w", err)
	}
	signedCfg, err := deps.loadConfigBytes(yamlBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse verified config: %w", err)
	}
	pinPolicyBundleTrust(signedCfg, cfg.PolicyBundle)
	if signedCfg.PolicyBundle.SignaturePath == "" {
		return nil, nil, errors.New("policy_bundle.signature_path is required when signed policy is enabled")
	}
	entity, err := deps.loadBundleEntity(signedCfg.PolicyBundle.SignaturePath)
	if err != nil {
		return nil, nil, err
	}

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, bundleVerifyDeadline(cfg.PolicyBundle))
	defer cancel()
	result, err := verifier.Verify(ctx, yamlBytes, entity)
	if err != nil {
		return nil, nil, err
	}

	logger.Info("policy bundle verified",
		"signature_path", signedCfg.PolicyBundle.SignaturePath,
		"signer", result.Signer,
		"digest", result.DigestHex,
		"elapsed_ms", result.ElapsedMS,
	)
	return &result, signedCfg, nil
}

func policyBundleTrustConfigPath(cmd *cobra.Command) string {
	flag := cmd.Flag("policy-bundle-trust-config")
	if flag == nil {
		return ""
	}
	return strings.TrimSpace(flag.Value.String())
}

func loadPolicyBundleTrustConfig(deps *serveDeps, path string) (config.PolicyBundleConfig, error) {
	data, err := deps.readConfigBytes(path)
	if err != nil {
		return config.PolicyBundleConfig{}, err
	}
	cfg, err := deps.loadConfigBytes(data)
	if err != nil {
		return config.PolicyBundleConfig{}, err
	}
	if !cfg.PolicyBundle.Enabled {
		return config.PolicyBundleConfig{}, errors.New("policy_bundle.enabled must be true in the out-of-band trust config")
	}
	trust := cfg.PolicyBundle
	trust.SignaturePath = ""
	return trust, nil
}

func samePolicyConfigFile(deps *serveDeps, candidatePath, trustPath string) bool {
	candidateAbs, candidateErr := filepath.Abs(candidatePath)
	trustAbs, trustErr := filepath.Abs(trustPath)
	if candidateErr == nil && trustErr == nil && candidateAbs == trustAbs {
		return true
	}
	if deps.statPath == nil {
		return false
	}
	candidateInfo, candidateErr := deps.statPath(candidatePath)
	trustInfo, trustErr := deps.statPath(trustPath)
	return candidateErr == nil && trustErr == nil && os.SameFile(candidateInfo, trustInfo)
}

func pinPolicyBundleTrust(cfg *config.Config, trust config.PolicyBundleConfig) {
	signaturePath := cfg.PolicyBundle.SignaturePath
	cfg.PolicyBundle = trust
	cfg.PolicyBundle.SignaturePath = signaturePath
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

		compatActive := config.ApplyCompat(cfg, discardLogger)

		// Structural, not full, validation: this candidate arrived over the
		// network. The full validator opens the cert, key, and client CA that
		// listen.tls names and returns the os.PathError verbatim, which would
		// let a caller point a candidate at any absolute path and read back
		// whether it exists, is readable, and parses as PEM. See
		// config.ValidateStructural.
		compiled, compileErr := validateAndCompileRulesStructural(cfg)
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
		RedactContainerEnv:         cfg.Response.RedactContainerEnv,
		RedactMountPaths:           cfg.Response.RedactMountPaths,
		RedactNetworkTopology:      cfg.Response.RedactNetworkTopology,
		RedactSensitiveData:        cfg.Response.RedactSensitiveData,
		RedactHostTopology:         cfg.Response.RedactHostTopology,
		AllowAttestationStatements: cfg.Response.AllowAttestationStatements,
	}
}

func serveFilterOptions(cfg *config.Config, res *upstream.Resolver, clientProfiles map[string]filter.Policy) filter.Options {
	return filter.Options{
		PolicyConfig:   servePolicyConfig(cfg, res),
		Profiles:       clientProfiles,
		ResolveProfile: clientacl.RequestProfile,
		Mutation:       cfg.Mutations.ToFilterOptions(),
	}
}

func servePolicyConfig(cfg *config.Config, res *upstream.Resolver) filter.PolicyConfig {
	policy := cfg.RequestBody.ToFilterOptions()
	policy.DenyResponseVerbosity = filter.ParseDenyResponseVerbosity(cfg.Response.DenyVerbosity)
	return attachRuntimeInspectors(cfg, res, policy)
}

// withResourceLimitGuard returns the #152 post-ownership resource-limit guard
// layer (internal/filter/resource_limit_guard.go). It reuses the same
// PolicyConfig/profile map/ResolveProfile wiring servePolicyConfig and
// clientProfiles already provide to withFilter, plus two runtime inspectors
// (container/service state GETs) issued through the shared upstream resolver.
func withResourceLimitGuard(cfg *config.Config, res *upstream.Resolver, logger *slog.Logger, clientProfiles map[string]filter.Policy) func(http.Handler) http.Handler {
	warnIfResourceLimitRequireWithoutAllowResourceUpdates(cfg, logger)
	rt := upstreamResolverFor(res, cfg)
	return filter.ResourceLimitGuardWithOptions(logger, filter.ResourceLimitGuardOptions{
		PolicyConfig:     servePolicyConfig(cfg, res),
		Profiles:         clientProfiles,
		ResolveProfile:   clientacl.RequestProfile,
		InspectContainer: filter.NewDockerContainerUpdateInspectorWithRoundTripper(rt),
		InspectService:   filter.NewDockerServiceInspectorWithRoundTripper(rt),
	})
}

// resourceLimitRequireWarnOnce gates warnIfResourceLimitRequireWithoutAllowResourceUpdates
// to a single emission per process, like labelACLWarnOnce — the handler chain
// is rebuilt on every config hot-reload, so an unguarded warning at the
// chain-build site would repeat on each reload.
var resourceLimitRequireWarnOnce sync.Once

// warnIfResourceLimitRequireWithoutAllowResourceUpdates surfaces the likely-
// confusion case from ContainerUpdateRequestBodyConfig's doc comment: a
// require_* resource-limit flag enabled while allow_resource_updates is
// false is not a config error (the existing blanket deny already provides
// the guarantee those flags would otherwise add), but an operator who set
// require_memory_limit: true expecting it to do something almost certainly
// also meant to set allow_resource_updates: true.
func warnIfResourceLimitRequireWithoutAllowResourceUpdates(cfg *config.Config, logger *slog.Logger) {
	warnResourceLimitRequireOnce(cfg, logger, &resourceLimitRequireWarnOnce)
}

// warnResourceLimitRequireOnce is the testable core of
// warnIfResourceLimitRequireWithoutAllowResourceUpdates: the Once is injected
// so tests can verify both the enable-check and the once-per-process gating
// without racing other tests for the package-level guard.
func warnResourceLimitRequireOnce(cfg *config.Config, logger *slog.Logger, once *sync.Once) {
	misconfigured := resourceLimitRequireWithoutGate(cfg.RequestBody.ContainerUpdate)
	for _, profile := range cfg.Clients.Profiles {
		if resourceLimitRequireWithoutGate(profile.RequestBody.ContainerUpdate) {
			misconfigured = true
			break
		}
	}
	if !misconfigured {
		return
	}
	once.Do(func() {
		logger.Warn("request_body.container_update (default policy and/or one or more client profiles) has a require_* resource-limit flag enabled while allow_resource_updates is false: the flag is currently a no-op there — the existing blanket deny of resource-control fields already blocks every resource update, so set allow_resource_updates: true to activate the require_* check, or drop the require_* flag to avoid confusion")
	})
}

func resourceLimitRequireWithoutGate(cu config.ContainerUpdateRequestBodyConfig) bool {
	if cu.AllowResourceUpdates {
		return false
	}
	return cu.RequireMemoryLimit || cu.RequireCPULimit || cu.RequireCPULimitHard || cu.RequirePidsLimit
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
	// CIDR backstop (#21): a dedicated TCP admin listener must still honor the
	// listen-wide client CIDR allowlist the main listener enforces, otherwise
	// relocating admin to its own port silently drops the IP gate the struct
	// docs promise admin "inherits". Wrapped inside the audit/request-id/access
	// layers so a denial is still logged with full metadata, but outside the
	// admin endpoints so a disallowed IP never reaches the YAML validator.
	// Unix-socket admin listeners are owner-only and carry no meaningful client
	// IP, so the guard is TCP-only.
	if cfg.Admin.Listen.Address != "" {
		h = withAdminClientACL(cfg, logger)(h)
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

// warnIfAdminListenerWideOpen emits a startup warning when the dedicated admin
// listener is a non-loopback plaintext (non-mTLS) TCP listener with no client
// CIDR allowlist. In that configuration the admin endpoints — which accept YAML
// for parsing and expose policy metadata — are reachable by any host that can
// route to the port, with neither authentication nor an IP backstop (#21). The
// CIDR guard in buildAdminHandlerChain closes the gap when clients.allowed_cidrs
// is set. Config validation now rejects this shape outright unless
// admin.listen.insecure_allow_wide_open acknowledges it, so by the time this
// warning fires the operator has explicitly opted in — it keeps the exposure
// visible in the logs rather than gating startup.
func warnIfAdminListenerWideOpen(cfg *config.Config, logger *slog.Logger) {
	listen := cfg.Admin.Listen
	if listen.Address == "" || listen.TLS.Complete() {
		return
	}
	if config.IsLoopbackTCPAddress(listen.Address) {
		return
	}
	if len(cfg.Clients.AllowedCIDRs) > 0 {
		return
	}
	logger.Warn("admin listener is non-loopback plaintext TCP with no client CIDR allowlist: admin endpoints are reachable without authentication from any source IP — configure admin.listen.tls (mutual TLS) or clients.allowed_cidrs",
		"address", listen.Address,
	)
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
			name: "deny-verbosity",
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

// pathInterceptor short-circuits GET requests matching path to target,
// passing all other requests to next.
//
// Used for health and metrics endpoints, which both sit ahead of Docker-API
// filtering in the middleware chain and share identical dispatch logic.
func pathInterceptor(path string, target, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == path {
			target.ServeHTTP(w, r)
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
