package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/banner"
	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/version"
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
	cfg, err := loadServeConfigWithOverrides(cmd, deps)
	if err != nil {
		return err
	}

	logger, closeLogOutput, err := openServeLogger(cmd, cfg, deps)
	if err != nil {
		return err
	}
	defer closeLogOutput()

	rules, err := compileServeRules(cfg, logger, deps)
	if err != nil {
		return err
	}
	if err := deps.verifyUpstreamReachable(cfg.Upstream.Socket, logger); err != nil {
		return err
	}

	handler := buildServeHandler(cfg, logger, rules, deps)
	ln, err := deps.createServeListener(cfg)
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	defer closeServeListener(logger, ln)

	server := newHTTPServer(handler)
	logServeStartup(cmd, cfg, logger)

	if err := serveUntilShutdown(server, ln, logger, deps); err != nil {
		return err
	}

	cleanupServeSocket(cfg, logger, deps)
	logger.Info("sockguard stopped")
	return nil
}

func loadServeConfigWithOverrides(cmd *cobra.Command, deps *serveDeps) (*config.Config, error) {
	cfg, err := deps.loadConfig(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	if err := applyFlagOverrides(cmd, cfg); err != nil {
		return nil, fmt.Errorf("apply flag overrides: %w", err)
	}
	return cfg, nil
}

func openServeLogger(cmd *cobra.Command, cfg *config.Config, deps *serveDeps) (*slog.Logger, func(), error) {
	logger, logOutputCloser, err := deps.newLogger(cfg.Log.Level, cfg.Log.Format, cfg.Log.Output)
	if err != nil {
		return nil, nil, fmt.Errorf("logger: %w", err)
	}

	closeLogOutput := func() {
		if logOutputCloser == nil {
			return
		}
		if closeErr := logOutputCloser.Close(); closeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to close log output: %v\n", closeErr)
		}
	}

	return logger, closeLogOutput, nil
}

func compileServeRules(cfg *config.Config, logger *slog.Logger, deps *serveDeps) ([]*filter.CompiledRule, error) {
	// Tecnativa compatibility mode expands legacy env vars like CONTAINERS=1
	// into explicit allow/deny rules before normal validation and compilation.
	config.ApplyCompat(cfg, logger)

	rules, err := deps.validateRules(cfg)
	if err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return rules, nil
}

func buildServeHandler(cfg *config.Config, logger *slog.Logger, rules []*filter.CompiledRule, deps *serveDeps) http.Handler {
	upstream := proxy.New(cfg.Upstream.Socket, logger)
	var handler http.Handler = upstream

	// Hijack handler: intercepts attach/exec endpoints for native bidirectional
	// streaming with optimized buffers and TCP half-close signaling.
	handler = proxy.HijackHandler(cfg.Upstream.Socket, logger, handler)

	handler = filter.MiddlewareWithOptions(rules, logger, filter.Options{
		DenyResponseVerbosity: filter.DenyResponseVerbosity(cfg.Response.DenyVerbosity),
	})(handler)

	if cfg.Health.Enabled {
		startTime := deps.now()
		healthHandler := health.Handler(cfg.Upstream.Socket, startTime, logger)
		handler = healthInterceptor(cfg.Health.Path, healthHandler, handler)
	}

	if cfg.Log.AccessLog {
		handler = logging.AccessLogMiddleware(logger)(handler)
	}

	return handler
}

func closeServeListener(logger *slog.Logger, ln net.Listener) {
	if closeErr := ln.Close(); closeErr != nil {
		logger.Warn("failed to close listener", "error", closeErr)
	}
}

func logServeStartup(cmd *cobra.Command, cfg *config.Config, logger *slog.Logger) {
	warnOnInsecureRemoteTCPBind(logger, cfg)
	banner.Render(cmd.ErrOrStderr(), banner.Info{
		Listen:    listenerAddr(cfg),
		Upstream:  cfg.Upstream.Socket,
		Rules:     len(cfg.Rules),
		LogFormat: cfg.Log.Format,
		LogLevel:  cfg.Log.Level,
		AccessLog: cfg.Log.AccessLog,
	})
	logger.Info("sockguard started",
		"version", version.Version,
		"listen", listenerAddr(cfg),
		"upstream", cfg.Upstream.Socket,
		"rules", len(cfg.Rules),
		"log_level", cfg.Log.Level,
	)
}

func serveUntilShutdown(server *http.Server, ln net.Listener, logger *slog.Logger, deps *serveDeps) error {
	errCh := make(chan error, 1)
	go deps.startServing(server, ln, errCh)

	if err := waitForServeStop(errCh, logger, deps); err != nil {
		return err
	}

	shutdownServeServer(server, logger, deps)
	return nil
}

func waitForServeStop(errCh <-chan error, logger *slog.Logger, deps *serveDeps) error {
	sigCh := make(chan os.Signal, 1)
	deps.notifySignals(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

func shutdownServeServer(server *http.Server, logger *slog.Logger, deps *serveDeps) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.shutdownGracePeriod)
	defer cancel()

	if err := deps.shutdownServer(server, shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
}

func cleanupServeSocket(cfg *config.Config, logger *slog.Logger, deps *serveDeps) {
	if cfg.Listen.Socket != "" {
		if err := deps.removePath(cfg.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "socket", cfg.Listen.Socket, "error", err)
		}
	}
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler,
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

func isWildcardTCPBind(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
