package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/health"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/proxy"
	"github.com/codeswhat/sockguard/internal/version"
)

const readHeaderTimeout = 5 * time.Second

var (
	umaskMu      sync.Mutex
	syscallUmask = syscall.Umask

	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the proxy server",
		Long:  "Start the sockguard proxy, listening for Docker API requests and filtering them according to configured rules.",
		RunE:  runServe,
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("listen-socket", "", "proxy socket path (overrides config)")
	serveCmd.Flags().String("upstream-socket", "", "Docker socket path (overrides config)")
	serveCmd.Flags().String("log-level", "", "log level (overrides config)")
	serveCmd.Flags().String("log-format", "", "log format (overrides config)")
	serveCmd.Flags().String("deny-response-verbosity", "", "deny response verbosity: verbose or minimal (overrides config)")
}

func runServe(cmd *cobra.Command, args []string) error {
	// 1. Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	// 2. Apply CLI flag overrides
	if err := applyFlagOverrides(cmd, cfg); err != nil {
		return fmt.Errorf("apply flag overrides: %w", err)
	}

	// 3. Create logger
	logger, logOutputCloser, err := logging.New(cfg.Log.Level, cfg.Log.Format, cfg.Log.Output)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	if logOutputCloser != nil {
		defer func() {
			if closeErr := logOutputCloser.Close(); closeErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to close log output: %v\n", closeErr)
			}
		}()
	}

	// 4. Tecnativa compat
	config.ApplyCompat(cfg, logger)

	// 5. Validate and compile rules
	rules, err := config.ValidateAndCompile(cfg)
	if err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	// 6. Verify upstream reachable
	conn, err := net.DialTimeout("unix", cfg.Upstream.Socket, 5*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("upstream socket not found (%s): %w", cfg.Upstream.Socket, err)
		case errors.Is(err, os.ErrPermission):
			return fmt.Errorf("permission denied on upstream socket (%s): %w", cfg.Upstream.Socket, err)
		default:
			return fmt.Errorf("upstream socket unreachable (%s): %w", cfg.Upstream.Socket, err)
		}
	}
	if closeErr := conn.Close(); closeErr != nil {
		logger.Debug("failed to close upstream check connection", "error", closeErr)
	}

	// 7. Build handler chain (inside-out)
	upstream := proxy.New(cfg.Upstream.Socket, logger)
	var handler http.Handler = upstream

	// Hijack handler: intercepts attach/exec endpoints for native bidirectional
	// streaming with optimized buffers and TCP half-close signaling.
	handler = proxy.HijackHandler(cfg.Upstream.Socket, logger, handler)

	// Rule evaluator
	handler = filter.MiddlewareWithOptions(rules, logger, filter.Options{
		DenyResponseVerbosity: filter.DenyResponseVerbosity(cfg.Response.DenyVerbosity),
	})(handler)

	// Health interceptor
	if cfg.Health.Enabled {
		startTime := time.Now()
		healthHandler := health.Handler(cfg.Upstream.Socket, startTime, logger)
		handler = healthInterceptor(cfg.Health.Path, healthHandler, handler)
	}

	// Access logger
	if cfg.Log.AccessLog {
		handler = logging.AccessLogMiddleware(logger)(handler)
	}

	// 8. Create listener
	ln, err := createListener(cfg)
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			logger.Warn("failed to close listener", "error", closeErr)
		}
	}()

	// 9. Start server
	server := newHTTPServer(handler)

	// 10. Log startup summary
	logger.Info("sockguard started",
		"version", version.Version,
		"listen", listenerAddr(cfg),
		"upstream", cfg.Upstream.Socket,
		"rules", len(cfg.Rules),
		"log_level", cfg.Log.Level,
	)

	// Start serving in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()

	// 11. Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	// 12. Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}

	// Remove socket file
	if cfg.Listen.Socket != "" {
		if err := os.Remove(cfg.Listen.Socket); err != nil && !os.IsNotExist(err) {
			logger.Error("remove socket error", "socket", cfg.Listen.Socket, "error", err)
		}
	}

	logger.Info("sockguard stopped")
	return nil
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler,
		// Docker attach/logs/events can hold request/response bodies open for long periods.
		// A non-zero ReadTimeout breaks those streaming APIs, so we intentionally leave it disabled.
		// ReadHeaderTimeout still bounds header parsing time, which partially mitigates slowloris
		// attacks on TCP listeners without affecting long-lived upgraded/streaming requests.
		ReadTimeout:       0,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}

// applyFlagOverrides applies CLI flags that were explicitly set.
func applyFlagOverrides(cmd *cobra.Command, cfg *config.Config) error {
	if err := applyStringFlagOverride(cmd, "listen-socket", func(v string) {
		cfg.Listen.Socket = v
	}); err != nil {
		return err
	}
	if err := applyStringFlagOverride(cmd, "upstream-socket", func(v string) {
		cfg.Upstream.Socket = v
	}); err != nil {
		return err
	}
	if err := applyStringFlagOverride(cmd, "log-level", func(v string) {
		cfg.Log.Level = v
	}); err != nil {
		return err
	}
	if err := applyStringFlagOverride(cmd, "log-format", func(v string) {
		cfg.Log.Format = v
	}); err != nil {
		return err
	}
	if err := applyStringFlagOverride(cmd, "deny-response-verbosity", func(v string) {
		cfg.Response.DenyVerbosity = v
	}); err != nil {
		return err
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
func createListener(cfg *config.Config) (net.Listener, error) {
	if cfg.Listen.Socket != "" {
		mode, err := strconv.ParseUint(cfg.Listen.SocketMode, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid socket_mode %q: %w", cfg.Listen.SocketMode, err)
		}

		ln, err := listenUnixSocket(cfg.Listen.Socket, os.FileMode(mode))
		if err != nil {
			return nil, err
		}

		return ln, nil
	}

	// Fall back to TCP
	return net.Listen("tcp", cfg.Listen.Address)
}

func listenUnixSocket(path string, mode os.FileMode) (net.Listener, error) {
	return withUmask(socketCreateUmask(mode), func() (net.Listener, error) {
		ln, err := net.Listen("unix", path)
		if err == nil {
			return ln, nil
		}
		if !isAddrInUse(err) {
			return nil, err
		}

		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, fmt.Errorf("socket path already in use and could not inspect %q: %w", path, statErr)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %q exists and is not a socket", path)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			if !os.IsNotExist(removeErr) {
				return nil, fmt.Errorf("remove stale socket: %w", removeErr)
			}
		}

		ln, err = net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		return ln, nil
	})
}

func socketCreateUmask(mode os.FileMode) int {
	return int(0o777 &^ mode.Perm())
}

func withUmask(mask int, fn func() (net.Listener, error)) (net.Listener, error) {
	umaskMu.Lock()
	defer umaskMu.Unlock()

	previous := syscallUmask(mask)
	defer syscallUmask(previous)

	return fn()
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
	return "tcp:" + cfg.Listen.Address
}
