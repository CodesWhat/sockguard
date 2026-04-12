package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

type serveDeps struct {
	loadConfig          func(string) (*config.Config, error)
	newLogger           func(string, string, string) (*slog.Logger, io.Closer, error)
	validateRules       func(*config.Config) ([]*filter.CompiledRule, error)
	dialUpstream        func(string, string, time.Duration) (net.Conn, error)
	listenNetwork       func(string, string) (net.Listener, error)
	lstatPath           func(string) (os.FileInfo, error)
	isAddrInUse         func(error) bool
	createServeListener func(*config.Config) (net.Listener, error)
	notifySignals       func(chan<- os.Signal, ...os.Signal)
	startServing        func(*http.Server, net.Listener, chan<- error)
	shutdownServer      func(*http.Server, context.Context) error
	removePath          func(string) error
	now                 func() time.Time
	shutdownGracePeriod time.Duration
	umask               func(int) int
	umaskMu             *sync.Mutex
}

var processUmaskMu sync.Mutex

func newServeDeps() *serveDeps {
	deps := &serveDeps{
		loadConfig:          config.Load,
		newLogger:           logging.New,
		validateRules:       validateAndCompileRules,
		dialUpstream:        net.DialTimeout,
		listenNetwork:       net.Listen,
		lstatPath:           os.Lstat,
		isAddrInUse:         isAddrInUse,
		notifySignals:       signal.Notify,
		startServing:        defaultServeStart,
		shutdownServer:      defaultServeShutdown,
		removePath:          os.Remove,
		now:                 time.Now,
		shutdownGracePeriod: 30 * time.Second,
		umask:               syscall.Umask,
		umaskMu:             &processUmaskMu,
	}
	deps.createServeListener = deps.createListener
	return deps
}

func defaultServeStart(server *http.Server, ln net.Listener, errCh chan<- error) {
	errCh <- server.Serve(ln)
}

func defaultServeShutdown(server *http.Server, ctx context.Context) error {
	return server.Shutdown(ctx)
}

func createListener(cfg *config.Config) (net.Listener, error) {
	return newServeDeps().createListener(cfg)
}

func listenUnixSocket(path string, mode os.FileMode) (net.Listener, error) {
	return newServeDeps().listenUnixSocket(path, mode)
}

func withUmask(mask int, fn func() (net.Listener, error)) (net.Listener, error) {
	return newServeDeps().withUmask(mask, fn)
}

func verifyUpstreamReachable(upstreamSocket string, logger *slog.Logger) error {
	return newServeDeps().verifyUpstreamReachable(upstreamSocket, logger)
}

func (d *serveDeps) verifyUpstreamReachable(upstreamSocket string, logger *slog.Logger) error {
	conn, err := d.dialUpstream("unix", upstreamSocket, 5*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("upstream socket not found (%s): %w", upstreamSocket, err)
		case errors.Is(err, os.ErrPermission):
			return fmt.Errorf("permission denied on upstream socket (%s): %w", upstreamSocket, err)
		default:
			return fmt.Errorf("upstream socket unreachable (%s): %w", upstreamSocket, err)
		}
	}
	if closeErr := conn.Close(); closeErr != nil {
		logger.Debug("failed to close upstream check connection", "error", closeErr)
	}
	return nil
}

func (d *serveDeps) createListener(cfg *config.Config) (net.Listener, error) {
	if cfg.Listen.Socket != "" {
		mode, err := strconv.ParseUint(cfg.Listen.SocketMode, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid socket_mode %q: %w", cfg.Listen.SocketMode, err)
		}

		return d.listenUnixSocket(cfg.Listen.Socket, os.FileMode(mode))
	}

	ln, err := d.listenNetwork("tcp", cfg.Listen.Address)
	if err != nil {
		return nil, err
	}
	if !cfg.Listen.TLS.Complete() {
		return ln, nil
	}

	tlsConfig, err := config.BuildMutualTLSServerConfig(cfg.Listen.TLS)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return tls.NewListener(ln, tlsConfig), nil
}

func (d *serveDeps) listenUnixSocket(path string, mode os.FileMode) (net.Listener, error) {
	return d.withUmask(socketCreateUmask(mode), func() (net.Listener, error) {
		ln, err := d.listenNetwork("unix", path)
		if err == nil {
			return ln, nil
		}
		if !d.isAddrInUse(err) {
			return nil, err
		}

		info, statErr := d.lstatPath(path)
		if statErr != nil {
			return nil, fmt.Errorf("socket path already in use and could not inspect %q: %w", path, statErr)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket path %q exists and is not a socket", path)
		}
		if removeErr := d.removePath(path); removeErr != nil {
			if !os.IsNotExist(removeErr) {
				return nil, fmt.Errorf("remove stale socket: %w", removeErr)
			}
		}

		ln, err = d.listenNetwork("unix", path)
		if err != nil {
			return nil, err
		}
		return ln, nil
	})
}

func (d *serveDeps) withUmask(mask int, fn func() (net.Listener, error)) (net.Listener, error) {
	d.umaskMu.Lock()
	defer d.umaskMu.Unlock()

	previous := d.umask(mask)
	ln, err := fn()
	d.umask(previous)

	return ln, err
}
