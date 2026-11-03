package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// These helpers let the hijack tests drive the production dialer path
// (HijackHandlerWithDialer, handleHijackDialer, upgradeHijackConnectionDialer)
// while still injecting fake upstream connections through dialUpstreamHook.

// hijackInactivityTimeout is the 10 minute default of
// upstream.hijack_inactivity_timeout, passed explicitly by tests.
const hijackInactivityTimeout = 10 * time.Minute

// Test hook — do not use t.Parallel() in tests that swap this.
var dialUpstreamHook = func(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, hijackDialTimeout)
}

// hookDialer is an upstream.RequestDialer for a unix socket path that dials
// through dialUpstreamHook and leaves the request untouched.
type hookDialer struct{ socket string }

func (d hookDialer) DialRequest(_ context.Context, req *http.Request) (net.Conn, *http.Request, error) {
	conn, err := dialUpstreamHook("unix", d.socket)
	if err != nil {
		return nil, nil, err
	}
	return conn, req, nil
}

// HijackHandler is HijackHandlerWithDialer over a unix socket path.
func HijackHandler(upstreamSocket string, logger *slog.Logger, next http.Handler) http.Handler {
	return HijackHandlerWithDialer(hookDialer{socket: upstreamSocket}, hijackInactivityTimeout, logger, next)
}

func handleHijack(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) {
	handleHijackDialer(w, r, hookDialer{socket: upstreamSocket}, hijackInactivityTimeout, logger)
}

func upgradeHijackConnection(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) (*hijackSession, bool) {
	return upgradeHijackConnectionDialer(w, r, hookDialer{socket: upstreamSocket}, logger)
}

func writeHijackUpstreamRequest(upstreamConn net.Conn, w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {
	return writePreparedHijackUpstreamRequest(upstreamConn, w, r, newUpstreamHijackRequest(r, r.URL.Path), logger)
}

func isHijackEndpoint(method, path string) bool {
	return filter.IsHijackCandidatePath(method, filter.NormalizePath(path))
}
