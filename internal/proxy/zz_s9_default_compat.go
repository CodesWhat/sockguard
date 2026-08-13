package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"

	"github.com/codeswhat/sockguard/internal/responsefilter"
	"github.com/codeswhat/sockguard/internal/upstream"
	"io"
	"log/slog"

	"net"
	"net/http"

	"net/http/httputil"

	"net/textproto"
	"net/url"
	"strings"

	"sync"
	"time"
)

// hijackBufSize is the buffer size for bidirectional copy on hijacked connections.
// 64KB balances throughput with memory use for Docker's streaming protocols.
const hijackBufSize = 64 * 1024

const hijackDialTimeout = 5 * time.Second
const hijackInactivityTimeout = 10 * time.Minute

type bytePool interface {
	Get() any
	Put(any)
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

var hijackBufferPool bytePool = &sync.Pool{
	New: func() any {
		return make([]byte, hijackBufSize)
	},
}

// Test hook — do not use t.Parallel() in tests that swap this.
var dialUpstreamWithTimeoutHook func(string, string, time.Duration) (net.Conn, error) = net.DialTimeout

// Test hook — do not use t.Parallel() in tests that swap this.
var dialUpstreamHook = func(network, address string) (net.Conn, error) {
	return dialUpstreamWithTimeoutHook(network, address, hijackDialTimeout)
}

// Test hook — do not use t.Parallel() in tests that swap this.
var readResponseHook func(*bufio.Reader, *http.Request) (*http.Response, error) = http.ReadResponse

// Test hook — do not use t.Parallel() in tests that swap this.
var copyBufferHook func(io.Writer, io.Reader, []byte) (int64, error) = io.CopyBuffer

// Test hook — do not use t.Parallel() in tests that swap this.
var timeNowHook func() time.Time = time.Now

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type hijackSession struct {
	path         string
	upstreamConn net.Conn
	upstreamBuf  *bufio.Reader
	clientConn   net.Conn
	clientBuf    *bufio.ReadWriter
}

type hijackCopyStream struct {
	direction      string
	src            io.Reader
	readConn       readDeadlineSetter
	dst            io.Writer
	writeConn      writeDeadlineSetter
	closeConnOnEOF net.Conn
}

type hijackUpgradeState struct {
	resp         *http.Response
	upstreamConn net.Conn
	upstreamBuf  *bufio.Reader
	path         string
}

// HijackHandler wraps a standard handler and intercepts Docker API endpoints
// that use HTTP connection upgrades (attach, exec start). For these endpoints,
// it dials the upstream Docker socket directly and performs a native bidirectional
// hijack with optimized buffers and proper TCP half-close signaling, rather than
// relying on the stdlib reverse proxy's generic upgrade handling.
func HijackHandler(upstreamSocket string, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHijackRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		handleHijack(w, r, upstreamSocket, logger)
	})
}

// HijackHandlerWithDialer is HijackHandler over an upstream.Dialer (typically an
// *upstream.Resolver), so the hijack path dials the same active endpoint — local
// socket or remote TCP+TLS — and fails over together with the rest of the proxy.
func HijackHandlerWithDialer(dialer upstream.Dialer, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHijackRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		handleHijackDialer(w, r, dialer, logger)
	})
}

// isHijackEndpoint returns true if the request targets a Docker API endpoint
// that upgrades to a raw TCP stream via 101 Switching Protocols.
//
// Matched endpoints:
//   - POST /containers/{id}/attach
//   - POST /exec/{id}/start
//   - POST /libpod/containers/{id}/attach (Podman's native libpod API, #148)
//   - POST /libpod/exec/{id}/start
//
// Docker API version prefixes (/v1.XX/, or Podman's three-part /v5.0.0/) are
// stripped before matching.
func isHijackEndpoint(method, path string) bool {
	return isHijackEndpointNormalized(method, filter.NormalizePath(path))
}

func isHijackRequest(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	return isHijackEndpointNormalized(r.Method, requestHijackPath(w, r))
}

func requestHijackPath(w http.ResponseWriter, r *http.Request) string {
	if r == nil {
		return ""
	}
	if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
		return meta.NormPath
	}
	return filter.NormalizePath(r.URL.Path)
}

func isHijackEndpointNormalized(method, path string) bool {
	if method != http.MethodPost {
		return false
	}

	p, ok := strings.CutPrefix(path, "/")
	if !ok {
		return false
	}

	p, _ = strings.CutPrefix(p, "libpod/")

	resource, remainder, ok := strings.Cut(p, "/")
	if !ok || resource == "" {
		return false
	}

	_, action, ok := strings.Cut(remainder, "/")
	if !ok || action == "" || strings.Contains(action, "/") {
		return false
	}

	return (resource == "containers" && action == "attach") ||
		(resource == "exec" && action == "start")
}

func writeHijackBadGateway(w http.ResponseWriter, logger *slog.Logger, path, message string) {
	if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
		Message: message,
	}); encErr != nil {
		logger.Warn("hijack: failed to encode error response", "error", logging.SafeString(encErr.Error()), "path", logging.SafeString(path))
	}
}

func handleHijack(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) {
	session, ok := upgradeHijackConnection(w, r, upstreamSocket, logger)
	if !ok {
		return
	}

	proxyHijackStreams(session, logger)
}

func handleHijackDialer(w http.ResponseWriter, r *http.Request, dialer upstream.Dialer, logger *slog.Logger) {
	session, ok := upgradeHijackConnectionDialer(w, r, dialer, logger)
	if !ok {
		return
	}

	proxyHijackStreams(session, logger)
}

func upgradeHijackConnection(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	upstreamConn, err := dialUpstreamHook("unix", upstreamSocket)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		writeHijackBadGateway(w, logger, reqPath, "upstream Docker socket unreachable")
		return nil, false
	}

	return finishHijackUpgrade(w, r, upstreamConn, logger)
}

// upgradeHijackConnectionDialer is upgradeHijackConnection over an
// upstream.Dialer: it dials the active endpoint (local or remote TCP+TLS) with
// the same bounded dial timeout, then shares the post-dial upgrade logic.
func upgradeHijackConnectionDialer(w http.ResponseWriter, r *http.Request, dialer upstream.Dialer, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	ctx, cancel := context.WithTimeout(context.Background(), hijackDialTimeout)
	defer cancel()
	upstreamConn, err := dialer.DialContext(ctx, "", "")
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		writeHijackBadGateway(w, logger, reqPath, "upstream Docker socket unreachable")
		return nil, false
	}

	return finishHijackUpgrade(w, r, upstreamConn, logger)
}

// finishHijackUpgrade performs the request write, response read, and 101-upgrade
// finalization shared by the socket and dialer hijack paths once the upstream
// connection is established.
func finishHijackUpgrade(w http.ResponseWriter, r *http.Request, upstreamConn net.Conn, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	if !writeHijackUpstreamRequest(upstreamConn, w, r, logger) {
		return nil, false
	}

	upstreamBuf, resp, ok := readHijackUpstreamResponse(upstreamConn, w, r, logger)
	if !ok {
		return nil, false
	}

	ok = false
	var session *hijackSession
	if resp.StatusCode == http.StatusSwitchingProtocols {
		session, ok = finalizeHijackUpgrade(w, logger, hijackUpgradeState{
			resp:         resp,
			upstreamConn: upstreamConn,
			upstreamBuf:  upstreamBuf,
			path:         reqPath,
		})
		if ok {
			logger.Debug("hijack: connection upgraded", "path", logging.SafeString(reqPath))
		}
	} else {
		writeNonUpgradeHijackResponse(w, resp, upstreamConn, logger, reqPath)
	}

	return session, ok
}

func proxyHijackStreams(session *hijackSession, logger *slog.Logger) {
	// Bidirectional copy with proper half-close signaling.
	// When one direction reaches EOF, we signal the other side via CloseWrite
	// so it knows no more data is coming (critical for stdin EOF → container stop).
	var wg sync.WaitGroup
	wg.Add(2)

	reqPath := session.path

	startHijackCopy(
		&wg,
		logger,
		reqPath,
		hijackCopyStream{
			direction:      "upstream→client",
			src:            session.upstreamBuf,
			readConn:       session.upstreamConn,
			dst:            session.clientConn,
			writeConn:      session.clientConn,
			closeConnOnEOF: session.clientConn,
		},
	)
	startHijackCopy(
		&wg,
		logger,
		reqPath,
		hijackCopyStream{
			direction:      "client→upstream",
			src:            session.clientBuf,
			readConn:       session.clientConn,
			dst:            session.upstreamConn,
			writeConn:      session.upstreamConn,
			closeConnOnEOF: session.upstreamConn,
		},
	)

	wg.Wait()
	closeConn(logger, session.clientConn, "client connection", reqPath)
	closeConn(logger, session.upstreamConn, "upstream connection", reqPath)
	logger.Debug("hijack: connection closed", "path", logging.SafeString(reqPath))
}

func writeHijackUpstreamRequest(upstreamConn net.Conn, w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {

	logPath := requestHijackPath(w, r)
	upstreamReq := newUpstreamHijackRequest(r, r.URL.Path)
	if err := upstreamReq.Write(upstreamConn); err != nil {
		closeConn(logger, upstreamConn, "upstream connection", logPath)
		logger.Error("hijack: write request to upstream failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath))
		writeHijackBadGateway(w, logger, logPath, "failed to forward request to upstream")
		return false
	}

	return true
}

func readHijackUpstreamResponse(
	upstreamConn net.Conn,
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
) (*bufio.Reader, *http.Response, bool) {

	upstreamBuf := bufio.NewReaderSize(upstreamConn, hijackBufSize)
	resp, err := readResponseHook(upstreamBuf, r)
	if err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: read upstream response failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(r.URL.Path))
		writeHijackBadGateway(w, logger, r.URL.Path, "failed to read upstream response")
		return nil, nil, false
	}

	return upstreamBuf, resp, true
}

func writeNonUpgradeHijackResponse(
	w http.ResponseWriter,
	resp *http.Response,
	upstreamConn net.Conn,
	logger *slog.Logger,
	path string,
) {

	defer closeConn(logger, upstreamConn, "upstream connection", path)

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body == nil {
		return
	}
	buf := getHijackBuffer()
	defer putHijackBuffer(buf)
	if _, err := io.CopyBuffer(w, resp.Body, buf); err != nil {
		logger.Debug("hijack: error copying non-upgrade response body", "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
	if err := resp.Body.Close(); err != nil {
		logger.Debug("hijack: error closing non-upgrade response body", "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
}

// finalizeHijackUpgrade writes the upstream's 101 response to the hijacked
// client connection verbatim — INCLUDING Connection/Upgrade and any other
// hop-by-hop headers. That is deliberate, not an oversight next to the
// hop-by-hop stripping on the non-upgrade path (writeNonUpgradeHijackResponse):
// a 101 Switching Protocols response is only valid with `Connection: Upgrade`
// and `Upgrade: tcp` present, and after the hijack this is a raw byte tunnel
// with no next hop those headers could confuse.
func finalizeHijackUpgrade(w http.ResponseWriter, logger *slog.Logger, state hijackUpgradeState) (*hijackSession, bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: ResponseWriter does not implement http.Hijacker", "path", logging.SafeString(state.path))
		return nil, false
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: client hijack failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(state.path))
		return nil, false
	}

	if err := state.resp.Write(clientBuf); err != nil {
		closeConn(logger, clientConn, "client connection", state.path)
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: write 101 to client failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(state.path))
		return nil, false
	}
	if err := clientBuf.Flush(); err != nil {
		closeConn(logger, clientConn, "client connection", state.path)
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: flush 101 to client failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(state.path))
		return nil, false
	}

	return &hijackSession{
		path:         state.path,
		upstreamConn: state.upstreamConn,
		upstreamBuf:  state.upstreamBuf,
		clientConn:   clientConn,
		clientBuf:    clientBuf,
	}, true
}

func startHijackCopy(
	wg *sync.WaitGroup,
	logger *slog.Logger,
	reqPath string,
	stream hijackCopyStream,
) {
	go func() {
		defer wg.Done()
		buf := getHijackBuffer()
		defer putHijackBuffer(buf)

		defer closeWrite(stream.closeConnOnEOF)
		defer func() {
			if v := recover(); v != nil {
				logger.Error("hijack: copy panic", "direction", logging.SafeString(stream.direction), "panic", logging.SafeString(fmt.Sprint(v)), "path", logging.SafeString(reqPath))
			}
		}()

		reader := withReadInactivityDeadline(stream.src, stream.readConn, hijackInactivityTimeout)
		writer := withWriteInactivityDeadline(stream.dst, stream.writeConn, hijackInactivityTimeout)
		if _, err := copyBufferHook(writer, reader, buf); err != nil {
			logger.Debug("hijack: copy ended", "direction", logging.SafeString(stream.direction), "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		}
	}()
}

func newUpstreamHijackRequest(r *http.Request, path string) *http.Request {
	rawQuery := ""
	rawPath := ""
	if path == "" && r.URL != nil {

		path = r.URL.Path
	}
	if r.URL != nil {

		rawQuery = r.URL.RawQuery

		if path == r.URL.Path {
			rawPath = r.URL.RawPath
		}
	}

	upstreamReq := &http.Request{
		Method:        r.Method,
		Host:          "docker",
		URL:           &url.URL{Scheme: "http", Host: "docker", Path: path, RawPath: rawPath, RawQuery: rawQuery},
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        r.Header.Clone(),
		Body:          r.Body,
		ContentLength: r.ContentLength,
	}
	if upstreamReq.ContentLength == 0 {
		upstreamReq.Body = nil
	}

	removeHopByHopHeaders(upstreamReq.Header)
	upstreamReq.TransferEncoding = nil
	upstreamReq.Trailer = nil
	upstreamReq.Close = false
	upstreamReq.Header.Set("Connection", "Upgrade")
	upstreamReq.Header.Set("Upgrade", "tcp")

	return upstreamReq
}

func removeHopByHopHeaders(h http.Header) {
	for _, value := range h["Connection"] {
		for token := range strings.SplitSeq(value, ",") {
			if token = textproto.TrimString(token); token != "" {
				h.Del(token)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

type inactivityDeadlineReader struct {
	reader          io.Reader
	conn            readDeadlineSetter
	timeout         time.Duration
	refreshInterval time.Duration
	lastRefresh     time.Time
}

func withReadInactivityDeadline(reader io.Reader, conn readDeadlineSetter, timeout time.Duration) io.Reader {
	return &inactivityDeadlineReader{
		reader:          reader,
		conn:            conn,
		timeout:         timeout,
		refreshInterval: timeout / 4,
	}
}

func (r *inactivityDeadlineReader) Read(p []byte) (int, error) {
	now := timeNowHook()
	if r.lastRefresh.IsZero() || now.Sub(r.lastRefresh) > r.refreshInterval {
		if err := r.conn.SetReadDeadline(now.Add(r.timeout)); err != nil {
			return 0, err
		}
		r.lastRefresh = now
	}
	return r.reader.Read(p)
}

type inactivityDeadlineWriter struct {
	writer          io.Writer
	conn            writeDeadlineSetter
	timeout         time.Duration
	refreshInterval time.Duration
	lastRefresh     time.Time
}

func withWriteInactivityDeadline(writer io.Writer, conn writeDeadlineSetter, timeout time.Duration) io.Writer {
	return &inactivityDeadlineWriter{
		writer:          writer,
		conn:            conn,
		timeout:         timeout,
		refreshInterval: timeout / 4,
	}
}

func (w *inactivityDeadlineWriter) Write(p []byte) (int, error) {
	now := timeNowHook()
	if w.lastRefresh.IsZero() || now.Sub(w.lastRefresh) > w.refreshInterval {
		if err := w.conn.SetWriteDeadline(now.Add(w.timeout)); err != nil {
			return 0, err
		}
		w.lastRefresh = now
	}
	return w.writer.Write(p)
}

func getHijackBuffer() []byte {
	buf, ok := hijackBufferPool.Get().([]byte)
	if !ok || cap(buf) < hijackBufSize {
		return make([]byte, hijackBufSize)
	}
	return buf[:hijackBufSize]
}

func putHijackBuffer(buf []byte) {
	if cap(buf) < hijackBufSize {
		return
	}
	buf = buf[:hijackBufSize]
	clear(buf)
	hijackBufferPool.Put(buf)
}

// closeWrite performs a TCP/Unix half-close, signaling no more data will be sent
// while still allowing reads from the other direction.
func closeWrite(c net.Conn) {
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.(halfCloser); ok {

		_ = hc.CloseWrite()
	}
}

func closeConn(logger *slog.Logger, conn net.Conn, label, path string) {
	if err := conn.Close(); err != nil {
		logger.Debug(logging.SafeString("hijack: failed to close "+label), "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
}

const (
	reasonCodeUpstreamSocketUnreachable = "upstream_socket_unreachable"
	reasonCodeUpstreamResponseRejected  = "upstream_response_rejected_by_policy"
	reasonCodeUpstreamRequestTimeout    = "upstream_request_timeout"
)

// Options configures reverse-proxy behavior beyond the fixed upstream socket.
type Options struct {
	ModifyResponse func(*http.Response) error
}

// NewWithOptions creates a reverse proxy that forwards requests to the upstream
// Docker socket and optionally enforces response-side policy. It is the
// single-local-socket shorthand: callers with a plain socket path get a
// one-endpoint resolver. The multi-endpoint/remote path uses NewWithTransport.
func NewWithOptions(upstreamSocket string, logger *slog.Logger, opts Options) *httputil.ReverseProxy {
	return NewWithTransport(upstream.NewSingleSocket(upstreamSocket), logger, opts)
}

// NewWithTransport creates a reverse proxy that forwards requests through rt —
// typically an *upstream.Resolver, which owns endpoint selection, per-endpoint
// connection pooling (MaxIdleConns 100, IdleConnTimeout 90s, ResponseHeader
// timeout 30s, matching the historical single-socket transport), client TLS,
// and automatic failover. Streaming endpoints (logs follow, events, stats) send
// headers promptly and stream the body, so the header timeout does not cap
// long-lived responses; hijacked attach/exec-start connections bypass this
// pooled transport entirely.
func NewWithTransport(rt http.RoundTripper, logger *slog.Logger, opts Options) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
		},
		Transport:      rt,
		ModifyResponse: opts.ModifyResponse,
		FlushInterval:  -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
			attrs = append(attrs, slog.String("error", logging.SafeString(err.Error())))
			logger.LogAttrs(r.Context(), slog.LevelError, "upstream request failed", attrs...)

			message := "upstream Docker socket unreachable"
			reasonCode := reasonCodeUpstreamSocketUnreachable
			status := http.StatusBadGateway
			switch {
			case errors.Is(err, responsefilter.ErrResponseRejected):
				message = "upstream Docker response rejected by sockguard policy"
				reasonCode = reasonCodeUpstreamResponseRejected
			case errors.Is(err, context.DeadlineExceeded):

				message = "upstream request timed out"
				reasonCode = reasonCodeUpstreamRequestTimeout
				status = http.StatusGatewayTimeout
			}
			if meta := logging.MetaForRequest(w, r); meta != nil {
				meta.ReasonCode = reasonCode
				meta.Reason = message
			}

			if encErr := httpjson.Write(w, status, httpjson.ErrorResponse{Message: message}); encErr != nil {
				attrs := logging.AppendCorrelationAttrsForResponseWriter(nil, r, w)
				attrs = append(attrs, slog.String("error", logging.SafeString(encErr.Error())))
				logger.LogAttrs(r.Context(), slog.LevelWarn, "failed to encode error response", attrs...)
			}
		},
	}
}

// WithRequestTimeout wraps next so that ordinary finite upstream requests are
// bounded by a total per-request deadline. When the deadline fires, the proxy
// transport aborts the upstream connection and the ReverseProxy ErrorHandler
// returns a 504 (reasonCodeUpstreamRequestTimeout). This is the body-phase
// backstop that ResponseHeaderTimeout cannot provide: a daemon that sends
// headers promptly and then hangs the body would otherwise pin the request
// until the client gives up.
//
// A non-positive timeout disables the wrapper entirely — next is returned
// unchanged. Long-lived endpoints (event streams, follow/stream reads, image
// pull/build/push, plugin create/pull/push/upgrade, container export/get, container
// archive i.e. docker cp, websocket attach, and the blocking container wait)
// are exempt, because a deadline would sever a legitimately long response.
// Hijacked endpoints
// (attach, exec start) never reach this handler: HijackHandler short-circuits
// them earlier in the chain.
func WithRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLongLivedUpstreamRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isLongLivedUpstreamRequest reports whether a proxied request is expected to
// have an unbounded or very long response and therefore must not carry the
// per-request upstream deadline. Docker API version prefixes (/v1.XX/) are
// stripped before matching.
func isLongLivedUpstreamRequest(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	path := requestNormalizedPath(w, r)
	switch r.Method {
	case http.MethodGet:
		switch {
		case path == "/events":
			return true
		case matchContainerAction(path, "logs"):
			return dockerBoolValue(r, "follow")
		case matchContainerAction(path, "stats"):

			return dockerBoolValueOrDefault(r, "stream", true)
		case matchContainerAction(path, "export"):
			return true
		case matchContainerAction(path, "archive"):

			return true
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/get"):
			return true
		case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/attach/ws"):
			return true
		}
	case http.MethodPut:

		return matchContainerAction(path, "archive")
	case http.MethodPost:
		switch {
		case path == "/build" || path == "/images/create" || path == "/images/load" || path == "/plugins/create":
			return true
		case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/push"):
			return true
		case path == "/plugins/pull":

			return true
		case strings.HasPrefix(path, "/plugins/") &&
			(strings.HasSuffix(path, "/push") || strings.HasSuffix(path, "/upgrade")):

			return true
		case matchContainerAction(path, "wait"):

			return true
		}
	}
	return false
}

// matchContainerAction reports whether path is exactly /containers/{id}/{action}.
func matchContainerAction(path, action string) bool {
	rest, ok := strings.CutPrefix(path, "/containers/")
	if !ok {
		return false
	}
	id, act, ok := strings.Cut(rest, "/")
	if !ok || id == "" {
		return false
	}
	return act == action
}

// dockerBoolValue mirrors the daemon's api/server/httputils.BoolValue: a query
// value is false only when empty or one of "0"/"no"/"false"/"none"
// (case-insensitive), and true otherwise. Matching dockerd's own parsing keeps
// the long-lived-request classification consistent with how the daemon will
// actually treat ?follow=/?stream= — e.g. follow=yes streams at the daemon, so
// it must be exempt from the request deadline here too, not just follow=1.
func dockerBoolValue(r *http.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "", "0", "no", "false", "none":
		return false
	default:
		return true
	}
}

// dockerBoolValueOrDefault mirrors httputils.BoolValueOrDefault: an absent key
// returns def; a present key (including an empty value) is parsed by
// dockerBoolValue. Used for ?stream=, which the daemon defaults to true.
func dockerBoolValueOrDefault(r *http.Request, key string, def bool) bool {
	if _, ok := r.URL.Query()[key]; !ok {
		return def
	}
	return dockerBoolValue(r, key)
}

func requestNormalizedPath(w http.ResponseWriter, r *http.Request) string {
	if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
		return meta.NormPath
	}
	return filter.NormalizePath(r.URL.Path)
}
