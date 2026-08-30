package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// hijackBufSize is the buffer size for bidirectional copy on hijacked connections.
// 64KB balances throughput with memory use for Docker's streaming protocols.
const hijackBufSize = 64 * 1024

const hijackDialTimeout = 5 * time.Second
const hijackHandshakeTimeout = 30 * time.Second

// hijackInactivityTimeout is the default connection-wide inactivity deadline
// for hijacked (attach/exec-start) connections, used by HijackHandler (the
// socket-only entry point, not wired into the production serve chain) and as
// upstream.hijack_inactivity_timeout's default. HijackHandlerWithDialer — the
// entry point production wiring uses — takes the effective timeout as an
// explicit parameter instead, so a configured override never touches this
// constant.
const hijackInactivityTimeout = 10 * time.Minute

type bytePool interface {
	Get() any
	Put(any)
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
	dst            io.Writer
	closeConnOnEOF net.Conn
}

type hijackActivity struct {
	started     time.Time
	lastElapsed atomic.Int64
}

func newHijackActivity() *hijackActivity {
	return &hijackActivity{started: time.Now()}
}

func (a *hijackActivity) touch() {
	a.record(time.Since(a.started))
}

func (a *hijackActivity) record(elapsed time.Duration) {
	next := elapsed.Nanoseconds()
	for {
		current := a.lastElapsed.Load()
		if next <= current || a.lastElapsed.CompareAndSwap(current, next) {
			return
		}
	}
}

func (a *hijackActivity) idleFor() time.Duration {
	lastElapsed := time.Duration(a.lastElapsed.Load())
	return time.Since(a.started) - lastElapsed
}

type activityReader struct {
	reader   io.Reader
	activity *hijackActivity
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.activity.touch()
	}
	return n, err
}

type activityWriter struct {
	writer   io.Writer
	activity *hijackActivity
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.activity.touch()
	}
	return n, err
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

// HijackHandlerWithDialer is HijackHandler over an upstream.RequestDialer (typically an
// *upstream.Resolver), so the hijack path dials the same active endpoint — local
// socket or remote TCP+TLS — and fails over together with the rest of the proxy.
//
// inactivityTimeout bounds how long a hijacked connection may pass no bytes
// in either direction before it is torn down; it is the caller-resolved value of
// upstream.hijack_inactivity_timeout, not a package constant, so a configured
// override reaches every connection this handler upgrades.
func HijackHandlerWithDialer(dialer upstream.RequestDialer, inactivityTimeout time.Duration, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHijackRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		handleHijackDialer(w, r, dialer, inactivityTimeout, logger)
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
	return filter.IsHijackCandidatePath(method, filter.NormalizePath(path))
}

func isHijackRequest(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	return filter.IsHijackCandidatePath(r.Method, requestHijackPath(w, r))
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

	proxyHijackStreams(session, hijackInactivityTimeout, logger)
}

func handleHijackDialer(w http.ResponseWriter, r *http.Request, dialer upstream.RequestDialer, inactivityTimeout time.Duration, logger *slog.Logger) {
	session, ok := upgradeHijackConnectionDialer(w, r, dialer, logger)
	if !ok {
		return
	}

	proxyHijackStreams(session, inactivityTimeout, logger)
}

func upgradeHijackConnection(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	// Dial upstream Docker socket
	upstreamConn, err := dialUpstreamHook("unix", upstreamSocket)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		writeHijackBadGateway(w, logger, reqPath, "upstream Docker socket unreachable")
		return nil, false
	}

	return finishHijackUpgrade(w, r, upstreamConn, newUpstreamHijackRequest(r, r.URL.Path), logger)
}

// upgradeHijackConnectionDialer is upgradeHijackConnection over an
// upstream.RequestDialer: it atomically dials the active endpoint and rewrites
// the request with that same endpoint's base path, then shares the post-dial
// upgrade logic.
func upgradeHijackConnectionDialer(w http.ResponseWriter, r *http.Request, dialer upstream.RequestDialer, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	ctx, cancel := context.WithTimeout(r.Context(), hijackDialTimeout)
	defer cancel()
	upstreamReq := newUpstreamHijackRequest(r, r.URL.Path)
	upstreamConn, upstreamReq, err := dialer.DialRequest(ctx, upstreamReq)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		writeHijackBadGateway(w, logger, reqPath, "upstream Docker socket unreachable")
		return nil, false
	}

	return finishHijackUpgrade(w, r, upstreamConn, upstreamReq, logger)
}

// finishHijackUpgrade performs the request write, response read, and 101-upgrade
// finalization shared by the socket and dialer hijack paths once the upstream
// connection is established.
func finishHijackUpgrade(w http.ResponseWriter, r *http.Request, upstreamConn net.Conn, upstreamReq *http.Request, logger *slog.Logger) (*hijackSession, bool) {
	reqPath := r.URL.Path

	if !writePreparedHijackUpstreamRequest(upstreamConn, w, r, upstreamReq, logger) {
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

func proxyHijackStreams(session *hijackSession, inactivityTimeout time.Duration, logger *slog.Logger) {
	// Bidirectional copy with proper half-close signaling.
	// When one direction reaches EOF, we signal the other side via CloseWrite
	// so it knows no more data is coming (critical for stdin EOF → container stop).
	var wg sync.WaitGroup
	wg.Add(2)
	activity := newHijackActivity()
	copyDone := make(chan struct{})

	reqPath := session.path

	startHijackCopy(
		&wg,
		logger,
		reqPath,
		activity,
		hijackCopyStream{
			direction:      "upstream→client",
			src:            session.upstreamBuf,
			dst:            session.clientConn,
			closeConnOnEOF: session.clientConn,
		},
	)
	startHijackCopy(
		&wg,
		logger,
		reqPath,
		activity,
		hijackCopyStream{
			direction:      "client→upstream",
			src:            session.clientBuf,
			dst:            session.upstreamConn,
			closeConnOnEOF: session.upstreamConn,
		},
	)

	go func() {
		wg.Wait()
		close(copyDone)
	}()

	if waitForHijackInactivity(activity, inactivityTimeout, copyDone) {
		logger.Warn("hijack: idle connection closed after inactivity timeout", "timeout", inactivityTimeout.String(), "path", logging.SafeString(reqPath))
	}
	closeConn(logger, session.clientConn, "client connection", reqPath)
	closeConn(logger, session.upstreamConn, "upstream connection", reqPath)
	<-copyDone
	logger.Debug("hijack: connection closed", "path", logging.SafeString(reqPath))
}

func waitForHijackInactivity(activity *hijackActivity, timeout time.Duration, done <-chan struct{}) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-done:
			return false
		case <-timer.C:
			select {
			case <-done:
				return false
			default:
			}
		}

		remaining := timeout - activity.idleFor()
		if remaining <= 0 {
			return true
		}
		timer.Reset(remaining)
	}
}

func writeHijackUpstreamRequest(upstreamConn net.Conn, w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {
	// We remove client-controlled hop-by-hop metadata and emit a fixed Docker
	// upgrade hint so upstream sees only proxy-controlled connection semantics.
	//
	// #194: the wire path is the client's ORIGINAL request path — version
	// prefix and all — not the normalized/stripped form. That mirrors the
	// non-hijack reverse-proxy path (proxy.go's Rewrite touches only
	// Scheme/Host and leaves Path untouched): real Podman requires the
	// version prefix (/v5.x.y/libpod/...) on every route but the bare
	// _ping, while dockerd accepts a versioned path too, so preserving it
	// doesn't regress docker-compat. logPath stays the normalized form used
	// everywhere else in the proxy for endpoint matching and logging.
	return writePreparedHijackUpstreamRequest(upstreamConn, w, r, newUpstreamHijackRequest(r, r.URL.Path), logger)
}

func writePreparedHijackUpstreamRequest(upstreamConn net.Conn, w http.ResponseWriter, r, upstreamReq *http.Request, logger *slog.Logger) bool {
	logPath := requestHijackPath(w, r)

	clientController := http.NewResponseController(w)
	clientDeadlineSet := false
	if err := clientController.SetReadDeadline(timeNowHook().Add(hijackHandshakeTimeout)); err != nil {
		if !errors.Is(err, http.ErrNotSupported) {
			closeConn(logger, upstreamConn, "upstream connection", logPath)
			logger.Error("hijack: set client body deadline failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath))
			writeHijackBadGateway(w, logger, logPath, "failed to forward request to upstream")
			return false
		}
	} else {
		clientDeadlineSet = true
	}

	if err := upstreamConn.SetWriteDeadline(timeNowHook().Add(hijackHandshakeTimeout)); err != nil {
		if clientDeadlineSet {
			_ = clientController.SetReadDeadline(time.Time{})
		}
		closeConn(logger, upstreamConn, "upstream connection", logPath)
		logger.Error("hijack: set upstream request deadline failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath))
		writeHijackBadGateway(w, logger, logPath, "failed to forward request to upstream")
		return false
	}

	writeErr := upstreamReq.Write(upstreamConn)
	upstreamClearErr := upstreamConn.SetWriteDeadline(time.Time{})
	var clientClearErr error
	if clientDeadlineSet {
		clientClearErr = clientController.SetReadDeadline(time.Time{})
	}
	if err := errors.Join(writeErr, upstreamClearErr, clientClearErr); err != nil {
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
	if err := upstreamConn.SetReadDeadline(timeNowHook().Add(hijackHandshakeTimeout)); err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: set upstream response deadline failed", "error", logging.SafeString(err.Error()), "path", logging.SafeString(r.URL.Path))
		writeHijackBadGateway(w, logger, r.URL.Path, "failed to read upstream response")
		return nil, nil, false
	}

	// Use a large buffer so data arriving immediately after the 101 header isn't lost.
	upstreamBuf := bufio.NewReaderSize(upstreamConn, hijackBufSize)
	resp, readErr := readResponseHook(upstreamBuf, r)
	clearErr := upstreamConn.SetReadDeadline(time.Time{})
	if err := errors.Join(readErr, clearErr); err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
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
	// Closing upstreamConn before draining resp.Body truncates chunked or
	// otherwise-unbuffered responses — the bufio.Reader has only the bytes
	// it happened to prefetch when headers were parsed.
	defer closeConn(logger, upstreamConn, "upstream connection", path)
	// The upstream response is hop-terminated here, not tunneled: forwarding
	// Connection et al. verbatim would let upstream inject connection-scoped
	// headers into the client response.
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
	activity *hijackActivity,
	stream hijackCopyStream,
) {
	go func() {
		defer wg.Done()
		buf := getHijackBuffer()
		defer putHijackBuffer(buf)
		// closeWrite must run even if the copy panics — otherwise the peer's
		// read side never sees EOF and the bidirectional pair deadlocks. The
		// recovered panic alone is not enough: the goroutine returns silently
		// but its half-close signal never reaches the other end.
		defer closeWrite(stream.closeConnOnEOF)
		defer func() {
			if v := recover(); v != nil {
				logger.Error("hijack: copy panic", "direction", logging.SafeString(stream.direction), "panic", logging.SafeString(fmt.Sprint(v)), "path", logging.SafeString(reqPath))
			}
		}()

		reader := activityReader{reader: stream.src, activity: activity}
		writer := activityWriter{writer: stream.dst, activity: activity}
		if _, err := copyBufferHook(writer, reader, buf); err != nil {
			logger.Debug("hijack: copy ended", "direction", logging.SafeString(stream.direction), "error", logging.SafeString(err.Error()), "path", logging.SafeString(reqPath))
		}
	}()
}

func newUpstreamHijackRequest(r *http.Request, path string) *http.Request {
	rawQuery := ""
	rawPath := ""
	if path == "" && r.URL != nil {
		// Defensive fallback for callers that don't have a path handy (e.g.
		// direct unit tests): use the client's original path, not a
		// normalized one — #194, see writeHijackUpstreamRequest.
		path = r.URL.Path
	}
	if r.URL != nil {
		// Forward the query verbatim rather than Query().Encode(), which would
		// re-parse and reorder the parameters (and allocate). This matches the
		// main reverse-proxy path and preserves the exact exec/attach query the
		// client sent.
		rawQuery = r.URL.RawQuery
		// Preserve the original percent-encoding too: when path is the
		// request's own (unmodified) path, carry over its RawPath so an
		// encoded segment like %2F round-trips onto the wire unchanged
		// instead of url.URL re-deriving EscapedPath() from the decoded
		// Path alone, which would collapse it to a literal /.
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
		// Best-effort half-close; the connection tears down on the next read.
		_ = hc.CloseWrite()
	}
}

func closeConn(logger *slog.Logger, conn net.Conn, label, path string) {
	if err := conn.Close(); err != nil {
		logger.Debug(logging.SafeString("hijack: failed to close "+label), "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
}
