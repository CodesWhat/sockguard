package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
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

type hijackDeps struct {
	bufferPool              bytePool
	dialUpstreamWithTimeout func(string, string, time.Duration) (net.Conn, error)
	dialUpstream            func(string, string) (net.Conn, error)
	readResponse            func(*bufio.Reader, *http.Request) (*http.Response, error)
	copyBuffer              func(io.Writer, io.Reader, []byte) (int64, error)
}

func newHijackDeps() *hijackDeps {
	deps := &hijackDeps{
		bufferPool: &sync.Pool{
			New: func() any {
				return make([]byte, hijackBufSize)
			},
		},
		dialUpstreamWithTimeout: net.DialTimeout,
		readResponse:            http.ReadResponse,
		copyBuffer:              io.CopyBuffer,
	}
	deps.dialUpstream = deps.defaultDialUpstream
	return deps
}

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
	return hijackHandlerWithDeps(upstreamSocket, logger, next, newHijackDeps())
}

func hijackHandlerWithDeps(upstreamSocket string, logger *slog.Logger, next http.Handler, deps *hijackDeps) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHijackRequest(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		handleHijackWithDeps(w, r, upstreamSocket, logger, deps)
	})
}

// IsHijackEndpoint returns true if the request targets a Docker API endpoint
// that upgrades to a raw TCP stream via 101 Switching Protocols.
//
// Matched endpoints:
//   - POST /containers/{id}/attach
//   - POST /exec/{id}/start
//
// Docker API version prefixes (/v1.XX/) are stripped before matching.
func IsHijackEndpoint(method, path string) bool {
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

	// Match: /containers/{id}/attach or /exec/{id}/start
	p, ok := strings.CutPrefix(path, "/")
	if !ok {
		return false
	}

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

func (d *hijackDeps) defaultDialUpstream(network, address string) (net.Conn, error) {
	return d.dialUpstreamWithTimeout(network, address, hijackDialTimeout)
}

func writeHijackBadGateway(w http.ResponseWriter, logger *slog.Logger, path, message string) {
	if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
		Message: message,
	}); encErr != nil {
		logger.Warn("hijack: failed to encode error response", "error", encErr, "path", path)
	}
}

func handleHijack(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) {
	handleHijackWithDeps(w, r, upstreamSocket, logger, newHijackDeps())
}

func handleHijackWithDeps(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger, deps *hijackDeps) {
	session, ok := upgradeHijackConnectionWithDeps(w, r, upstreamSocket, logger, deps)
	if !ok {
		return
	}

	proxyHijackStreamsWithDeps(session, logger, deps)
}

func upgradeHijackConnection(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) (*hijackSession, bool) {
	return upgradeHijackConnectionWithDeps(w, r, upstreamSocket, logger, newHijackDeps())
}

func upgradeHijackConnectionWithDeps(
	w http.ResponseWriter,
	r *http.Request,
	upstreamSocket string,
	logger *slog.Logger,
	deps *hijackDeps,
) (*hijackSession, bool) {
	reqPath := r.URL.Path

	// Dial upstream Docker socket
	upstreamConn, err := deps.dialUpstream("unix", upstreamSocket)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", err, "path", reqPath)
		writeHijackBadGateway(w, logger, reqPath, "upstream Docker socket unreachable")
		return nil, false
	}

	if !writeHijackUpstreamRequest(upstreamConn, w, r, logger) {
		return nil, false
	}

	upstreamBuf, resp, ok := readHijackUpstreamResponseWithDeps(upstreamConn, w, r, logger, deps)
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
			logger.Debug("hijack: connection upgraded", "path", reqPath)
		}
	} else {
		writeNonUpgradeHijackResponse(w, resp, upstreamConn, logger, reqPath)
	}

	return session, ok
}

func proxyHijackStreams(session *hijackSession, logger *slog.Logger) {
	proxyHijackStreamsWithDeps(session, logger, newHijackDeps())
}

func proxyHijackStreamsWithDeps(session *hijackSession, logger *slog.Logger, deps *hijackDeps) {
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
		deps,
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
		deps,
	)

	wg.Wait()
	closeConn(logger, session.clientConn, "client connection", reqPath)
	closeConn(logger, session.upstreamConn, "upstream connection", reqPath)
	logger.Debug("hijack: connection closed", "path", reqPath)
}

func writeHijackUpstreamRequest(upstreamConn net.Conn, w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {
	// We remove client-controlled hop-by-hop metadata and emit a fixed Docker
	// upgrade hint so upstream sees only proxy-controlled connection semantics.
	reqPath := requestHijackPath(w, r)
	upstreamReq := newUpstreamHijackRequest(r, reqPath)
	if err := upstreamReq.Write(upstreamConn); err != nil {
		closeConn(logger, upstreamConn, "upstream connection", reqPath)
		logger.Error("hijack: write request to upstream failed", "error", err, "path", reqPath)
		writeHijackBadGateway(w, logger, reqPath, "failed to forward request to upstream")
		return false
	}

	return true
}

func readHijackUpstreamResponseWithDeps(
	upstreamConn net.Conn,
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	deps *hijackDeps,
) (*bufio.Reader, *http.Response, bool) {
	// Use a large buffer so data arriving immediately after the 101 header isn't lost.
	upstreamBuf := bufio.NewReaderSize(upstreamConn, hijackBufSize)
	resp, err := deps.readResponse(upstreamBuf, r)
	if err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: read upstream response failed", "error", err, "path", r.URL.Path)
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
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body == nil {
		return
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Debug("hijack: error copying non-upgrade response body", "error", err, "path", path)
	}
	if err := resp.Body.Close(); err != nil {
		logger.Debug("hijack: error closing non-upgrade response body", "error", err, "path", path)
	}
}

func finalizeHijackUpgrade(w http.ResponseWriter, logger *slog.Logger, state hijackUpgradeState) (*hijackSession, bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: ResponseWriter does not implement http.Hijacker", "path", state.path)
		return nil, false
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: client hijack failed", "error", err, "path", state.path)
		return nil, false
	}

	if err := state.resp.Write(clientBuf); err != nil {
		closeConn(logger, clientConn, "client connection", state.path)
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: write 101 to client failed", "error", err, "path", state.path)
		return nil, false
	}
	if err := clientBuf.Flush(); err != nil {
		closeConn(logger, clientConn, "client connection", state.path)
		closeConn(logger, state.upstreamConn, "upstream connection", state.path)
		logger.Error("hijack: flush 101 to client failed", "error", err, "path", state.path)
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
	deps *hijackDeps,
) {
	go func() {
		defer wg.Done()
		buf := deps.getHijackBuffer()
		defer deps.putHijackBuffer(buf)
		defer func() {
			if v := recover(); v != nil {
				logger.Error("hijack: panic in "+stream.direction+" copy", "panic", fmt.Sprint(v), "path", reqPath)
			}
		}()

		reader := withReadInactivityDeadline(stream.src, stream.readConn, hijackInactivityTimeout)
		writer := withWriteInactivityDeadline(stream.dst, stream.writeConn, hijackInactivityTimeout)
		if _, err := deps.copyBuffer(writer, reader, buf); err != nil {
			logger.Debug("hijack: "+stream.direction+" copy ended", "error", err, "path", reqPath)
		}
		closeWrite(stream.closeConnOnEOF)
	}()
}

func newUpstreamHijackRequest(r *http.Request, normalizedPath string) *http.Request {
	rawQuery := ""
	if normalizedPath == "" && r.URL != nil {
		normalizedPath = filter.NormalizePath(r.URL.Path)
	}
	if r.URL != nil {
		rawQuery = r.URL.Query().Encode()
	}

	upstreamReq := &http.Request{
		Method:        r.Method,
		Host:          "docker",
		URL:           &url.URL{Scheme: "http", Host: "docker", Path: normalizedPath, RawQuery: rawQuery},
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
	now := time.Now()
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
	now := time.Now()
	if w.lastRefresh.IsZero() || now.Sub(w.lastRefresh) > w.refreshInterval {
		if err := w.conn.SetWriteDeadline(now.Add(w.timeout)); err != nil {
			return 0, err
		}
		w.lastRefresh = now
	}
	return w.writer.Write(p)
}

func (d *hijackDeps) getHijackBuffer() []byte {
	buf, ok := d.bufferPool.Get().([]byte)
	if !ok || cap(buf) < hijackBufSize {
		return make([]byte, hijackBufSize)
	}
	return buf[:hijackBufSize]
}

func (d *hijackDeps) putHijackBuffer(buf []byte) {
	if cap(buf) < hijackBufSize {
		return
	}
	buf = buf[:hijackBufSize]
	clear(buf)
	d.bufferPool.Put(buf)
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
		logger.Debug("hijack: failed to close "+label, "error", err, "path", path)
	}
}
