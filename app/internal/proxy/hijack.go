package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
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

var dialHijackUpstreamWithTimeout = net.DialTimeout
var dialHijackUpstream = defaultDialHijackUpstream
var readHijackResponse = http.ReadResponse
var copyHijackBuffer = io.CopyBuffer

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

// HijackHandler wraps a standard handler and intercepts Docker API endpoints
// that use HTTP connection upgrades (attach, exec start). For these endpoints,
// it dials the upstream Docker socket directly and performs a native bidirectional
// hijack with optimized buffers and proper TCP half-close signaling, rather than
// relying on the stdlib reverse proxy's generic upgrade handling.
func HijackHandler(upstreamSocket string, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsHijackEndpoint(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		handleHijack(w, r, upstreamSocket, logger)
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
	if method != http.MethodPost {
		return false
	}

	// Strip Docker API version prefix
	p := filter.NormalizePath(path)

	// Match: /containers/{id}/attach or /exec/{id}/start
	p, ok := strings.CutPrefix(p, "/")
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

func defaultDialHijackUpstream(network, address string) (net.Conn, error) {
	return dialHijackUpstreamWithTimeout(network, address, hijackDialTimeout)
}

func handleHijack(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) {
	// Dial upstream Docker socket
	upstreamConn, err := dialHijackUpstream("unix", upstreamSocket)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", err, "path", r.URL.Path)
		if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
			Message: "upstream Docker socket unreachable",
		}); encErr != nil {
			logger.Warn("hijack: failed to encode error response", "error", encErr, "path", r.URL.Path)
		}
		return
	}

	// Write a sanitized HTTP request to upstream.
	// We remove client-controlled hop-by-hop metadata and emit a fixed Docker
	// upgrade hint so upstream sees only proxy-controlled connection semantics.
	upstreamReq := newUpstreamHijackRequest(r)
	if err := upstreamReq.Write(upstreamConn); err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: write request to upstream failed", "error", err, "path", r.URL.Path)
		if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
			Message: "failed to forward request to upstream",
		}); encErr != nil {
			logger.Warn("hijack: failed to encode error response", "error", encErr, "path", r.URL.Path)
		}
		return
	}

	// Read the upstream response. Use a large buffer so data arriving immediately
	// after the 101 header isn't lost.
	upstreamBuf := bufio.NewReaderSize(upstreamConn, hijackBufSize)
	resp, err := readHijackResponse(upstreamBuf, r)
	if err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: read upstream response failed", "error", err, "path", r.URL.Path)
		if encErr := httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{
			Message: "failed to read upstream response",
		}); encErr != nil {
			logger.Warn("hijack: failed to encode error response", "error", encErr, "path", r.URL.Path)
		}
		return
	}

	// If upstream didn't upgrade, fall back: write the response normally.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				logger.Debug("hijack: error copying non-upgrade response body", "error", err, "path", r.URL.Path)
			}
			if err := resp.Body.Close(); err != nil {
				logger.Debug("hijack: error closing non-upgrade response body", "error", err, "path", r.URL.Path)
			}
		}
		return
	}

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: ResponseWriter does not implement http.Hijacker", "path", r.URL.Path)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: client hijack failed", "error", err, "path", r.URL.Path)
		return
	}

	// Write the 101 Switching Protocols response to the client
	if err := resp.Write(clientBuf); err != nil {
		closeConn(logger, clientConn, "client connection", r.URL.Path)
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: write 101 to client failed", "error", err, "path", r.URL.Path)
		return
	}
	if err := clientBuf.Flush(); err != nil {
		closeConn(logger, clientConn, "client connection", r.URL.Path)
		closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
		logger.Error("hijack: flush 101 to client failed", "error", err, "path", r.URL.Path)
		return
	}

	logger.Debug("hijack: connection upgraded", "path", r.URL.Path)

	// Bidirectional copy with proper half-close signaling.
	// When one direction reaches EOF, we signal the other side via CloseWrite
	// so it knows no more data is coming (critical for stdin EOF → container stop).
	var wg sync.WaitGroup
	wg.Add(2)

	reqPath := r.URL.Path

	// upstream → client
	go func() {
		defer wg.Done()
		buf := getHijackBuffer()
		defer putHijackBuffer(buf)
		defer func() {
			if v := recover(); v != nil {
				logger.Error("hijack: panic in upstream→client copy", "panic", fmt.Sprint(v), "path", reqPath)
			}
		}()
		src := withReadInactivityDeadline(upstreamBuf, upstreamConn, hijackInactivityTimeout)
		dst := withWriteInactivityDeadline(clientConn, clientConn, hijackInactivityTimeout)
		if _, err := copyHijackBuffer(dst, src, buf); err != nil {
			logger.Debug("hijack: upstream→client copy ended", "error", err, "path", reqPath)
		}
		closeWrite(clientConn)
	}()

	// client → upstream (stdin)
	go func() {
		defer wg.Done()
		buf := getHijackBuffer()
		defer putHijackBuffer(buf)
		defer func() {
			if v := recover(); v != nil {
				logger.Error("hijack: panic in client→upstream copy", "panic", fmt.Sprint(v), "path", reqPath)
			}
		}()
		src := withReadInactivityDeadline(clientBuf, clientConn, hijackInactivityTimeout)
		dst := withWriteInactivityDeadline(upstreamConn, upstreamConn, hijackInactivityTimeout)
		if _, err := copyHijackBuffer(dst, src, buf); err != nil {
			logger.Debug("hijack: client→upstream copy ended", "error", err, "path", reqPath)
		}
		closeWrite(upstreamConn)
	}()

	wg.Wait()
	closeConn(logger, clientConn, "client connection", r.URL.Path)
	closeConn(logger, upstreamConn, "upstream connection", r.URL.Path)
	logger.Debug("hijack: connection closed", "path", r.URL.Path)
}

func newUpstreamHijackRequest(r *http.Request) *http.Request {
	upstreamReq := r.Clone(r.Context())
	if upstreamReq.Header == nil {
		upstreamReq.Header = make(http.Header)
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
	reader  io.Reader
	conn    readDeadlineSetter
	timeout time.Duration
}

func withReadInactivityDeadline(reader io.Reader, conn readDeadlineSetter, timeout time.Duration) io.Reader {
	return &inactivityDeadlineReader{
		reader:  reader,
		conn:    conn,
		timeout: timeout,
	}
}

func (r *inactivityDeadlineReader) Read(p []byte) (int, error) {
	if err := r.conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type inactivityDeadlineWriter struct {
	writer  io.Writer
	conn    writeDeadlineSetter
	timeout time.Duration
}

func withWriteInactivityDeadline(writer io.Writer, conn writeDeadlineSetter, timeout time.Duration) io.Writer {
	return &inactivityDeadlineWriter{
		writer:  writer,
		conn:    conn,
		timeout: timeout,
	}
}

func (w *inactivityDeadlineWriter) Write(p []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return 0, err
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
		hc.CloseWrite() //nolint:errcheck // best-effort half-close; connection tears down next
	}
}

func closeConn(logger *slog.Logger, conn net.Conn, label, path string) {
	if err := conn.Close(); err != nil {
		logger.Debug("hijack: failed to close "+label, "error", err, "path", path)
	}
}
