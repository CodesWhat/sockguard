package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// hijackBufSize is the buffer size for bidirectional copy on hijacked connections.
// 64KB balances throughput with memory use for Docker's streaming protocols.
const hijackBufSize = 64 * 1024

// apiVersionPrefix matches Docker API version prefixes like /v1.45/
var hijackVersionPrefix = regexp.MustCompile(`^/v\d+(\.\d+)?/`)

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
	p := hijackVersionPrefix.ReplaceAllString(path, "/")

	// Match: /containers/{id}/attach or /exec/{id}/start
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 3 {
		return false
	}
	return (parts[0] == "containers" && parts[2] == "attach") ||
		(parts[0] == "exec" && parts[2] == "start")
}

func handleHijack(w http.ResponseWriter, r *http.Request, upstreamSocket string, logger *slog.Logger) {
	// Dial upstream Docker socket
	upstreamConn, err := net.Dial("unix", upstreamSocket)
	if err != nil {
		logger.Error("hijack: upstream dial failed", "error", err, "path", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"message":"upstream Docker socket unreachable","error":"` + err.Error() + `"}`))
		return
	}

	// Write the original HTTP request to upstream.
	// r.Write serializes the full request (method, path, headers, body) in wire format.
	// Docker ignores the Host header on Unix socket connections.
	if err := r.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		logger.Error("hijack: write request to upstream failed", "error", err, "path", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"message":"failed to forward request to upstream"}`))
		return
	}

	// Read the upstream response. Use a large buffer so data arriving immediately
	// after the 101 header isn't lost.
	upstreamBuf := bufio.NewReaderSize(upstreamConn, hijackBufSize)
	resp, err := http.ReadResponse(upstreamBuf, r)
	if err != nil {
		upstreamConn.Close()
		logger.Error("hijack: read upstream response failed", "error", err, "path", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"message":"failed to read upstream response"}`))
		return
	}

	// If upstream didn't upgrade, fall back: write the response normally.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		upstreamConn.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			io.Copy(w, resp.Body)
			resp.Body.Close()
		}
		return
	}

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		logger.Error("hijack: ResponseWriter does not implement http.Hijacker", "path", r.URL.Path)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		upstreamConn.Close()
		logger.Error("hijack: client hijack failed", "error", err, "path", r.URL.Path)
		return
	}

	// Write the 101 Switching Protocols response to the client
	if err := resp.Write(clientBuf); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		logger.Error("hijack: write 101 to client failed", "error", err, "path", r.URL.Path)
		return
	}
	if err := clientBuf.Flush(); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		logger.Error("hijack: flush 101 to client failed", "error", err, "path", r.URL.Path)
		return
	}

	logger.Debug("hijack: connection upgraded", "path", r.URL.Path)

	// Bidirectional copy with proper half-close signaling.
	// When one direction reaches EOF, we signal the other side via CloseWrite
	// so it knows no more data is coming (critical for stdin EOF → container stop).
	var wg sync.WaitGroup
	wg.Add(2)

	// upstream → client
	go func() {
		defer wg.Done()
		buf := make([]byte, hijackBufSize)
		io.CopyBuffer(clientConn, upstreamBuf, buf)
		closeWrite(clientConn)
	}()

	// client → upstream (stdin)
	go func() {
		defer wg.Done()
		buf := make([]byte, hijackBufSize)
		io.CopyBuffer(upstreamConn, clientBuf, buf)
		closeWrite(upstreamConn)
	}()

	wg.Wait()
	clientConn.Close()
	upstreamConn.Close()
	logger.Debug("hijack: connection closed", "path", r.URL.Path)
}

// closeWrite performs a TCP/Unix half-close, signaling no more data will be sent
// while still allowing reads from the other direction.
func closeWrite(c net.Conn) {
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	}
}
