package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

const wantHijackHandshakeTimeout = 30 * time.Second

// safeBuffer is a goroutine-safe bytes.Buffer for concurrent log capture.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *safeBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *safeBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

func waitForGoroutineDrain(t *testing.T, baseline int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		runtime.GC()
		got := runtime.NumGoroutine()
		if got <= baseline+2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not drain: got %d, want <= %d", got, baseline+2)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// restoreHijackHooks saves all package-level hook vars and schedules their
// restoration via t.Cleanup. Call at the start of any test that mutates hooks.
func restoreHijackHooks(t *testing.T) {
	t.Helper()
	savedPool := hijackBufferPool
	savedDialWithTimeout := dialUpstreamWithTimeoutHook
	savedDial := dialUpstreamHook
	savedRead := readResponseHook
	savedCopy := copyBufferHook
	t.Cleanup(func() {
		hijackBufferPool = savedPool
		dialUpstreamWithTimeoutHook = savedDialWithTimeout
		dialUpstreamHook = savedDial
		readResponseHook = savedRead
		copyBufferHook = savedCopy
	})
}

func TestDefaultDialHijackUpstreamUsesFiveSecondTimeout(t *testing.T) {
	restoreHijackHooks(t)

	var gotNetwork, gotAddress string
	var gotTimeout time.Duration
	wantErr := errors.New("dial boom")

	dialUpstreamWithTimeoutHook = func(network, address string, timeout time.Duration) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		gotTimeout = timeout
		return nil, wantErr
	}

	_, err := dialUpstreamHook("unix", "/tmp/docker.sock")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if gotNetwork != "unix" {
		t.Fatalf("network = %q, want %q", gotNetwork, "unix")
	}
	if gotAddress != "/tmp/docker.sock" {
		t.Fatalf("address = %q, want %q", gotAddress, "/tmp/docker.sock")
	}
	if gotTimeout != hijackDialTimeout {
		t.Fatalf("timeout = %v, want %v", gotTimeout, hijackDialTimeout)
	}
}

type erroringResponseWriter struct {
	header http.Header
	status int
}

func (w *erroringResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *erroringResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *erroringResponseWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type closeErrorReadCloser struct {
	io.Reader
	closeErr error
}

func (r closeErrorReadCloser) Close() error {
	return r.closeErr
}

type hijackErrorWriter struct {
	header http.Header
	err    error
}

func (w *hijackErrorWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *hijackErrorWriter) Write([]byte) (int, error) { return 0, nil }
func (w *hijackErrorWriter) WriteHeader(int)           {}
func (w *hijackErrorWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, w.err
}

type loggingTestResponseWriter struct {
	header http.Header
	meta   *logging.RequestMeta
}

type hijackDeadlineResponseWriter struct {
	http.ResponseWriter
	readDeadlines []time.Time
	readDeadline  func(time.Time) error
}

func (w *hijackDeadlineResponseWriter) SetReadDeadline(deadline time.Time) error {
	w.readDeadlines = append(w.readDeadlines, deadline)
	if w.readDeadline != nil {
		return w.readDeadline(deadline)
	}
	return nil
}

func (w *loggingTestResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *loggingTestResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *loggingTestResponseWriter) WriteHeader(int)           {}
func (w *loggingTestResponseWriter) RequestMeta() *logging.RequestMeta {
	return w.meta
}

func TestIsHijackEndpoint(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		// Positive cases
		{"POST", "/containers/abc123/attach", true},
		{"POST", "/exec/abc123/start", true},
		// With version prefix
		{"POST", "/v1.45/containers/abc123/attach", true},
		{"POST", "/v1.45/exec/abc123/start", true},
		{"POST", "/v1.47/containers/mycontainer/attach", true},
		{"POST", "/v1.47/exec/myexec/start", true},
		// Negative: wrong method
		{"GET", "/containers/abc123/attach", false},
		{"GET", "/exec/abc123/start", false},
		{"PUT", "/containers/abc123/attach", false},
		// Negative: wrong path
		{"POST", "/containers/abc123/start", false},
		{"POST", "/containers/abc123/logs", false},
		{"POST", "/exec/abc123/resize", false},
		{"POST", "/images/abc123/attach", false},
		// Negative: wrong segment count
		{"POST", "/containers/attach", false},
		{"POST", "/exec/start", false},
		{"POST", "/containers/a/b/attach", false},
		{"POST", "containers/abc123/attach", false},
		{"POST", "/", false},
		// Negative: other endpoints
		{"GET", "/containers/json", false},
		{"GET", "/info", false},
		{"POST", "/containers/create", false},
	}

	for _, tt := range tests {
		name := tt.method + " " + tt.path
		t.Run(name, func(t *testing.T) {
			got := isHijackEndpoint(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("IsHijackEndpoint(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHijackEndpointDoesNotAllocateForHijackPaths(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "attach", method: http.MethodPost, path: "/containers/abc123/attach"},
		{name: "versioned_exec", method: http.MethodPost, path: "/v1.45/exec/abc123/start"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !isHijackEndpoint(tt.method, tt.path) {
				t.Fatalf("IsHijackEndpoint(%q, %q) = false, want true", tt.method, tt.path)
			}

			allocs := testing.AllocsPerRun(1000, func() {
				isHijackEndpoint(tt.method, tt.path)
			})

			if allocs > 0 {
				t.Fatalf("IsHijackEndpoint(%q, %q) allocated %.0f times, want 0", tt.method, tt.path, allocs)
			}
		})
	}
}

func TestRequestHijackPathUsesRequestMetaNormPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/not-a-hijack-endpoint", nil)
	writer := &loggingTestResponseWriter{meta: &logging.RequestMeta{
		NormPath: "/containers/abc123/attach",
	}}

	if got := requestHijackPath(writer, req); got != "/containers/abc123/attach" {
		t.Fatalf("requestHijackPath() = %q, want %q", got, "/containers/abc123/attach")
	}
	if !isHijackRequest(writer, req) {
		t.Fatal("expected cached normalized path to drive hijack detection")
	}
}

func TestRequestHijackPathFallsBackToNormalizePath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1.45/exec/abc123/start", nil)

	if got := requestHijackPath(httptest.NewRecorder(), req); got != "/exec/abc123/start" {
		t.Fatalf("requestHijackPath() = %q, want %q", got, "/exec/abc123/start")
	}
	if !isHijackRequest(httptest.NewRecorder(), req) {
		t.Fatal("expected fallback normalized path to match hijack endpoint")
	}
}

func TestRequestHijackHelpersHandleNilRequest(t *testing.T) {
	if isHijackRequest(httptest.NewRecorder(), nil) {
		t.Fatal("expected nil request to not be hijackable")
	}
	if got := requestHijackPath(httptest.NewRecorder(), nil); got != "" {
		t.Fatalf("requestHijackPath(nil) = %q, want empty", got)
	}
}

func TestWriteHijackUpstreamRequestBoundsAndClearsHandshakeIO(t *testing.T) {
	upstreamConn := &funcConn{}
	writer := &hijackDeadlineResponseWriter{ResponseWriter: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", strings.NewReader("stdin"))
	start := time.Now()

	if !writeHijackUpstreamRequest(upstreamConn, writer, req, slog.New(slog.NewTextHandler(io.Discard, nil))) {
		t.Fatal("writeHijackUpstreamRequest = false, want true")
	}

	if len(writer.readDeadlines) != 2 {
		t.Fatalf("client read deadlines = %v, want finite deadline followed by clear", writer.readDeadlines)
	}
	assertDeadlineNear(t, writer.readDeadlines[0], start, time.Now(), wantHijackHandshakeTimeout)
	if !writer.readDeadlines[1].IsZero() {
		t.Fatalf("final client read deadline = %v, want zero", writer.readDeadlines[1])
	}
	if len(upstreamConn.writeDeadlines) != 2 {
		t.Fatalf("upstream write deadlines = %v, want finite deadline followed by clear", upstreamConn.writeDeadlines)
	}
	assertDeadlineNear(t, upstreamConn.writeDeadlines[0], start, time.Now(), wantHijackHandshakeTimeout)
	if !upstreamConn.writeDeadlines[1].IsZero() {
		t.Fatalf("final upstream write deadline = %v, want zero", upstreamConn.writeDeadlines[1])
	}
}

func TestReadHijackUpstreamResponseBoundsAndClearsHeaderRead(t *testing.T) {
	response := bytes.NewReader([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
	upstreamConn := &funcConn{readFn: response.Read}
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	start := time.Now()

	_, resp, ok := readHijackUpstreamResponse(upstreamConn, httptest.NewRecorder(), req, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok {
		t.Fatal("readHijackUpstreamResponse = false, want true")
	}
	defer resp.Body.Close()

	if len(upstreamConn.readDeadlines) != 2 {
		t.Fatalf("upstream read deadlines = %v, want finite deadline followed by clear", upstreamConn.readDeadlines)
	}
	assertDeadlineNear(t, upstreamConn.readDeadlines[0], start, time.Now(), wantHijackHandshakeTimeout)
	if !upstreamConn.readDeadlines[1].IsZero() {
		t.Fatalf("final upstream read deadline = %v, want zero", upstreamConn.readDeadlines[1])
	}
}

func TestHijackHandshakeFailsWhenDeadlineCannotBeApplied(t *testing.T) {
	wantErr := errors.New("deadline unavailable")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/containers/abc/attach", strings.NewReader("stdin"))
	}

	t.Run("client body read", func(t *testing.T) {
		writer := &hijackDeadlineResponseWriter{
			ResponseWriter: httptest.NewRecorder(),
			readDeadline:   func(time.Time) error { return wantErr },
		}
		if writeHijackUpstreamRequest(&funcConn{}, writer, newRequest(), logger) {
			t.Fatal("writeHijackUpstreamRequest = true when the client read deadline failed")
		}
	})

	t.Run("upstream request write", func(t *testing.T) {
		conn := &funcConn{writeDeadlineFn: func(time.Time) error { return wantErr }}
		if writeHijackUpstreamRequest(conn, httptest.NewRecorder(), newRequest(), logger) {
			t.Fatal("writeHijackUpstreamRequest = true when the upstream write deadline failed")
		}
	})

	t.Run("upstream response headers", func(t *testing.T) {
		response := bytes.NewReader([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
		conn := &funcConn{
			readFn:         response.Read,
			readDeadlineFn: func(time.Time) error { return wantErr },
		}
		if _, _, ok := readHijackUpstreamResponse(conn, httptest.NewRecorder(), newRequest(), logger); ok {
			t.Fatal("readHijackUpstreamResponse = true when the upstream read deadline failed")
		}
	})
}

func TestHijackHandler_NonHijackPassthrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := HijackHandler("/not/used", logger, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for non-hijack endpoint")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestHijackHandler_UpstreamUnreachable(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})

	socketPath := "/nonexistent/socket.sock"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := HijackHandler(socketPath, logger, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", rec.Code)
	}
	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Message != "upstream Docker socket unreachable" {
		t.Fatalf("unexpected message: %q", body.Message)
	}
	if strings.Contains(rec.Body.String(), socketPath) {
		t.Fatalf("response leaked upstream socket path: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("response leaked internal error field: %q", rec.Body.String())
	}
}

func TestHijackHandler_FullUpgrade(t *testing.T) {
	// Create a mock Docker daemon on a Unix socket that responds with 101
	// and then echoes data back.
	socketPath := tempSocketPath(t, "upgrade")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const echoPayload = "hello from upstream"

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the incoming HTTP request
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		// Send 101 Switching Protocols
		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		resp.Header.Set("Content-Type", "application/vnd.docker.raw-stream")

		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
			return
		}

		// Echo: read from client, then write payload back
		buf := make([]byte, 256)
		n, _ := reader.Read(buf)
		conn.Write(buf[:n])
		conn.Write([]byte(echoPayload))
	}()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandler(socketPath, logger, next)

	// Create a real TCP server so we can get a hijackable connection
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	go srv.Serve(clientLn)
	defer srv.Close()

	// Connect as a client and send the attach request
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	// Write raw HTTP request
	reqStr := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	// Read the 101 response
	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if upgrade := resp.Header.Get("Upgrade"); upgrade != "tcp" {
		t.Errorf("expected Upgrade: tcp, got %q", upgrade)
	}

	// Send data through the hijacked connection
	clientMsg := "ping"
	clientConn.Write([]byte(clientMsg))

	// Read echoed data + upstream payload.
	// The upstream writes echo then payload in two calls, so a single Read
	// may return only part of the data. Use ReadFull with a deadline instead.
	expected := clientMsg + echoPayload
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	result := make([]byte, len(expected))
	if _, err := io.ReadFull(clientBuf, result); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := string(result); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}

	serverWg.Wait()
}

// unixSocketDialer adapts a unix socket path to the upstream.RequestDialer seam so the
// HijackHandlerWithDialer path can be exercised against an in-test mock daemon.
type unixSocketDialer struct {
	socketPath  string
	basePath    string
	rawBasePath string
}

func (d unixSocketDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", d.socketPath)
}

func (d unixSocketDialer) DialRequest(ctx context.Context, req *http.Request) (net.Conn, *http.Request, error) {
	conn, err := d.DialContext(ctx, "", "")
	if err != nil {
		return nil, nil, err
	}
	clone := req.Clone(req.Context())
	urlCopy := *req.URL
	clone.URL = &urlCopy
	clone.URL.Path = d.basePath + req.URL.Path
	if d.rawBasePath != "" || req.URL.RawPath != "" {
		clone.URL.RawPath = d.rawBasePath + req.URL.EscapedPath()
	}
	return conn, clone, nil
}

// TestHijackHandlerWithDialer_FullUpgrade mirrors TestHijackHandler_FullUpgrade
// for the multi-host dialer path: the hijack must dial the active endpoint via
// the upstream.RequestDialer, complete the 101 upgrade, and proxy bytes bidirectionally.
func TestHijackHandlerWithDialer_FullUpgrade(t *testing.T) {
	baseline := runtime.NumGoroutine()

	socketPath := tempSocketPath(t, "dialer-upgrade")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const echoPayload = "hello from dialer upstream"

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()
		if req.RequestURI != "/proxy%2Fapi/containers/abc/attach?stream=1" {
			t.Errorf("mock: RequestURI = %q, want prefixed escaped path", req.RequestURI)
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		resp.Header.Set("Content-Type", "application/vnd.docker.raw-stream")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
			return
		}

		buf := make([]byte, 256)
		n, _ := reader.Read(buf)
		conn.Write(buf[:n])
		conn.Write([]byte(echoPayload))
	}()

	var logs safeBuffer
	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}), collector)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandlerWithDialer(unixSocketDialer{
		socketPath:  socketPath,
		basePath:    "/proxy/api",
		rawBasePath: "/proxy%2Fapi",
	}, hijackInactivityTimeout, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(clientLn)
	}()
	defer srv.Close()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	reqStr := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if upgrade := resp.Header.Get("Upgrade"); upgrade != "tcp" {
		t.Errorf("expected Upgrade: tcp, got %q", upgrade)
	}

	clientMsg := "ping"
	clientConn.Write([]byte(clientMsg))

	expected := clientMsg + echoPayload
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	result := make([]byte, len(expected))
	if _, err := io.ReadFull(clientBuf, result); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := string(result); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}

	// Tear down deterministically so the proxy's copy goroutines finish (and
	// run their deferred putHijackBuffer) before the test returns — otherwise a
	// leaked copy goroutine reads the package-level hijackBufferPool while a
	// sibling test's restoreHijackHooks cleanup writes it (a cross-test race).
	if err := clientConn.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	serverWg.Wait()
	if err := srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("close server: %v", err)
	}
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop after teardown")
	}
	if !collector.WaitForMessage("hijack: connection closed", 2*time.Second) {
		t.Fatalf("expected 'connection closed' log within 2s; captured = %q", logs.String())
	}
	waitForGoroutineDrain(t, baseline, 2*time.Second)
}

func TestHijackHandler_Non101Fallbacks(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		statusCode  int
		message     string
		wantBody    string
	}{
		{
			name:        "500 internal server error",
			requestPath: "/containers/abc/attach",
			statusCode:  http.StatusInternalServerError,
			message:     "internal server error",
			wantBody:    "internal server error",
		},
		{
			name:        "503 service unavailable",
			requestPath: "/v1.45/exec/abc/start",
			statusCode:  http.StatusServiceUnavailable,
			message:     "service unavailable",
			wantBody:    "service unavailable",
		},
		{
			name:        "409 conflict",
			requestPath: "/v1.45/exec/abc/start",
			statusCode:  http.StatusConflict,
			message:     "container is not running",
			wantBody:    "not running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode, body := runHijackFallbackCase(t, tt.requestPath, tt.statusCode, tt.message)

			if statusCode != tt.statusCode {
				t.Errorf("expected %d, got %d", tt.statusCode, statusCode)
			}
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("expected error message in body, got %q", body)
			}
		})
	}
}

func runHijackFallbackCase(t *testing.T, requestPath string, statusCode int, message string) (int, string) {
	t.Helper()

	socketPath := tempSocketPath(t, fmt.Sprintf("fallback-%d", statusCode))

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.Body.Close()

		body := fmt.Sprintf(`{"message":%q}`, message)
		response := fmt.Sprintf(
			"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			statusCode,
			http.StatusText(statusCode),
			len(body),
			body,
		)
		if _, err := conn.Write([]byte(response)); err != nil {
			t.Errorf("mock: write fallback response: %v", err)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})
	handler := HijackHandler(socketPath, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	go srv.Serve(clientLn)
	defer srv.Close()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n", requestPath)
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}

	return resp.StatusCode, string(body)
}

func TestHandleHijack_UpstreamMalformedResponse(t *testing.T) {
	socketPath := tempSocketPath(t, "malformed")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		if _, err := conn.Write([]byte("not an http response\r\n\r\n")); err != nil {
			t.Errorf("mock: write malformed response: %v", err)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	handleHijack(rec, req, socketPath, logger)
	serverWg.Wait()

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Message != "failed to read upstream response" {
		t.Fatalf("unexpected message: %q", body.Message)
	}
	if strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("response leaked internal error field: %q", rec.Body.String())
	}
}

func TestHandleHijack_RequestWriteErrorDoesNotLeakDetails(t *testing.T) {
	socketPath := tempSocketPath(t, "write-error")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	bodyErr := fmt.Errorf("permission denied opening %s", socketPath)
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", io.NopCloser(errorReader{err: bodyErr}))
	req.ContentLength = 1

	rec := httptest.NewRecorder()
	handleHijack(rec, req, socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	serverWg.Wait()

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	var body httpjson.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Message != "failed to forward request to upstream" {
		t.Fatalf("unexpected message: %q", body.Message)
	}
	if strings.Contains(rec.Body.String(), bodyErr.Error()) || strings.Contains(rec.Body.String(), socketPath) {
		t.Fatalf("response leaked internal error details: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("response leaked internal error field: %q", rec.Body.String())
	}
}

func TestHandleHijack_StripsHopByHopHeadersBeforeForwarding(t *testing.T) {
	restoreHijackHooks(t)

	var rawRequest bytes.Buffer
	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) {
				return rawRequest.Write(p)
			},
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"bad request"}`)),
		}, nil
	}

	const body = "stdin payload"

	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach?stream=1", strings.NewReader(body))
	req.Close = true
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Connection", "keep-alive, X-Smuggled")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Smuggled", "attack")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authenticate", "Basic realm=upstream")
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	req.Header.Set("Te", "gzip")
	req.Header.Set("Trailer", "X-Trace")
	req.Trailer = http.Header{"X-Trace": []string{"secret"}}

	rec := httptest.NewRecorder()
	handleHijack(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawRequest.Bytes())))
	if err != nil {
		t.Fatalf("read forwarded request: %v", err)
	}
	defer gotReq.Body.Close()

	gotBody, err := io.ReadAll(gotReq.Body)
	if err != nil {
		t.Fatalf("read forwarded body: %v", err)
	}
	if string(gotBody) != body {
		t.Fatalf("forwarded body = %q, want %q", string(gotBody), body)
	}

	if gotReq.Header.Get("Connection") != "Upgrade" {
		t.Fatalf("Connection = %q, want %q", gotReq.Header.Get("Connection"), "Upgrade")
	}
	if gotReq.Header.Get("Upgrade") != "tcp" {
		t.Fatalf("Upgrade = %q, want %q", gotReq.Header.Get("Upgrade"), "tcp")
	}
	if gotReq.Header.Get("X-Smuggled") != "" {
		t.Fatalf("X-Smuggled leaked upstream: %q", gotReq.Header.Get("X-Smuggled"))
	}
	if gotReq.Header.Get("Proxy-Connection") != "" {
		t.Fatalf("Proxy-Connection leaked upstream: %q", gotReq.Header.Get("Proxy-Connection"))
	}
	if gotReq.Header.Get("Keep-Alive") != "" {
		t.Fatalf("Keep-Alive leaked upstream: %q", gotReq.Header.Get("Keep-Alive"))
	}
	if gotReq.Header.Get("Proxy-Authenticate") != "" {
		t.Fatalf("Proxy-Authenticate leaked upstream: %q", gotReq.Header.Get("Proxy-Authenticate"))
	}
	if gotReq.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("Proxy-Authorization leaked upstream: %q", gotReq.Header.Get("Proxy-Authorization"))
	}
	if gotReq.Header.Get("Te") != "" {
		t.Fatalf("Te leaked upstream: %q", gotReq.Header.Get("Te"))
	}
	if gotReq.Header.Get("Trailer") != "" {
		t.Fatalf("Trailer leaked upstream: %q", gotReq.Header.Get("Trailer"))
	}
	if len(gotReq.TransferEncoding) != 0 {
		t.Fatalf("TransferEncoding = %v, want empty", gotReq.TransferEncoding)
	}
	if gotReq.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", gotReq.ContentLength, len(body))
	}
	if gotReq.Close {
		t.Fatal("forwarded request unexpectedly asked upstream to close the connection")
	}
	if len(gotReq.Trailer) != 0 {
		t.Fatalf("Trailer = %v, want empty", gotReq.Trailer)
	}
}

// TestHandleHijack_PreservesOriginalRequestPathUpstream is the #194
// regression test for the Docker-compat side: the hijack layer must forward
// the client's original (versioned) request path upstream, not the
// normalized/stripped path used internally for endpoint matching. dockerd
// accepts a versioned path fine, so this doesn't regress docker-compat
// behavior; it's Podman's libpod API that actually requires the prefix (see
// TestHandleHijack_LibpodExecStartPreservesVersionPrefix in
// hijack_libpod_test.go).
func TestHandleHijack_PreservesOriginalRequestPathUpstream(t *testing.T) {
	restoreHijackHooks(t)

	var rawRequest bytes.Buffer
	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) {
				return rawRequest.Write(p)
			},
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"bad request"}`)),
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "http://client.example/v1.45/containers/abc/attach?stream=1&stderr=1", nil)
	req.Host = "client.example"

	rec := httptest.NewRecorder()
	handleHijack(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawRequest.Bytes())))
	if err != nil {
		t.Fatalf("read forwarded request: %v", err)
	}
	defer gotReq.Body.Close()

	if gotReq.Host != "docker" {
		t.Fatalf("Host = %q, want %q", gotReq.Host, "docker")
	}
	if gotReq.URL.Path != "/v1.45/containers/abc/attach" {
		t.Fatalf("URL.Path = %q, want %q", gotReq.URL.Path, "/v1.45/containers/abc/attach")
	}
	// The query is forwarded verbatim (RawQuery passthrough), preserving the
	// client's original parameter order rather than re-encoding/reordering it.
	if gotReq.URL.RawQuery != "stream=1&stderr=1" {
		t.Fatalf("URL.RawQuery = %q, want %q", gotReq.URL.RawQuery, "stream=1&stderr=1")
	}

	rawForwarded := rawRequest.String()
	if !strings.Contains(rawForwarded, "POST /v1.45/containers/abc/attach?stream=1&stderr=1 HTTP/1.1") {
		t.Fatalf("forwarded request target did not preserve the original versioned path with the verbatim query:\n%s", rawForwarded)
	}
	// The client's Host header must still not leak into the upstream request
	// target/headers — only the path itself is preserved.
	if strings.Contains(rawForwarded, "client.example") {
		t.Fatalf("forwarded request leaked client Host %q:\n%s", "client.example", rawForwarded)
	}
}

// TestHandleHijack_PreservesEncodedPathBytesUpstream is a CodeRabbit-flagged
// regression check on top of #194's fix: newUpstreamHijackRequest sets the
// wire path from r.URL.Path, which is the DECODED form (%2F becomes /). A
// url.URL with no RawPath re-derives EscapedPath() from that decoded Path
// alone, so an encoded target would collapse into a different, decoded one
// on the wire. Asserts the raw forwarded HTTP request line still has the
// percent-encoding, not a literal slash, at the actual byte level (not just
// the parsed URL struct).
func TestHandleHijack_PreservesEncodedPathBytesUpstream(t *testing.T) {
	restoreHijackHooks(t)

	var rawRequest bytes.Buffer
	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) {
				return rawRequest.Write(p)
			},
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"message":"bad request"}`)),
		}, nil
	}

	// abc%2Fdef decodes to abc/def in URL.Path; the encoded form must survive
	// onto the wire unchanged rather than being flattened to a literal slash.
	req := httptest.NewRequest(http.MethodPost, "http://client.example/v1.45/containers/abc%2Fdef/attach?stream=1", nil)
	req.Host = "client.example"

	rec := httptest.NewRecorder()
	handleHijack(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	rawForwarded := rawRequest.String()
	if !strings.Contains(rawForwarded, "POST /v1.45/containers/abc%2Fdef/attach?stream=1 HTTP/1.1") {
		t.Fatalf("forwarded request target did not preserve the encoded path:\n%s", rawForwarded)
	}
	if strings.Contains(rawForwarded, "POST /v1.45/containers/abc/def/attach") {
		t.Fatalf("forwarded request target decoded %%2F into a literal slash:\n%s", rawForwarded)
	}
}

func TestNewUpstreamHijackRequest_BuildsMinimalOutboundRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/containers/abc/attach?stream=1", strings.NewReader("stdin"))
	req.RequestURI = "/containers/abc/attach?stream=1"
	req.RemoteAddr = "192.0.2.10:12345"
	req.TLS = &tls.ConnectionState{}
	req.Response = &http.Response{StatusCode: http.StatusTeapot}
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = http.Header{"X-Trace": []string{"secret"}}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Test", "ok")

	upstreamReq := newUpstreamHijackRequest(req, "/containers/abc/attach")

	if upstreamReq == req {
		t.Fatal("expected a distinct request")
	}
	if upstreamReq.RequestURI != "" {
		t.Fatalf("RequestURI = %q, want empty", upstreamReq.RequestURI)
	}
	if upstreamReq.RemoteAddr != "" {
		t.Fatalf("RemoteAddr = %q, want empty", upstreamReq.RemoteAddr)
	}
	if upstreamReq.TLS != nil {
		t.Fatalf("TLS = %#v, want nil", upstreamReq.TLS)
	}
	if upstreamReq.Response != nil {
		t.Fatalf("Response = %#v, want nil", upstreamReq.Response)
	}
	if upstreamReq.Host != "docker" {
		t.Fatalf("Host = %q, want %q", upstreamReq.Host, "docker")
	}
	if upstreamReq.URL.Host != "docker" {
		t.Fatalf("URL.Host = %q, want %q", upstreamReq.URL.Host, "docker")
	}
	if upstreamReq.URL.Path != "/containers/abc/attach" {
		t.Fatalf("URL.Path = %q, want %q", upstreamReq.URL.Path, "/containers/abc/attach")
	}
	if upstreamReq.URL.RawQuery != "stream=1" {
		t.Fatalf("URL.RawQuery = %q, want %q", upstreamReq.URL.RawQuery, "stream=1")
	}
	if got := upstreamReq.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want %q", got, "ok")
	}
	if got := upstreamReq.Header.Get("Connection"); got != "Upgrade" {
		t.Fatalf("Connection = %q, want %q", got, "Upgrade")
	}
	if got := upstreamReq.Header.Get("Upgrade"); got != "tcp" {
		t.Fatalf("Upgrade = %q, want %q", got, "tcp")
	}
}

// TestNewUpstreamHijackRequest_PreservesRawPathForEncodedSegments is the
// unit-level half of the CodeRabbit-flagged RawPath regression: when path
// equals r.URL.Path (the production caller's normal case — see
// writeHijackUpstreamRequest), the constructed upstream URL must carry
// r.URL.RawPath too, so EscapedPath() reproduces the client's original
// percent-encoding instead of re-deriving it from the decoded Path (which
// would turn %2F into a literal /).
func TestNewUpstreamHijackRequest_PreservesRawPathForEncodedSegments(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/containers/abc%2Fdef/attach?stream=1", nil)

	upstreamReq := newUpstreamHijackRequest(req, req.URL.Path)

	if upstreamReq.URL.RawPath != "/containers/abc%2Fdef/attach" {
		t.Fatalf("URL.RawPath = %q, want %q", upstreamReq.URL.RawPath, "/containers/abc%2Fdef/attach")
	}
	if got := upstreamReq.URL.EscapedPath(); got != "/containers/abc%2Fdef/attach" {
		t.Fatalf("URL.EscapedPath() = %q, want %q", got, "/containers/abc%2Fdef/attach")
	}
}

// TestNewUpstreamHijackRequest_OmitsRawPathForCallerSuppliedPath covers the
// other half: when the caller passes a path that does NOT equal r.URL.Path
// (e.g. a literal string a test hands in directly), RawPath must stay empty
// rather than carrying over a stale encoding that doesn't describe the
// substituted path.
func TestNewUpstreamHijackRequest_OmitsRawPathForCallerSuppliedPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/containers/abc%2Fdef/attach?stream=1", nil)

	upstreamReq := newUpstreamHijackRequest(req, "/containers/other/attach")

	if upstreamReq.URL.RawPath != "" {
		t.Fatalf("URL.RawPath = %q, want empty", upstreamReq.URL.RawPath)
	}
	if got := upstreamReq.URL.EscapedPath(); got != "/containers/other/attach" {
		t.Fatalf("URL.EscapedPath() = %q, want %q", got, "/containers/other/attach")
	}
}

// TestNewUpstreamHijackRequestFallsBackToRequestURLPathWhenMissing covers the
// defensive empty-path branch (never hit by the production caller, which
// always passes r.URL.Path explicitly — see writeHijackUpstreamRequest).
// #194: the fallback must use the request's own original path, not a
// normalized/stripped one, to stay consistent with the fixed contract.
func TestNewUpstreamHijackRequestFallsBackToRequestURLPathWhenMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1.45/exec/abc/../abc/start?detach=0", nil)

	upstreamReq := newUpstreamHijackRequest(req, "")

	if upstreamReq.URL.Path != req.URL.Path {
		t.Fatalf("URL.Path = %q, want the request's own original path %q", upstreamReq.URL.Path, req.URL.Path)
	}
	if upstreamReq.URL.RawQuery != "detach=0" {
		t.Fatalf("URL.RawQuery = %q, want detach=0", upstreamReq.URL.RawQuery)
	}
}

func TestHandleHijack_ErrorResponseEncodingFailures(t *testing.T) {
	t.Run("dial failure", func(t *testing.T) {
		writer := &erroringResponseWriter{}
		req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

		handleHijack(writer, req, "/nonexistent/socket.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

		if writer.status != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", writer.status, http.StatusBadGateway)
		}
	})

	t.Run("request write failure", func(t *testing.T) {
		socketPath := tempSocketPath(t, "write-error-encode")

		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		var serverWg sync.WaitGroup
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}()

		req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", io.NopCloser(errorReader{err: errors.New("body boom")}))
		req.ContentLength = 1
		writer := &erroringResponseWriter{}

		handleHijack(writer, req, socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
		serverWg.Wait()

		if writer.status != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", writer.status, http.StatusBadGateway)
		}
	})

	t.Run("read response failure", func(t *testing.T) {
		socketPath := tempSocketPath(t, "read-error-encode")

		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		var serverWg sync.WaitGroup
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			if req.Body != nil {
				_ = req.Body.Close()
			}
			_, _ = conn.Write([]byte("not an http response\r\n\r\n"))
		}()

		writer := &erroringResponseWriter{}
		req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

		handleHijack(writer, req, socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
		serverWg.Wait()

		if writer.status != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", writer.status, http.StatusBadGateway)
		}
	})
}

func TestWriteHijackBadGateway(t *testing.T) {
	t.Run("writes bad gateway json response", func(t *testing.T) {
		rec := httptest.NewRecorder()

		writeHijackBadGateway(rec, slog.New(slog.NewTextHandler(io.Discard, nil)), "/containers/abc/attach", "failed to read upstream response")

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
		}

		var body httpjson.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("response body is not valid JSON: %v", err)
		}
		if body.Message != "failed to read upstream response" {
			t.Fatalf("message = %q, want %q", body.Message, "failed to read upstream response")
		}
	})

	t.Run("logs encode failure", func(t *testing.T) {
		var logBuf safeBuffer
		logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

		writeHijackBadGateway(&erroringResponseWriter{}, logger, "/containers/abc/attach", "failed to read upstream response")

		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "hijack: failed to encode error response") {
			t.Fatalf("expected encode failure log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, "/containers/abc/attach") {
			t.Fatalf("expected request path in log, got: %s", logOutput)
		}
	})
}

func TestWriteNonUpgradeHijackResponse_LogsBodyCopyAndCloseErrors(t *testing.T) {
	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	upstreamConn := &funcConn{}
	resp := &http.Response{
		StatusCode: http.StatusConflict,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body: closeErrorReadCloser{
			Reader:   errorReader{err: io.ErrClosedPipe},
			closeErr: errors.New("close boom"),
		},
	}

	writer := &erroringResponseWriter{}

	writeNonUpgradeHijackResponse(writer, resp, upstreamConn, logger, "/containers/abc/attach")

	if writer.status != http.StatusConflict {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusConflict)
	}

	logText := logs.String()
	if !strings.Contains(logText, "hijack: error copying non-upgrade response body") {
		t.Fatalf("expected copy error log, got %q", logText)
	}
	if !strings.Contains(logText, "hijack: error closing non-upgrade response body") {
		t.Fatalf("expected close error log, got %q", logText)
	}
}

func TestWriteNonUpgradeHijackResponse_NilBody(t *testing.T) {
	writer := httptest.NewRecorder()

	writeNonUpgradeHijackResponse(writer, &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       nil,
	}, &funcConn{}, slog.New(slog.NewTextHandler(io.Discard, nil)), "/containers/abc/attach")

	if writer.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", writer.Code, http.StatusAccepted)
	}
}

func TestWriteNonUpgradeHijackResponse_StripsHopByHopHeaders(t *testing.T) {
	writer := httptest.NewRecorder()

	writeNonUpgradeHijackResponse(writer, &http.Response{
		StatusCode: http.StatusConflict,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
			"Connection":   []string{"X-Injected-Header"},
			"Keep-Alive":   []string{"timeout=5"},
			"Upgrade":      []string{"tcp"},
			// Listed in Connection above, so it must be stripped too.
			"X-Injected-Header": []string{"malicious"},
		},
		Body: nil,
	}, &funcConn{}, slog.New(slog.NewTextHandler(io.Discard, nil)), "/containers/abc/attach")

	for _, name := range []string{"Connection", "Keep-Alive", "Upgrade", "X-Injected-Header"} {
		if got := writer.Header().Get(name); got != "" {
			t.Errorf("hop-by-hop header %s forwarded to client: %q", name, got)
		}
	}
	if got := writer.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
}

func TestUpgradeHijackConnectionReturnsReadySession(t *testing.T) {
	restoreHijackHooks(t)

	upstreamConn := &funcConn{
		writeFn: func(p []byte) (int, error) { return len(p), nil },
	}
	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return upstreamConn, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) { return len(p), nil },
	}
	writer := newHijackTestWriter(clientConn, strings.NewReader(""))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	session, ok := upgradeHijackConnection(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok {
		t.Fatal("expected upgradeHijackConnection() to return a ready session")
	}
	if session == nil {
		t.Fatal("expected non-nil hijack session")
		return
	}
	if session.path != req.URL.Path {
		t.Fatalf("session path = %q, want %q", session.path, req.URL.Path)
	}
	if session.upstreamConn != upstreamConn {
		t.Fatal("expected upstream connection to be preserved in session")
	}
	if session.clientConn != clientConn {
		t.Fatal("expected client connection to be preserved in session")
	}
	if session.upstreamBuf == nil {
		t.Fatal("expected upstream reader buffer in session")
	}
	if session.clientBuf == nil {
		t.Fatal("expected client read-writer in session")
	}
}

func TestUpgradeHijackConnectionWrapperReturnsReadySession(t *testing.T) {
	socketPath := filepath.Join("/tmp", fmt.Sprintf("sockguard-hijack-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
		if err := resp.Write(conn); err != nil {
			t.Errorf("write response: %v", err)
		}
	}()

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) { return len(p), nil },
	}
	writer := newHijackTestWriter(clientConn, strings.NewReader(""))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	session, ok := upgradeHijackConnection(writer, req, socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok || session == nil {
		t.Fatal("expected upgradeHijackConnection wrapper to return a ready session")
	}
	<-accepted
}

func TestProxyHijackStreamsClosesConnections(t *testing.T) {
	restoreHijackHooks(t)

	var copyCalls atomic.Int32
	copyBufferHook = func(io.Writer, io.Reader, []byte) (int64, error) {
		copyCalls.Add(1)
		return 0, io.EOF
	}

	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientClosed := 0
	upstreamClosed := 0
	clientConn := &funcConn{
		closeFn: func() error {
			clientClosed++
			return nil
		},
	}
	upstreamConn := &funcConn{
		closeFn: func() error {
			upstreamClosed++
			return nil
		},
	}

	proxyHijackStreams(&hijackSession{
		path:         "/containers/abc/attach",
		upstreamConn: upstreamConn,
		upstreamBuf:  bufio.NewReader(strings.NewReader("")),
		clientConn:   clientConn,
		clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
	}, hijackInactivityTimeout, logger)

	if got := copyCalls.Load(); got != 2 {
		t.Fatalf("copyHijackBuffer calls = %d, want 2", got)
	}
	if clientConn.closeWriteCalls == 0 {
		t.Fatal("expected client CloseWrite to be attempted")
	}
	if upstreamConn.closeWriteCalls == 0 {
		t.Fatal("expected upstream CloseWrite to be attempted")
	}
	if clientClosed != 1 {
		t.Fatalf("client close calls = %d, want 1", clientClosed)
	}
	if upstreamClosed != 1 {
		t.Fatalf("upstream close calls = %d, want 1", upstreamClosed)
	}
	if !strings.Contains(logs.String(), "connection closed") {
		t.Fatalf("expected connection closed log, got %q", logs.String())
	}
}

func TestProxyHijackStreamsWrapperClosesConnections(t *testing.T) {
	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{}
	upstreamConn := &funcConn{}

	proxyHijackStreams(&hijackSession{
		path:         "/containers/abc/attach",
		upstreamConn: upstreamConn,
		upstreamBuf:  bufio.NewReader(strings.NewReader("")),
		clientConn:   clientConn,
		clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
	}, hijackInactivityTimeout, logger)

	if clientConn.closeWriteCalls == 0 || upstreamConn.closeWriteCalls == 0 {
		t.Fatal("expected proxyHijackStreams wrapper to half-close both sides")
	}
}

// TestProxyHijackStreamsHalfClosesOnCopyPanic regresses a fuzz-discovered
// deadlock: when copyBuffer panicked, the deferred recover swallowed the
// panic but the goroutine exited without signaling half-close to the peer.
// The peer's read then blocked forever waiting for an EOF that never came,
// wedging FuzzHijackBidirectionalStream past Go's -timeout watchdog.
func TestProxyHijackStreamsHalfClosesOnCopyPanic(t *testing.T) {
	restoreHijackHooks(t)
	copyBufferHook = func(io.Writer, io.Reader, []byte) (int64, error) {
		panic("synthetic copy panic")
	}

	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{}
	upstreamConn := &funcConn{}

	done := make(chan struct{})
	go func() {
		proxyHijackStreams(&hijackSession{
			path:         "/containers/abc/attach",
			upstreamConn: upstreamConn,
			upstreamBuf:  bufio.NewReader(strings.NewReader("")),
			clientConn:   clientConn,
			clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
		}, hijackInactivityTimeout, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxyHijackStreams did not return after copy panic")
	}

	if clientConn.closeWriteCalls == 0 {
		t.Fatal("client CloseWrite was not called after upstream→client copy panic — peer would deadlock")
	}
	if upstreamConn.closeWriteCalls == 0 {
		t.Fatal("upstream CloseWrite was not called after client→upstream copy panic — peer would deadlock")
	}
	if !strings.Contains(logs.String(), `msg="hijack: copy panic" direction=upstream→client`) {
		t.Fatalf("expected upstream→client panic log, got %q", logs.String())
	}
	if !strings.Contains(logs.String(), `msg="hijack: copy panic" direction=client→upstream`) {
		t.Fatalf("expected client→upstream panic log, got %q", logs.String())
	}
}

// TestProxyHijackStreamsTornDownAfterConfiguredInactivityTimeout proves the
// configurable inactivity timeout (upstream.hijack_inactivity_timeout,
// threaded into proxyHijackStreams as an explicit parameter rather than the
// hijackInactivityTimeout package default) actually tears an idle hijacked
// connection down, at a scaled-down duration instead of the 10m default.
// The client→upstream direction is given an already-exhausted (EOF) source
// so the test's timing is driven entirely by the upstream→client direction,
// which reads from a real net.Pipe conn nobody writes to.
func TestProxyHijackStreamsTornDownAfterConfiguredInactivityTimeout(t *testing.T) {
	restoreHijackHooks(t)
	const timeout = 60 * time.Millisecond

	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	clientConn := &funcConn{}

	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	done := make(chan struct{})
	go func() {
		proxyHijackStreams(&hijackSession{
			path:         "/containers/abc/attach",
			upstreamConn: upstreamConn,
			upstreamBuf:  bufio.NewReader(upstreamConn),
			clientConn:   clientConn,
			clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
		}, timeout, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected an idle hijacked connection to be torn down once the configured inactivity timeout elapsed")
	}

	if count := strings.Count(logs.String(), "hijack: idle connection closed after inactivity timeout"); count != 1 {
		t.Fatalf("idle-timeout warn log count = %d, want 1; logs = %q", count, logs.String())
	}
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, "hijack: idle connection closed after inactivity timeout") && strings.Contains(line, "direction=") {
			t.Fatalf("connection-wide idle log must not blame one direction, got %q", line)
		}
	}
}

// TestProxyHijackStreamsNotTornDownWhileEitherDirectionActive proves that
// inactivity belongs to the whole hijacked session. Continuous upstream
// output must keep the client-input direction usable past one timeout.
func TestProxyHijackStreamsNotTornDownWhileEitherDirectionActive(t *testing.T) {
	restoreHijackHooks(t)
	const timeout = 120 * time.Millisecond
	const writeInterval = 30 * time.Millisecond

	upstreamConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	defer upstreamPeer.Close()
	defer clientPeer.Close()

	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	done := make(chan struct{})
	go func() {
		proxyHijackStreams(&hijackSession{
			path:         "/containers/abc/attach",
			upstreamConn: upstreamConn,
			upstreamBuf:  bufio.NewReader(upstreamConn),
			clientConn:   clientConn,
			clientBuf:    bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		}, timeout, logger)
		close(done)
	}()

	for i := byte(0); i < 6; i++ {
		time.Sleep(writeInterval)
		writeDone := make(chan error, 1)
		go func(value byte) {
			_, err := upstreamPeer.Write([]byte{value})
			writeDone <- err
		}(i)
		if err := clientPeer.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatalf("set client read deadline: %v", err)
		}
		got := []byte{0}
		if _, err := io.ReadFull(clientPeer, got); err != nil {
			t.Fatalf("read active upstream output: %v; logs = %q", err, logs.String())
		}
		if got[0] != i {
			t.Fatalf("upstream output = %d, want %d", got[0], i)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("write active upstream output: %v", err)
		}
	}

	if err := clientPeer.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set client write deadline: %v", err)
	}
	clientWriteDone := make(chan error, 1)
	go func() {
		_, err := clientPeer.Write([]byte("input"))
		clientWriteDone <- err
	}()
	if err := upstreamPeer.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set upstream read deadline: %v", err)
	}
	gotInput := make([]byte, len("input"))
	if _, err := io.ReadFull(upstreamPeer, gotInput); err != nil {
		t.Fatalf("read client input after sustained upstream output: %v; logs = %q", err, logs.String())
	}
	if string(gotInput) != "input" {
		t.Fatalf("client input = %q, want %q", gotInput, "input")
	}
	if err := <-clientWriteDone; err != nil {
		t.Fatalf("write client input after sustained upstream output: %v", err)
	}

	_ = clientPeer.Close()
	_ = upstreamPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxyHijackStreams did not return after peers closed")
	}
	if strings.Contains(logs.String(), "hijack: idle connection closed after inactivity timeout") {
		t.Fatalf("did not expect an idle-timeout warn log while the connection was active, got %q", logs.String())
	}
}

func TestHijackActivityNeverMovesBackward(t *testing.T) {
	activity := newHijackActivity()
	activity.record(2 * time.Second)
	activity.record(time.Second)

	if got := time.Duration(activity.lastElapsed.Load()); got != 2*time.Second {
		t.Fatalf("last activity = %s, want %s", got, 2*time.Second)
	}
}

func TestHandleHijack_NonUpgradeFallbackEdgePaths(t *testing.T) {
	restoreHijackHooks(t)

	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: closeErrorReadCloser{
				Reader:   strings.NewReader(`{"message":"conflict"}`),
				closeErr: errors.New("close boom"),
			},
		}, nil
	}

	writer := &erroringResponseWriter{}
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	handleHijack(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if writer.status != http.StatusConflict {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusConflict)
	}
}

func TestHandleHijack_ResponseWriterNotHijacker(t *testing.T) {
	restoreHijackHooks(t)

	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	handleHijack(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil), "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHandleHijack_HijackErrorAndWrite101Error(t *testing.T) {
	restoreHijackHooks(t)

	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	handleHijack(&hijackErrorWriter{err: errors.New("hijack boom")}, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

	failingConn := &funcConn{
		writeFn: func(p []byte) (int, error) {
			return 0, io.ErrClosedPipe
		},
	}
	writer := &hijackTestWriter{
		header: make(http.Header),
		conn:   failingConn,
		rw:     bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriterSize(failingConn, 1)),
	}

	handleHijack(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHandleHijack_CopyErrorsAreLoggedAndIgnored(t *testing.T) {
	restoreHijackHooks(t)

	dialUpstreamHook = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	copyBufferHook = func(io.Writer, io.Reader, []byte) (int64, error) {
		return 0, io.ErrClosedPipe
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	writer := newHijackTestWriter(&funcConn{}, strings.NewReader(""))

	handleHijack(writer, req, "/unused.sock", logger)

	logText := logs.String()
	if !strings.Contains(logText, `msg="hijack: copy ended" direction=upstream→client`) {
		t.Fatalf("expected upstream copy log, got %q", logText)
	}
	if !strings.Contains(logText, `msg="hijack: copy ended" direction=client→upstream`) {
		t.Fatalf("expected client copy log, got %q", logText)
	}
}

func TestHandleHijack_ClientDisconnectDuringUpgrade(t *testing.T) {
	socketPath := tempSocketPath(t, "upgrade-disconnect")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
		}
	}()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{
		writeFn: func([]byte) (int, error) {
			return 0, net.ErrClosed
		},
		closeFn: func() error {
			return errors.New("client close failed")
		},
	}
	w := newHijackTestWriter(clientConn, strings.NewReader(""))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	done := make(chan struct{})
	go func() {
		handleHijack(w, req, socketPath, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHijack did not return after client disconnect during upgrade")
	}

	serverWg.Wait()

	if !strings.Contains(logs.String(), "flush 101 to client failed") {
		t.Fatalf("expected upgrade disconnect log, got %q", logs.String())
	}
	if !strings.Contains(logs.String(), "failed to close client connection") {
		t.Fatalf("expected client close debug log, got %q", logs.String())
	}
}

func TestHandleHijack_PanicRecoveryInCopyGoroutines(t *testing.T) {
	socketPath := tempSocketPath(t, "copy-panic")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
			return
		}

		if _, err := conn.Write([]byte("panic-stream")); err != nil {
			t.Errorf("mock: write stream payload: %v", err)
		}
	}()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) {
			if strings.Contains(string(p), "panic-stream") {
				panic("client write panic")
			}
			return len(p), nil
		},
	}
	w := newHijackTestWriter(clientConn, panicReader{message: "client read panic"})
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	done := make(chan struct{})
	go func() {
		handleHijack(w, req, socketPath, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHijack did not return after copy goroutine panics")
	}

	serverWg.Wait()

	logText := logs.String()
	if !strings.Contains(logText, `msg="hijack: copy panic" direction=upstream→client`) {
		t.Fatalf("expected upstream panic log, got %q", logText)
	}
	if !strings.Contains(logText, `msg="hijack: copy panic" direction=client→upstream`) {
		t.Fatalf("expected client panic log, got %q", logText)
	}
}

func TestHandleHijack_HalfCloseFailureIgnored(t *testing.T) {
	socketPath := tempSocketPath(t, "half-close")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) {
			return len(p), nil
		},
		closeWriteFn: func() error {
			return net.ErrClosed
		},
	}
	w := newHijackTestWriter(clientConn, strings.NewReader(""))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	done := make(chan struct{})
	go func() {
		handleHijack(w, req, socketPath, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHijack did not return after CloseWrite failure")
	}

	serverWg.Wait()

	if clientConn.closeWriteCalls == 0 {
		t.Fatal("expected client CloseWrite to be attempted")
	}
}

func TestHandleHijack_FinalCloseErrorLogged(t *testing.T) {
	socketPath := tempSocketPath(t, "final-close")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		req.Body.Close()

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
		}
	}()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) {
			return len(p), nil
		},
		closeFn: func() error {
			return errors.New("client close failed")
		},
	}
	w := newHijackTestWriter(clientConn, strings.NewReader(""))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	done := make(chan struct{})
	go func() {
		handleHijack(w, req, socketPath, logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHijack did not return after final close error")
	}

	serverWg.Wait()

	logText := logs.String()
	if !strings.Contains(logText, "failed to close client connection") {
		t.Fatalf("expected client close debug log, got %q", logText)
	}
	if !strings.Contains(logText, "connection closed") {
		t.Fatalf("expected connection closed debug log, got %q", logText)
	}
}

func TestHandleHijack_UpstreamDisconnectDuringStreaming(t *testing.T) {
	socketPath := tempSocketPath(t, "upstream-disconnect")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const streamPayload = "partial-stream"

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
			return
		}

		if _, err := conn.Write([]byte(streamPayload)); err != nil {
			t.Errorf("mock: write stream payload: %v", err)
		}
	}()

	var logs safeBuffer
	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}), collector)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandler(socketPath, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	go srv.Serve(clientLn)
	defer srv.Close()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	reqStr := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite(): %v", err)
		}
	}

	data, err := io.ReadAll(clientBuf)
	if err != nil {
		t.Fatalf("client read stream: %v", err)
	}
	if string(data) != streamPayload {
		t.Fatalf("stream payload = %q, want %q", string(data), streamPayload)
	}

	serverWg.Wait()

	if !collector.WaitForMessage("hijack: connection closed", 2*time.Second) {
		t.Fatalf("expected 'connection closed' log within 2s; captured = %q", logs.String())
	}
}

func TestHijackConnectionClosedByUpstream(t *testing.T) {
	baseline := runtime.NumGoroutine()

	socketPath := tempSocketPath(t, "upstream-close-lifecycle")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const streamPayload = "partial-stream"

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("mock: read request: %v", err)
			return
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
		}
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "tcp")
		if err := resp.Write(conn); err != nil {
			t.Errorf("mock: write 101: %v", err)
			return
		}

		if _, err := conn.Write([]byte(streamPayload)); err != nil {
			t.Errorf("mock: write stream payload: %v", err)
		}
	}()

	var logs safeBuffer
	collector := &testhelp.CollectingHandler{}
	logger := testhelp.NewTeeLogger(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}), collector)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandler(socketPath, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(clientLn)
	}()
	defer srv.Close()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}

	reqStr := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("client SetReadDeadline: %v", err)
	}
	data, err := io.ReadAll(clientBuf)
	if err != nil {
		t.Fatalf("client read stream: %v", err)
	}
	if string(data) != streamPayload {
		t.Fatalf("stream payload = %q, want %q", string(data), streamPayload)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	serverWg.Wait()
	if err := srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("close server: %v", err)
	}

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop after upstream close")
	}

	if !collector.WaitForMessage("hijack: connection closed", 2*time.Second) {
		t.Fatalf("expected 'connection closed' log within 2s; captured = %q", logs.String())
	}

	waitForGoroutineDrain(t, baseline, 2*time.Second)
}

// TestHijackHandler_ConcurrentSessionsDoNotLeakGoroutines is the QA-3
// per-PR goroutine-leak regression for hijacked exec/attach streams.
// TestHijackConnectionClosedByUpstream above asserts the invariant for a
// single session; a leak that only shows up under fan-out (e.g. a per-
// session goroutine that never receives its stop signal when peers
// overlap) would slip past it but still grow RSS in production. Run a
// modest fan-out of full upgrade-and-echo sessions, finish them, and
// assert NumGoroutine returns to the baseline within the same window the
// single-session test uses.
//
// Sized at 32 sessions: large enough that a per-session leak puts the
// final goroutine count well above baseline+2 (the existing helper's
// slack); small enough that the test still completes well under a second
// on a loaded CI runner. The upstream serves one session per accepted
// connection in its own goroutine, mirroring how a real dockerd handles
// concurrent attaches.
func TestHijackHandler_ConcurrentSessionsDoNotLeakGoroutines(t *testing.T) {
	const sessions = 32
	const echoPayload = "ack"

	baseline := runtime.NumGoroutine()

	socketPath := tempSocketPath(t, "concurrent-hijack")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var upstreamWg sync.WaitGroup
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			upstreamWg.Add(1)
			go func(c net.Conn) {
				defer upstreamWg.Done()
				defer c.Close()

				reader := bufio.NewReader(c)
				req, readErr := http.ReadRequest(reader)
				if readErr != nil {
					return
				}
				if req.Body != nil {
					_ = req.Body.Close()
				}

				resp := &http.Response{
					StatusCode: http.StatusSwitchingProtocols,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     http.Header{},
				}
				resp.Header.Set("Connection", "Upgrade")
				resp.Header.Set("Upgrade", "tcp")
				resp.Header.Set("Content-Type", "application/vnd.docker.raw-stream")
				if writeErr := resp.Write(c); writeErr != nil {
					return
				}

				if _, writeErr := c.Write([]byte(echoPayload)); writeErr != nil {
					return
				}
			}(conn)
		}
	}()

	// Tee through a CollectingHandler so the test can wait for each
	// session's "hijack: connection closed" — the proxy emits that log
	// *after* wg.Wait() on both copy goroutines (hijack.go:264), and
	// the collector's internal mutex turns observing the log into a
	// happens-before edge with everything the copy goroutines did,
	// including the deferred putHijackBuffer call that the next test
	// would otherwise race on.
	collector := &testhelp.CollectingHandler{}
	logger := slog.New(collector)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandler(socketPath, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()

	srv := &http.Server{Handler: handler}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(clientLn)
	}()
	defer srv.Close()

	addr := clientLn.Addr().String()
	var clientWg sync.WaitGroup
	clientWg.Add(sessions)
	for i := 0; i < sessions; i++ {
		go func(i int) {
			defer clientWg.Done()

			clientConn, dialErr := net.Dial("tcp", addr)
			if dialErr != nil {
				t.Errorf("session %d: dial: %v", i, dialErr)
				return
			}
			defer clientConn.Close()

			reqStr := fmt.Sprintf(
				"POST /containers/abc%d/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
				i,
			)
			if _, writeErr := clientConn.Write([]byte(reqStr)); writeErr != nil {
				t.Errorf("session %d: write: %v", i, writeErr)
				return
			}

			clientBuf := bufio.NewReader(clientConn)
			resp, respErr := http.ReadResponse(clientBuf, nil)
			if respErr != nil {
				t.Errorf("session %d: read response: %v", i, respErr)
				return
			}
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Errorf("session %d: status = %d, want 101", i, resp.StatusCode)
				return
			}

			if deadlineErr := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); deadlineErr != nil {
				t.Errorf("session %d: SetReadDeadline: %v", i, deadlineErr)
				return
			}
			got := make([]byte, len(echoPayload))
			if _, readErr := io.ReadFull(clientBuf, got); readErr != nil {
				t.Errorf("session %d: read payload: %v", i, readErr)
				return
			}
			if string(got) != echoPayload {
				t.Errorf("session %d: payload = %q, want %q", i, string(got), echoPayload)
			}
		}(i)
	}

	clientWg.Wait()

	// Wait for "hijack: connection closed" × sessions before doing
	// anything else. That log is the published-after-wg.Wait signal
	// that BOTH copy goroutines for a session have finished their
	// deferred putHijackBuffer; the collector's mutex turns it into a
	// real HB edge with the test goroutine. Without this, the next
	// test's write to hijackBufferPool races the copy goroutines'
	// trailing read (Go race detector flags it even after the
	// goroutines have exited, because exit alone does not synchronize).
	closedDeadline := time.Now().Add(5 * time.Second)
	for {
		got := len(collector.FindMessage("hijack: connection closed"))
		if got >= sessions {
			break
		}
		if time.Now().After(closedDeadline) {
			t.Fatalf("only %d/%d sessions reached 'hijack: connection closed' within 5s", got, sessions)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if closeErr := ln.Close(); closeErr != nil {
		t.Errorf("close upstream listener: %v", closeErr)
	}
	<-upstreamDone
	upstreamWg.Wait()

	if closeErr := srv.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
		t.Errorf("close http server: %v", closeErr)
	}
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop after all sessions closed")
	}

	// 32 sessions widen the "proxy hijack goroutine still in its
	// deferred putHijackBuffer when the next test mutates
	// hijackBufferPool" window past what the shared helper's baseline+2
	// slack tolerates — race detector catches it as a global write/read
	// race. Drain to baseline exactly so every straggler has fully
	// returned before the next test runs.
	waitForStrictGoroutineDrain(t, baseline, 5*time.Second)
}

// waitForStrictGoroutineDrain is a tighter sibling of
// waitForGoroutineDrain: same shape, but no baseline+2 slack. Use it
// when subsequent tests mutate a global (here, hijackBufferPool) that
// the goroutines being drained still touch on their way out — that
// global write would race the in-flight read.
func waitForStrictGoroutineDrain(t *testing.T, baseline int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var got int
	for {
		runtime.GC()
		got = runtime.NumGoroutine()
		if got <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not drain to baseline: got %d, want <= %d after %v", got, baseline, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGetHijackBufferRestoresFullLengthFromPool(t *testing.T) {
	restoreHijackHooks(t)
	fakePool := &stubBufferPool{getValue: make([]byte, 128, hijackBufSize)}
	hijackBufferPool = fakePool

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsNil(t *testing.T) {
	restoreHijackHooks(t)
	fakePool := &stubBufferPool{}
	hijackBufferPool = fakePool

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsUndersizedBuffer(t *testing.T) {
	restoreHijackHooks(t)
	undersized := make([]byte, 128, hijackBufSize-1)
	fakePool := &stubBufferPool{getValue: undersized}
	hijackBufferPool = fakePool

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestPutHijackBufferRestoresFullLengthBeforeReuse(t *testing.T) {
	restoreHijackHooks(t)
	fakePool := &stubBufferPool{}
	hijackBufferPool = fakePool

	putHijackBuffer(make([]byte, 256, hijackBufSize))

	pooled, ok := fakePool.putValue.([]byte)
	if !ok {
		t.Fatalf("pooled value type = %T, want []byte", fakePool.putValue)
	}
	if len(pooled) != hijackBufSize {
		t.Fatalf("pooled length = %d, want %d", len(pooled), hijackBufSize)
	}
	if cap(pooled) != hijackBufSize {
		t.Fatalf("pooled capacity = %d, want %d", cap(pooled), hijackBufSize)
	}
}

func assertDeadlineNear(t *testing.T, got, start, end time.Time, timeout time.Duration) {
	t.Helper()
	lowerBound := start.Add(timeout - time.Second)
	upperBound := end.Add(timeout + time.Second)
	if got.Before(lowerBound) || got.After(upperBound) {
		t.Fatalf("deadline = %v, want between %v and %v", got, lowerBound, upperBound)
	}
}

func TestPutHijackBufferDiscardsUndersizedBuffer(t *testing.T) {
	restoreHijackHooks(t)
	fakePool := &stubBufferPool{}
	hijackBufferPool = fakePool

	putHijackBuffer(make([]byte, 128, hijackBufSize-1))

	if fakePool.putValue != nil {
		t.Fatalf("pooled value = %#v, want nil", fakePool.putValue)
	}
}

func TestPutHijackBufferZeroesBufferBeforeReuse(t *testing.T) {
	restoreHijackHooks(t)
	fakePool := &stubBufferPool{}
	hijackBufferPool = fakePool

	buf := make([]byte, hijackBufSize)
	for i := range buf {
		buf[i] = 0xAB
	}

	putHijackBuffer(buf)

	pooled, ok := fakePool.putValue.([]byte)
	if !ok {
		t.Fatalf("pooled value type = %T, want []byte", fakePool.putValue)
	}
	for i, b := range pooled {
		if b != 0 {
			t.Fatalf("pooled[%d] = %#x, want 0x00", i, b)
		}
	}
}

// TestGetHijackBufferAcceptsExactCapacityFromPool verifies that a buffer whose
// capacity is exactly hijackBufSize is returned from the pool rather than
// triggering a new allocation.
// Kills mutant: CONDITIONALS_BOUNDARY hijack.go:527 ("cap < hijackBufSize" → "cap <= hijackBufSize").
func TestGetHijackBufferAcceptsExactCapacityFromPool(t *testing.T) {
	restoreHijackHooks(t)
	// Pool holds a buffer with cap == hijackBufSize (not one less, not one more).
	exact := make([]byte, 0, hijackBufSize)
	fakePool := &stubBufferPool{getValue: exact}
	hijackBufferPool = fakePool

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
	// The returned buffer must share the same backing array as the pooled slice,
	// proving it was reused rather than freshly allocated.
	if cap(buf) > 0 && cap(exact) > 0 && &buf[:cap(buf)][0] != &exact[:cap(exact)][0] {
		t.Fatal("getHijackBuffer allocated a new buffer instead of reusing the exact-capacity pooled buffer")
	}
}

type hijackTestWriter struct {
	header http.Header
	conn   net.Conn
	rw     *bufio.ReadWriter
}

func newHijackTestWriter(conn net.Conn, reader io.Reader) *hijackTestWriter {
	return &hijackTestWriter{
		header: make(http.Header),
		conn:   conn,
		rw:     bufio.NewReadWriter(bufio.NewReader(reader), bufio.NewWriter(conn)),
	}
}

func (w *hijackTestWriter) Header() http.Header {
	return w.header
}

func (w *hijackTestWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *hijackTestWriter) WriteHeader(statusCode int) {}

func (w *hijackTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

type funcConn struct {
	readFn             func([]byte) (int, error)
	writeFn            func([]byte) (int, error)
	closeFn            func() error
	closeWriteFn       func() error
	closeWriteCalls    int
	readDeadlineFn     func(time.Time) error
	writeDeadlineFn    func(time.Time) error
	readDeadlines      []time.Time
	writeDeadlines     []time.Time
	readDeadlineCalls  int
	writeDeadlineCalls int
}

func (c *funcConn) Read(p []byte) (int, error) {
	if c.readFn != nil {
		return c.readFn(p)
	}
	return 0, io.EOF
}

func (c *funcConn) Write(p []byte) (int, error) {
	if c.writeFn != nil {
		return c.writeFn(p)
	}
	return len(p), nil
}

func (c *funcConn) Close() error {
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}

func (c *funcConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *funcConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *funcConn) SetDeadline(time.Time) error { return nil }
func (c *funcConn) SetReadDeadline(t time.Time) error {
	c.readDeadlineCalls++
	c.readDeadlines = append(c.readDeadlines, t)
	if c.readDeadlineFn != nil {
		return c.readDeadlineFn(t)
	}
	return nil
}
func (c *funcConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlineCalls++
	c.writeDeadlines = append(c.writeDeadlines, t)
	if c.writeDeadlineFn != nil {
		return c.writeDeadlineFn(t)
	}
	return nil
}

func (c *funcConn) CloseWrite() error {
	c.closeWriteCalls++
	if c.closeWriteFn != nil {
		return c.closeWriteFn()
	}
	return nil
}

type panicReader struct {
	message string
}

func (r panicReader) Read([]byte) (int, error) {
	panic(r.message)
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type stubBufferPool struct {
	getValue any
	putValue any
}

func (p *stubBufferPool) Get() any {
	return p.getValue
}

func (p *stubBufferPool) Put(value any) {
	p.putValue = value
}

// TestHijackConstantsArePinned pins the concrete values of the three hijack
// tuning constants. Other tests use the constants in comparisons, so an
// ARITHMETIC_BASE mutation (`*` → `/`, etc.) would shift both the const and
// the comparison together and stay invisible. These pin tests assert against
// the explicit literal values so a mutation cannot ride the rename.
func TestHijackConstantsArePinned(t *testing.T) {
	if hijackBufSize != 64*1024 {
		t.Errorf("hijackBufSize = %d, want %d", hijackBufSize, 64*1024)
	}
	if hijackDialTimeout != 5*time.Second {
		t.Errorf("hijackDialTimeout = %v, want 5s", hijackDialTimeout)
	}
	if hijackHandshakeTimeout != 30*time.Second {
		t.Errorf("hijackHandshakeTimeout = %v, want 30s", hijackHandshakeTimeout)
	}
	if hijackInactivityTimeout != 10*time.Minute {
		t.Errorf("hijackInactivityTimeout = %v, want 10m", hijackInactivityTimeout)
	}
}

// TestNewProxyTransportTunings pins the FlushInterval=-1 on the ReverseProxy
// and that the proxy routes through the shared upstream resolver. FlushInterval
// is required for correct streaming behavior: a non-streaming value would buffer
// docker events/logs/attach. The connection-pool tunings (IdleConnTimeout, etc.)
// now live on the resolver's per-endpoint transport and are pinned in
// internal/upstream's TestEndpoint_NewTransport_PoolTunings.
func TestNewProxyTransportTunings(t *testing.T) {
	rp := NewWithOptions("/tmp/does-not-matter.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})

	if got, want := rp.FlushInterval, time.Duration(-1); got != want {
		t.Errorf("FlushInterval = %v, want %v (immediate flush for streaming)", got, want)
	}
	if _, ok := rp.Transport.(*upstream.Resolver); !ok {
		t.Fatalf("Transport type = %T, want *upstream.Resolver", rp.Transport)
	}
}
