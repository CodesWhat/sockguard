package proxy

import (
	"bufio"
	"bytes"
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
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

const wantHijackInactivityTimeout = 10 * time.Minute

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

func TestDialHijackUpstreamDefaultIsNotBareNetDial(t *testing.T) {
	got := runtime.FuncForPC(reflect.ValueOf(newHijackDeps().dialUpstream).Pointer()).Name()
	wantNot := runtime.FuncForPC(reflect.ValueOf(net.Dial).Pointer()).Name()

	if got == wantNot {
		t.Fatalf("dialUpstream = %s, want a wrapper that applies a timeout", got)
	}
}

func TestDefaultDialHijackUpstreamUsesFiveSecondTimeout(t *testing.T) {
	deps := newHijackDeps()

	var gotNetwork, gotAddress string
	var gotTimeout time.Duration
	wantErr := errors.New("dial boom")

	deps.dialUpstreamWithTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		gotTimeout = timeout
		return nil, wantErr
	}

	_, err := deps.defaultDialUpstream("unix", "/tmp/docker.sock")
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
			got := IsHijackEndpoint(tt.method, tt.path)
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
			if !IsHijackEndpoint(tt.method, tt.path) {
				t.Fatalf("IsHijackEndpoint(%q, %q) = false, want true", tt.method, tt.path)
			}

			allocs := testing.AllocsPerRun(1000, func() {
				IsHijackEndpoint(tt.method, tt.path)
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
	deps := newHijackDeps()

	var rawRequest bytes.Buffer
	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) {
				return rawRequest.Write(p)
			},
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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
	handleHijackWithDeps(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)

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

func TestHandleHijack_RebuildsUpstreamRequestTargetFromNormalizedPath(t *testing.T) {
	deps := newHijackDeps()

	var rawRequest bytes.Buffer
	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) {
				return rawRequest.Write(p)
			},
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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
	handleHijackWithDeps(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)

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
	if gotReq.URL.Path != "/containers/abc/attach" {
		t.Fatalf("URL.Path = %q, want %q", gotReq.URL.Path, "/containers/abc/attach")
	}
	if gotReq.URL.RawQuery != "stderr=1&stream=1" {
		t.Fatalf("URL.RawQuery = %q, want %q", gotReq.URL.RawQuery, "stderr=1&stream=1")
	}

	rawForwarded := rawRequest.String()
	if !strings.Contains(rawForwarded, "POST /containers/abc/attach?stderr=1&stream=1 HTTP/1.1") {
		t.Fatalf("forwarded request target was not rebuilt from normalized path and canonical query:\n%s", rawForwarded)
	}
	for _, disallowed := range []string{"client.example", "/v1.45/", "?stream=1&stderr=1"} {
		if strings.Contains(rawForwarded, disallowed) {
			t.Fatalf("forwarded request leaked %q:\n%s", disallowed, rawForwarded)
		}
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

func TestNewUpstreamHijackRequestNormalizesWhenPathMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1.45/exec/abc/../abc/start?detach=0", nil)

	upstreamReq := newUpstreamHijackRequest(req, "")

	if upstreamReq.URL.Path != "/exec/abc/start" {
		t.Fatalf("URL.Path = %q, want normalized exec path", upstreamReq.URL.Path)
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

func TestUpgradeHijackConnectionReturnsReadySession(t *testing.T) {
	deps := newHijackDeps()

	upstreamConn := &funcConn{
		writeFn: func(p []byte) (int, error) { return len(p), nil },
	}
	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return upstreamConn, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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

	session, ok := upgradeHijackConnectionWithDeps(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
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
	deps := newHijackDeps()

	var copyCalls atomic.Int32
	deps.copyBuffer = func(io.Writer, io.Reader, []byte) (int64, error) {
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

	proxyHijackStreamsWithDeps(&hijackSession{
		path:         "/containers/abc/attach",
		upstreamConn: upstreamConn,
		upstreamBuf:  bufio.NewReader(strings.NewReader("")),
		clientConn:   clientConn,
		clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
	}, logger, deps)

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
	}, logger)

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
	deps := newHijackDeps()
	deps.copyBuffer = func(io.Writer, io.Reader, []byte) (int64, error) {
		panic("synthetic copy panic")
	}

	var logs safeBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	clientConn := &funcConn{}
	upstreamConn := &funcConn{}

	done := make(chan struct{})
	go func() {
		proxyHijackStreamsWithDeps(&hijackSession{
			path:         "/containers/abc/attach",
			upstreamConn: upstreamConn,
			upstreamBuf:  bufio.NewReader(strings.NewReader("")),
			clientConn:   clientConn,
			clientBuf:    bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard)),
		}, logger, deps)
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
	if !strings.Contains(logs.String(), "panic in upstream→client copy") {
		t.Fatalf("expected upstream→client panic log, got %q", logs.String())
	}
	if !strings.Contains(logs.String(), "panic in client→upstream copy") {
		t.Fatalf("expected client→upstream panic log, got %q", logs.String())
	}
}

func TestInactivityDeadlineReaderReturnsDeadlineError(t *testing.T) {
	wantErr := errors.New("deadline boom")
	conn := &funcConn{
		readDeadlineFn: func(time.Time) error { return wantErr },
		readFn: func([]byte) (int, error) {
			t.Fatal("reader should not be called when deadline setup fails")
			return 0, nil
		},
	}

	_, err := withReadInactivityDeadline(strings.NewReader("data"), conn, time.Second).Read(make([]byte, 4))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Read() error = %v, want %v", err, wantErr)
	}
}

func TestInactivityDeadlineWriterReturnsDeadlineError(t *testing.T) {
	wantErr := errors.New("deadline boom")
	conn := &funcConn{
		writeDeadlineFn: func(time.Time) error { return wantErr },
		writeFn: func([]byte) (int, error) {
			t.Fatal("writer should not be called when deadline setup fails")
			return 0, nil
		},
	}

	_, err := withWriteInactivityDeadline(io.Discard, conn, time.Second).Write([]byte("data"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write() error = %v, want %v", err, wantErr)
	}
}

func TestHandleHijack_NonUpgradeFallbackEdgePaths(t *testing.T) {
	deps := newHijackDeps()

	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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

	handleHijackWithDeps(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)

	if writer.status != http.StatusConflict {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusConflict)
	}
}

func TestHandleHijack_ResponseWriterNotHijacker(t *testing.T) {
	deps := newHijackDeps()

	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	handleHijackWithDeps(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil), "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
}

func TestHandleHijack_HijackErrorAndWrite101Error(t *testing.T) {
	deps := newHijackDeps()

	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	handleHijackWithDeps(&hijackErrorWriter{err: errors.New("hijack boom")}, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)

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

	handleHijackWithDeps(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
}

func TestHandleHijack_CopyErrorsAreLoggedAndIgnored(t *testing.T) {
	deps := newHijackDeps()

	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	deps.copyBuffer = func(io.Writer, io.Reader, []byte) (int64, error) {
		return 0, io.ErrClosedPipe
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	writer := newHijackTestWriter(&funcConn{}, strings.NewReader(""))

	handleHijackWithDeps(writer, req, "/unused.sock", logger, deps)

	logText := logs.String()
	if !strings.Contains(logText, "upstream→client copy ended") {
		t.Fatalf("expected upstream copy log, got %q", logText)
	}
	if !strings.Contains(logText, "client→upstream copy ended") {
		t.Fatalf("expected client copy log, got %q", logText)
	}
}

func TestHandleHijack_StreamingActivityRefreshesInactivityDeadlines(t *testing.T) {
	deps := newHijackDeps()

	deps.readResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	upstreamPayload := bytes.Repeat([]byte("u"), hijackBufSize+1)
	clientPayload := bytes.Repeat([]byte("c"), hijackBufSize+1)

	upstreamReader := bytes.NewReader(upstreamPayload)
	upstreamConn := &funcConn{
		readFn: func(p []byte) (int, error) {
			return upstreamReader.Read(p)
		},
		writeFn: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	deps.dialUpstream = func(network, address string) (net.Conn, error) {
		return upstreamConn, nil
	}

	clientConn := &funcConn{
		writeFn: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	writer := newHijackTestWriter(clientConn, bytes.NewReader(clientPayload))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)

	start := time.Now()
	handleHijackWithDeps(writer, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
	end := time.Now()

	if upstreamConn.readDeadlineCalls < 1 {
		t.Fatalf("upstream read deadline calls = %d, want at least 1", upstreamConn.readDeadlineCalls)
	}
	if upstreamConn.writeDeadlineCalls < 1 {
		t.Fatalf("upstream write deadline calls = %d, want at least 1", upstreamConn.writeDeadlineCalls)
	}
	if clientConn.readDeadlineCalls < 1 {
		t.Fatalf("client read deadline calls = %d, want at least 1", clientConn.readDeadlineCalls)
	}
	if clientConn.writeDeadlineCalls < 1 {
		t.Fatalf("client write deadline calls = %d, want at least 1", clientConn.writeDeadlineCalls)
	}

	assertDeadlineNearTimeout(t, upstreamConn.readDeadlines[0], start, end)
	assertDeadlineNearTimeout(t, upstreamConn.writeDeadlines[0], start, end)
	assertDeadlineNearTimeout(t, clientConn.readDeadlines[0], start, end)
	assertDeadlineNearTimeout(t, clientConn.writeDeadlines[0], start, end)
}

func TestReadInactivityDeadlineRefreshIsThrottled(t *testing.T) {
	timeout := 200 * time.Millisecond
	readerConn := &funcConn{}
	reader := withReadInactivityDeadline(bytes.NewReader([]byte("abc")), readerConn, timeout)
	buf := make([]byte, 1)

	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if got, want := readerConn.readDeadlineCalls, 1; got != want {
		t.Fatalf("read deadline calls after first read = %d, want %d", got, want)
	}

	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if got, want := readerConn.readDeadlineCalls, 1; got != want {
		t.Fatalf("read deadline calls after immediate second read = %d, want %d", got, want)
	}

	time.Sleep((timeout / 4) + (timeout / 20))

	if _, err := reader.Read(buf); err != nil {
		t.Fatalf("third read: %v", err)
	}
	if got, want := readerConn.readDeadlineCalls, 2; got != want {
		t.Fatalf("read deadline calls after delayed third read = %d, want %d", got, want)
	}
}

func TestWriteInactivityDeadlineRefreshIsThrottled(t *testing.T) {
	timeout := 200 * time.Millisecond
	writerConn := &funcConn{}
	writer := withWriteInactivityDeadline(io.Discard, writerConn, timeout)

	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if got, want := writerConn.writeDeadlineCalls, 1; got != want {
		t.Fatalf("write deadline calls after first write = %d, want %d", got, want)
	}

	if _, err := writer.Write([]byte("b")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got, want := writerConn.writeDeadlineCalls, 1; got != want {
		t.Fatalf("write deadline calls after immediate second write = %d, want %d", got, want)
	}

	time.Sleep((timeout / 4) + (timeout / 20))

	if _, err := writer.Write([]byte("c")); err != nil {
		t.Fatalf("third write: %v", err)
	}
	if got, want := writerConn.writeDeadlineCalls, 2; got != want {
		t.Fatalf("write deadline calls after delayed third write = %d, want %d", got, want)
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
	if !strings.Contains(logText, "panic in upstream") {
		t.Fatalf("expected upstream panic log, got %q", logText)
	}
	if !strings.Contains(logText, "panic in client") {
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
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
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

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "connection closed") {
		if time.Now().After(deadline) {
			t.Fatalf("expected connection closed log, got %q", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
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
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
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

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "connection closed") {
		if time.Now().After(deadline) {
			t.Fatalf("expected connection closed log, got %q", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	waitForGoroutineDrain(t, baseline, 2*time.Second)
}

func TestGetHijackBufferRestoresFullLengthFromPool(t *testing.T) {
	deps := newHijackDeps()
	fakePool := &stubBufferPool{getValue: make([]byte, 128, hijackBufSize)}
	deps.bufferPool = fakePool

	buf := deps.getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsNil(t *testing.T) {
	deps := newHijackDeps()
	fakePool := &stubBufferPool{}
	deps.bufferPool = fakePool

	buf := deps.getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsUndersizedBuffer(t *testing.T) {
	deps := newHijackDeps()
	undersized := make([]byte, 128, hijackBufSize-1)
	fakePool := &stubBufferPool{getValue: undersized}
	deps.bufferPool = fakePool

	buf := deps.getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestPutHijackBufferRestoresFullLengthBeforeReuse(t *testing.T) {
	deps := newHijackDeps()
	fakePool := &stubBufferPool{}
	deps.bufferPool = fakePool

	deps.putHijackBuffer(make([]byte, 256, hijackBufSize))

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

func assertDeadlineNearTimeout(t *testing.T, got, start, end time.Time) {
	t.Helper()

	lowerBound := start.Add(wantHijackInactivityTimeout - time.Second)
	upperBound := end.Add(wantHijackInactivityTimeout + time.Second)
	if got.Before(lowerBound) || got.After(upperBound) {
		t.Fatalf("deadline = %v, want between %v and %v", got, lowerBound, upperBound)
	}
}

func TestPutHijackBufferDiscardsUndersizedBuffer(t *testing.T) {
	deps := newHijackDeps()
	fakePool := &stubBufferPool{}
	deps.bufferPool = fakePool

	deps.putHijackBuffer(make([]byte, 128, hijackBufSize-1))

	if fakePool.putValue != nil {
		t.Fatalf("pooled value = %#v, want nil", fakePool.putValue)
	}
}

func TestPutHijackBufferZeroesBufferBeforeReuse(t *testing.T) {
	deps := newHijackDeps()
	fakePool := &stubBufferPool{}
	deps.bufferPool = fakePool

	buf := make([]byte, hijackBufSize)
	for i := range buf {
		buf[i] = 0xAB
	}

	deps.putHijackBuffer(buf)

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
	deps := newHijackDeps()
	// Pool holds a buffer with cap == hijackBufSize (not one less, not one more).
	exact := make([]byte, 0, hijackBufSize)
	fakePool := &stubBufferPool{getValue: exact}
	deps.bufferPool = fakePool

	buf := deps.getHijackBuffer()

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
