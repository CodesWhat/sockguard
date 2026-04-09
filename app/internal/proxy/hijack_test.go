package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
)

var hijackBufferPoolMu sync.Mutex

func useHijackBufferPool(t *testing.T, pool bytePool) {
	t.Helper()

	hijackBufferPoolMu.Lock()
	oldPool := hijackBufferPool
	hijackBufferPool = pool
	t.Cleanup(func() {
		hijackBufferPool = oldPool
		hijackBufferPoolMu.Unlock()
	})
}

func useHijackDeps(t *testing.T) {
	t.Helper()

	originalDial := dialHijackUpstream
	originalReadResponse := readHijackResponse
	originalCopyBuffer := copyHijackBuffer

	t.Cleanup(func() {
		dialHijackUpstream = originalDial
		readHijackResponse = originalReadResponse
		copyHijackBuffer = originalCopyBuffer
	})
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
	// Use /tmp directly — macOS limits Unix socket paths to 104 bytes.
	socketPath := fmt.Sprintf("/tmp/dp-test-upgrade-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })
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

	// Read echoed data + upstream payload
	result := make([]byte, 1024)
	n, err := clientBuf.Read(result)
	if err != nil && err != io.EOF {
		t.Fatalf("client read: %v", err)
	}
	got := string(result[:n])
	expected := clientMsg + echoPayload
	if got != expected {
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

	socketPath := fmt.Sprintf("/tmp/dp-test-fallback-%d-%d.sock", statusCode, os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-malformed-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-write-error-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
		socketPath := fmt.Sprintf("/tmp/dp-test-write-error-encode-%d.sock", os.Getpid())
		t.Cleanup(func() { os.Remove(socketPath) })

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
		socketPath := fmt.Sprintf("/tmp/dp-test-read-error-encode-%d.sock", os.Getpid())
		t.Cleanup(func() { os.Remove(socketPath) })

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

func TestHandleHijack_NonUpgradeFallbackEdgePaths(t *testing.T) {
	useHijackDeps(t)

	dialHijackUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readHijackResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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
	useHijackDeps(t)

	dialHijackUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readHijackResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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
	useHijackDeps(t)

	dialHijackUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readHijackResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
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
	useHijackDeps(t)

	dialHijackUpstream = func(network, address string) (net.Conn, error) {
		return &funcConn{
			writeFn: func(p []byte) (int, error) { return len(p), nil },
		}, nil
	}
	readHijackResponse = func(*bufio.Reader, *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"tcp"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	copyHijackBuffer = func(io.Writer, io.Reader, []byte) (int64, error) {
		return 0, io.ErrClosedPipe
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	writer := newHijackTestWriter(&funcConn{}, strings.NewReader(""))

	handleHijack(writer, req, "/unused.sock", logger)

	logText := logs.String()
	if !strings.Contains(logText, "upstream→client copy ended") {
		t.Fatalf("expected upstream copy log, got %q", logText)
	}
	if !strings.Contains(logText, "client→upstream copy ended") {
		t.Fatalf("expected client copy log, got %q", logText)
	}
}

func TestHandleHijack_ClientDisconnectDuringUpgrade(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/dp-test-upgrade-disconnect-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-copy-panic-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-half-close-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-final-close-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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
	socketPath := fmt.Sprintf("/tmp/dp-test-upstream-disconnect-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(socketPath) })

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

	var logs bytes.Buffer
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

func TestGetHijackBufferRestoresFullLengthFromPool(t *testing.T) {
	fakePool := &stubBufferPool{getValue: make([]byte, 128, hijackBufSize)}
	useHijackBufferPool(t, fakePool)

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsNil(t *testing.T) {
	fakePool := &stubBufferPool{}
	useHijackBufferPool(t, fakePool)

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestGetHijackBufferAllocatesWhenPoolReturnsUndersizedBuffer(t *testing.T) {
	undersized := make([]byte, 128, hijackBufSize-1)
	fakePool := &stubBufferPool{getValue: undersized}
	useHijackBufferPool(t, fakePool)

	buf := getHijackBuffer()

	if len(buf) != hijackBufSize {
		t.Fatalf("buffer length = %d, want %d", len(buf), hijackBufSize)
	}
	if cap(buf) != hijackBufSize {
		t.Fatalf("buffer capacity = %d, want %d", cap(buf), hijackBufSize)
	}
}

func TestPutHijackBufferRestoresFullLengthBeforeReuse(t *testing.T) {
	fakePool := &stubBufferPool{}
	useHijackBufferPool(t, fakePool)

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

func TestPutHijackBufferDiscardsUndersizedBuffer(t *testing.T) {
	fakePool := &stubBufferPool{}
	useHijackBufferPool(t, fakePool)

	putHijackBuffer(make([]byte, 128, hijackBufSize-1))

	if fakePool.putValue != nil {
		t.Fatalf("pooled value = %#v, want nil", fakePool.putValue)
	}
}

func TestPutHijackBufferZeroesBufferBeforeReuse(t *testing.T) {
	fakePool := &stubBufferPool{}
	useHijackBufferPool(t, fakePool)

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
	readFn          func([]byte) (int, error)
	writeFn         func([]byte) (int, error)
	closeFn         func() error
	closeWriteFn    func() error
	closeWriteCalls int
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

func (c *funcConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *funcConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *funcConn) SetDeadline(time.Time) error      { return nil }
func (c *funcConn) SetReadDeadline(time.Time) error  { return nil }
func (c *funcConn) SetWriteDeadline(time.Time) error { return nil }

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
