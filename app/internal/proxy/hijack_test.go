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

func TestHijackHandler_Non101Fallback_500(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/dp-test-500-%d.sock", os.Getpid())
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

		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 36\r\n\r\n{\"message\":\"internal server error\"}\r\n")
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

	reqStr := "POST /containers/abc/attach HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	clientConn.Write([]byte(reqStr))

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "internal server error") {
		t.Errorf("expected error message in body, got %q", string(body))
	}
}

func TestHijackHandler_Non101Fallback_503(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/dp-test-503-%d.sock", os.Getpid())
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

		fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 36\r\n\r\n{\"message\":\"service unavailable\"}\r\n\r\n")
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

	reqStr := "POST /v1.45/exec/abc/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	clientConn.Write([]byte(reqStr))

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "service unavailable") {
		t.Errorf("expected error message in body, got %q", string(body))
	}
}

func TestHijackHandler_Non101Fallback(t *testing.T) {
	// Mock Docker daemon that returns 409 Conflict (e.g., container not running)
	socketPath := fmt.Sprintf("/tmp/dp-test-fallback-%d.sock", os.Getpid())
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

		// Respond with 409 Conflict
		fmt.Fprintf(conn, "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"message\":\"container is not running\"}\r\n\r\n")
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})
	handler := HijackHandler(socketPath, logger, next)

	// Use a real server for hijack support
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

	reqStr := "POST /v1.45/exec/abc/start HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	clientConn.Write([]byte(reqStr))

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "not running") {
		t.Errorf("expected error message in body, got %q", string(body))
	}
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
