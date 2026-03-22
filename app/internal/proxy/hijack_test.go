package proxy

import (
	"bufio"
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := HijackHandler("/nonexistent/socket.sock", logger, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", rec.Code)
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
