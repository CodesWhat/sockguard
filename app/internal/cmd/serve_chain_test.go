package cmd

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/config"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
	"github.com/codeswhat/sockguard/internal/proxy"
)

func TestFullProxyChainHTTPIntegration(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-http")
	_ = os.Remove(socketPath)

	upstreamPaths := make(chan string, 1)
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPaths <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))

	handler, logBuf := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1.45/_ping")
	if err != nil {
		t.Fatalf("proxy GET /_ping: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, string(body))
	}
	if string(body) != "upstream-ok" {
		t.Fatalf("body = %q, want %q", string(body), "upstream-ok")
	}

	waitForRequest()

	select {
	case got := <-upstreamPaths:
		if got != "/v1.45/_ping" {
			t.Fatalf("upstream path = %q, want %q", got, "/v1.45/_ping")
		}
	default:
		t.Fatal("expected upstream request")
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"decision":"allow"`) {
		t.Fatalf("expected allow decision in log output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"normalized_path":"/_ping"`) {
		t.Fatalf("expected normalized path in log output, got: %s", logOutput)
	}
}

func TestFullProxyChainHijackIntegration(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-hijack")
	_ = os.Remove(socketPath)

	const (
		clientMsg   = "ping"
		echoPayload = "hello from upstream"
	)

	upstreamPath := make(chan string, 1)
	upstreamDone := make(chan struct{})

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix upstream: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	go func() {
		defer close(upstreamDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("upstream read request: %v", err)
			return
		}
		upstreamPath <- req.URL.Path
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

		if err := resp.Write(conn); err != nil {
			t.Errorf("upstream write 101: %v", err)
			return
		}

		buf := make([]byte, len(clientMsg))
		if _, err := io.ReadFull(reader, buf); err != nil {
			t.Errorf("upstream read hijacked payload: %v", err)
			return
		}
		if _, err := conn.Write(buf); err != nil {
			t.Errorf("upstream echo payload: %v", err)
			return
		}
		if _, err := conn.Write([]byte(echoPayload)); err != nil {
			t.Errorf("upstream write payload: %v", err)
		}
	}()

	handler, logBuf := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/attach"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy server: %v", err)
	}

	reqStr := "POST /v1.45/containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		_ = clientConn.Close()
		t.Fatalf("write hijack request: %v", err)
	}

	clientBuf := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(clientBuf, nil)
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("read hijack response: %v", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = clientConn.Close()
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if upgrade := resp.Header.Get("Upgrade"); upgrade != "tcp" {
		_ = clientConn.Close()
		t.Fatalf("upgrade header = %q, want %q", upgrade, "tcp")
	}

	if _, err := clientConn.Write([]byte(clientMsg)); err != nil {
		_ = clientConn.Close()
		t.Fatalf("write hijacked payload: %v", err)
	}
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			_ = clientConn.Close()
			t.Fatalf("close client write side: %v", err)
		}
	}

	result := make([]byte, len(clientMsg)+len(echoPayload))
	if _, err := io.ReadFull(clientBuf, result); err != nil {
		_ = clientConn.Close()
		t.Fatalf("read hijacked response payload: %v", err)
	}
	if got, want := string(result), clientMsg+echoPayload; got != want {
		_ = clientConn.Close()
		t.Fatalf("hijacked payload = %q, want %q", got, want)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}

	waitForRequest()

	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream hijack server")
	}

	select {
	case got := <-upstreamPath:
		if got != "/v1.45/containers/abc/attach" {
			t.Fatalf("upstream path = %q, want %q", got, "/v1.45/containers/abc/attach")
		}
	default:
		t.Fatal("expected upstream hijack request")
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"decision":"allow"`) {
		t.Fatalf("expected allow decision in log output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"normalized_path":"/containers/abc/attach"`) {
		t.Fatalf("expected normalized path in log output, got: %s", logOutput)
	}
}

func TestFullProxyChainHijackDenied(t *testing.T) {
	socketPath := shortSocketPath(t, "chain-deny")
	handler, logBuf := newFullProxyChainHandler(t, socketPath, []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/_ping"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "deny all"},
	})
	addr, waitForRequest := startProxyChainServer(t, handler)

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1.45/containers/abc/attach?stream=1", nil)
	if err != nil {
		t.Fatalf("new denied hijack request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send denied hijack request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read denied hijack response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusForbidden, string(body))
	}
	if !strings.Contains(string(body), "request denied by sockguard policy") {
		t.Fatalf("expected denial body, got: %s", string(body))
	}

	waitForRequest()

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"msg":"request_denied"`) {
		t.Fatalf("expected request_denied log event, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"normalized_path":"/containers/abc/attach"`) {
		t.Fatalf("expected normalized path in denied log, got: %s", logOutput)
	}
}

func newFullProxyChainHandler(t *testing.T, socketPath string, rules []config.RuleConfig) (http.Handler, *bytes.Buffer) {
	t.Helper()

	compiled, err := config.CompileRules(rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var handler http.Handler = proxy.New(socketPath, logger)
	handler = proxy.HijackHandler(socketPath, logger, handler)
	handler = filter.Middleware(compiled, logger)(handler)
	handler = logging.AccessLogMiddleware(logger)(handler)

	return handler, &logBuf
}

func startProxyChainServer(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	done := make(chan struct{})
	var once sync.Once

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		once.Do(func() {
			close(done)
		})
	})

	srv := newHTTPServer(wrapped)
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	waitForRequest := func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for proxy request to finish")
		}
	}

	return ln.Addr().String(), waitForRequest
}

func startUnixHTTPUpstream(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})
}
