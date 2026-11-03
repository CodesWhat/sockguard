package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// moby answers 101 when the request carries an Upgrade header and a headerless
// 200 raw stream when it does not (daemon/server/router/container/exec.go).
// passthroughDaemon mimics both shapes and records what it was sent.
type passthroughDaemon struct {
	mu      sync.Mutex
	headers http.Header
	done    chan struct{}
}

// startPassthroughDaemon accepts one connection. After the response head it
// echoes whatever the client sends, and once the client half-closes it sends
// "bye" and closes, so tests can observe half-close propagation both ways.
func startPassthroughDaemon(t *testing.T) (string, *passthroughDaemon) {
	t.Helper()
	socketPath := tempSocketPath(t, "passthrough")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	d := &passthroughDaemon{done: make(chan struct{})}
	go func() {
		defer close(d.done)
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
		_ = req.Body.Close()
		d.mu.Lock()
		d.headers = req.Header.Clone()
		d.mu.Unlock()

		if _, ok := req.Header["Upgrade"]; ok {
			_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		} else {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		}
		_, _ = io.WriteString(conn, "ready;")

		buf := make([]byte, 256)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				_, _ = conn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		_, _ = io.WriteString(conn, "bye")
	}()
	return socketPath, d

}

func (d *passthroughDaemon) header(name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.headers[name]
	if !ok {
		return "", false
	}
	return strings.Join(v, ","), true
}

func serveHijackHandler(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestHijackUpgradePassthrough(t *testing.T) {
	for _, mode := range []string{"socket", "dialer"} {
		for _, upgrade := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/upgrade=%v", mode, upgrade), func(t *testing.T) {
				socketPath, daemon := startPassthroughDaemon(t)
				logger := slog.New(slog.NewTextHandler(io.Discard, nil))
				next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("next handler must not run for a hijack endpoint")
				})
				var handler http.Handler
				if mode == "socket" {
					handler = PassClientUpgrade(HijackHandler(socketPath, logger, next))
				} else {
					handler = PassClientUpgrade(HijackHandlerWithDialer(unixSocketDialer{socketPath: socketPath}, time.Minute, logger, next))
				}
				addr := serveHijackHandler(t, handler)

				conn, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

				req := "POST /exec/abc/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
				if upgrade {
					req += "Connection: Upgrade\r\nUpgrade: tcp\r\n"
				}
				req += "Content-Length: 2\r\n\r\n{}"
				if _, err := io.WriteString(conn, req); err != nil {
					t.Fatalf("write request: %v", err)
				}

				br := bufio.NewReader(conn)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				wantStatus := http.StatusOK
				if upgrade {
					wantStatus = http.StatusSwitchingProtocols
				}
				if resp.StatusCode != wantStatus {
					t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
				}
				if got := resp.Header.Get("Content-Type"); got != "application/vnd.docker.raw-stream" {
					t.Errorf("Content-Type = %q", got)
				}

				connHdr, hasConn := daemon.header("Connection")
				upHdr, hasUp := daemon.header("Upgrade")
				if upgrade {
					if connHdr != "Upgrade" || upHdr != "tcp" {
						t.Errorf("upstream Connection/Upgrade = %q/%q, want Upgrade/tcp", connHdr, upHdr)
					}
				} else if hasConn || hasUp {
					t.Errorf("upstream saw Connection=%q Upgrade=%q, want neither", connHdr, upHdr)
				}

				// Bidirectional bytes: data the daemon sent right after the head
				// (already buffered) plus an echo of what the client sends.
				if _, err := io.WriteString(conn, "ping"); err != nil {
					t.Fatalf("write ping: %v", err)
				}
				got := make([]byte, len("ready;ping"))
				if _, err := io.ReadFull(br, got); err != nil {
					t.Fatalf("read stream: %v", err)
				}
				if string(got) != "ready;ping" {
					t.Fatalf("stream = %q, want %q", got, "ready;ping")
				}

				// Half-close: client EOF reaches the daemon, its "bye" and close
				// reach the client.
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatalf("CloseWrite: %v", err)
				}
				rest, err := io.ReadAll(br)
				if err != nil {
					t.Fatalf("read tail: %v", err)
				}
				if string(rest) != "bye" {
					t.Fatalf("tail = %q, want %q", rest, "bye")
				}
				<-daemon.done
			})
		}
	}
}

func TestHijackNonStreamResponsesForwardedNormally(t *testing.T) {
	cases := []struct {
		name     string
		upgrade  bool
		response string
		status   int
		body     string
	}{
		{"404 without upgrade", false, "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"message\":\"nf\"}\n", 404, "{\"message\":\"nf\"}\n"},
		{"404 with upgrade", true, "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"message\":\"nf\"}\n", 404, "{\"message\":\"nf\"}\n"},
		{"200 with length without upgrade", false, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", 200, "{}"},
		{"200 chunked without upgrade", false, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", 200, "hi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := tempSocketPath(t, "nonstream")
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
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err == nil {
					_ = req.Body.Close()
					_, _ = io.WriteString(conn, tc.response)
				}
			}()

			handler := PassClientUpgrade(HijackHandler(socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler()))
			addr := serveHijackHandler(t, handler)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			req := "POST /containers/abc/attach HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
			if tc.upgrade {
				req = "POST /containers/abc/attach HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
			}
			if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
				t.Fatalf("write: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || string(body) != tc.body {
				t.Fatalf("got %d %q, want %d %q", resp.StatusCode, body, tc.status, tc.body)
			}
		})
	}
}

// TestHijackRawStreamInactivityTimeout covers the 200 form: it must be torn
// down by the same inactivity deadline as the 101 form.
func TestHijackRawStreamInactivityTimeout(t *testing.T) {
	socketPath, daemon := startPassthroughDaemon(t)
	handler := PassClientUpgrade(HijackHandlerWithDialer(unixSocketDialer{socketPath: socketPath}, 150*time.Millisecond,
		slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler()))
	addr := serveHijackHandler(t, handler)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "POST /exec/abc/start HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("read response: %v %v", resp, err)
	}
	start := time.Now()
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("expected clean close after idle timeout, got %v", err)
	}
	if string(rest) != "ready;" {
		t.Errorf("stream = %q, want %q", rest, "ready;")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("idle teardown took %v", elapsed)
	}
	select {
	case <-daemon.done:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection was not closed after idle timeout")
	}
}

// closeRecordingConn wraps a net.Conn and records Close.
type closeRecordingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeRecordingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type closedClientWriter struct {
	header http.Header
	conn   net.Conn
}

func (w *closedClientWriter) Header() http.Header         { return w.header }
func (w *closedClientWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *closedClientWriter) WriteHeader(int)             {}
func (w *closedClientWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

// TestHijackRawStreamHeadWriteFailureClosesBothConns: the client is gone by the
// time the 200 head is written, so the write fails; both the client conn and
// the upstream conn must be closed rather than left half-open.
func TestHijackRawStreamHeadWriteFailureClosesBothConns(t *testing.T) {
	socketPath, daemon := startPassthroughDaemon(t)

	clientEnd, peer := net.Pipe()
	_ = peer.Close()
	client := &closeRecordingConn{Conn: clientEnd, closed: make(chan struct{})}
	w := &closedClientWriter{header: http.Header{}, conn: client}

	req, err := http.NewRequest(http.MethodPost, "http://x/exec/abc/start", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		PassClientUpgrade(HijackHandler(socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler())).ServeHTTP(w, req)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after head write failure")
	}
	select {
	case <-client.closed:
	default:
		t.Error("client conn was not closed")
	}
	select {
	case <-daemon.done:
	case <-time.After(3 * time.Second):
		t.Error("upstream conn was not closed")
	}
}

// Without PassClientUpgrade (any upstream not probed as Docker, Podman
// included) the upstream is always asked to upgrade and the client gets the 101
// even when it sent no Upgrade header.
func TestHijackForcesUpgradeWithoutPassthrough(t *testing.T) {
	// The mock answers 200 raw-stream to a request without Upgrade. If the
	// proxy forwarded the client's choice the client would see that 200.
	socketPath, daemon := startPassthroughDaemon(t)
	handler := HijackHandler(socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler())
	addr := serveHijackHandler(t, handler)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "POST /exec/abc/start HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if c, u := func() (string, string) {
		a, _ := daemon.header("Connection")
		b, _ := daemon.header("Upgrade")
		return a, b
	}(); c != "Upgrade" || u != "tcp" {
		t.Errorf("upstream Connection/Upgrade = %q/%q, want Upgrade/tcp", c, u)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_, _ = io.ReadAll(br)
}
