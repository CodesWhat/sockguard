package cmd

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/proxy"
)

// TestHijackedConnTrackerReleasesNonUpgradeRawStream drives the real hijack
// handler behind the tracker with a client that sends no Upgrade header and an
// upstream that answers 200 and streams raw: the conn must register while the
// stream is live and be released once it ends.
func TestHijackedConnTrackerReleasesNonUpgradeRawStream(t *testing.T) {
	socketPath := "/tmp/sg-tracker-" + time.Now().Format("150405.000000") + ".sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	finish := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\nhello")
		<-finish
	}()

	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler:           proxy.PassClientUpgrade(proxy.HijackHandler(socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler())),
	}
	tracker := trackHijackedConnections(server)
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	go func() { _ = server.Serve(clientLn) }()
	t.Cleanup(func() { _ = server.Close() })

	conn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "POST /exec/abc/start HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("read response: %v %v", resp, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "hello" {
		t.Fatalf("stream = %q, %v", got, err)
	}
	waitForTracked(t, tracker, 1)

	close(finish)
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	// Same teardown as the 101 form: the session ends once the client side
	// half-closes too.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	waitForTracked(t, tracker, 0)
}

type closedPipeHijackWriter struct {
	header http.Header
	conn   net.Conn
}

func (w *closedPipeHijackWriter) Header() http.Header         { return w.header }
func (w *closedPipeHijackWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *closedPipeHijackWriter) WriteHeader(int)             {}
func (w *closedPipeHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

// TestHijackedConnTrackerReleasesWhenRawStreamHeadWriteFails: the client conn
// is dead when the 200 head is written. The failed session must still release
// the conn from the tracker and close the upstream.
func TestHijackedConnTrackerReleasesWhenRawStreamHeadWriteFails(t *testing.T) {
	socketPath := "/tmp/sg-tracker-fail-" + time.Now().Format("150405.000000") + ".sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	upstreamClosed := make(chan struct{})
	go func() {
		defer close(upstreamClosed)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		_, _ = io.Copy(io.Discard, br) // returns when sockguard closes the upstream conn
	}()

	clientEnd, peer := net.Pipe()
	_ = peer.Close()
	tracker := &hijackedConnTracker{conns: map[net.Conn]struct{}{clientEnd: {}}}
	w := &hijackTrackingWriter{
		ResponseWriter: &closedPipeHijackWriter{header: http.Header{}, conn: clientEnd},
		tracker:        tracker,
	}
	req, err := http.NewRequest(http.MethodPost, "http://x/exec/abc/start", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	proxy.PassClientUpgrade(proxy.HijackHandler(socketPath, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler())).ServeHTTP(w, req)

	waitForTracked(t, tracker, 0)
	select {
	case <-upstreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream conn was not closed")
	}
}
