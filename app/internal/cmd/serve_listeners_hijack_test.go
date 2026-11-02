package cmd

import (
	"bufio"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func trackedHijackCount(tracker *hijackedConnTracker) int {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return len(tracker.conns)
}

// startHijackServer serves a real net/http server whose handler hijacks the
// connection and hands the (possibly wrapped) conn to onHijack.
func startHijackServer(t *testing.T, onHijack func(net.Conn)) (*http.Server, *hijackedConnTracker, string) {
	t.Helper()
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("Hijack: %v", err)
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n")
			_ = buf.Flush()
			onHijack(conn)
		}),
	}
	tracker := trackHijackedConnections(server)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return server, tracker, ln.Addr().String()
}

func dialHijack(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatalf("read 101: %v", err)
	}
	return c
}

func waitForTracked(t *testing.T, tracker *hijackedConnTracker, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for trackedHijackCount(tracker) != want {
		if time.Now().After(deadline) {
			t.Fatalf("tracked hijacked conns = %d, want %d", trackedHijackCount(tracker), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHijackedConnTrackerUnregistersCompletedSessions(t *testing.T) {
	t.Parallel()

	_, tracker, addr := startHijackServer(t, func(conn net.Conn) { _ = conn.Close() })
	for range 3 {
		c := dialHijack(t, addr)
		_ = c.Close()
	}
	waitForTracked(t, tracker, 0)
}

func TestHijackedConnTrackerKeepsLiveSessionsForShutdown(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	_, tracker, addr := startHijackServer(t, func(conn net.Conn) {
		defer wg.Done()
		<-release
		_ = conn.Close() // handler closes after shutdown already did: must not panic or error out the server
	})
	live := dialHijack(t, addr)
	waitForTracked(t, tracker, 1)

	tracker.closeAll()
	if _, err := live.Read(make([]byte, 1)); err == nil {
		t.Fatal("live hijacked peer stayed open after closeAll")
	}
	close(release)
	wg.Wait()
	if got := trackedHijackCount(tracker); got != 0 {
		t.Fatalf("tracked after closeAll = %d, want 0", got)
	}
}

func TestHijackedConnTrackerConcurrentCompletionAndShutdown(t *testing.T) {
	t.Parallel()

	_, tracker, addr := startHijackServer(t, func(conn net.Conn) { _ = conn.Close(); _ = conn.Close() })
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Shutdown may close the peer mid-handshake; only the race matters here.
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			_, _ = bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
		}()
	}
	tracker.closeAll()
	wg.Wait()
}
