package cmd

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/health"
	"github.com/codeswhat/sockguard/v2/app/internal/inbound"
	"github.com/codeswhat/sockguard/v2/app/internal/metrics"
	"github.com/codeswhat/sockguard/v2/app/internal/proxy"
)

// auditSink stands in for the audit logger: the handler "emits" its event
// after it returns from the hijacked session, exactly when the real audit
// middleware would, and shutdown must not close the sink before that.
type auditSink struct {
	mu     sync.Mutex
	events []string
	closed bool
	late   []string // events that arrived after close
}

func (s *auditSink) emit(e string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.late = append(s.late, e)
		return
	}
	s.events = append(s.events, e)
}

func (s *auditSink) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

type joinHarness struct {
	member  *listenerMember
	sink    *auditSink
	started chan struct{}
	addr    string
}

// newJoinHarness serves a real tracked http.Server. The handler hijacks, then
// runs session(ctx) and finally emits an audit event, mirroring the audit
// middleware that logs only after the handler returns.
func newJoinHarness(t *testing.T, session func(shutdown <-chan struct{})) *joinHarness {
	t.Helper()
	h := &joinHarness{sink: &auditSink{}, started: make(chan struct{}, 8)}
	identity := inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkTCP}
	server := newHTTPServerForIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n")
		_ = buf.Flush()
		h.started <- struct{}{}
		session(proxy.HijackShutdown(r.Context()))
		_ = conn.Close()
		h.sink.emit("exec-session")
	}), identity)
	tracker := trackHijackedConnections(server)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	h.addr = ln.Addr().String()
	h.member = &listenerMember{identity: identity, listener: ln, server: server, hijacked: tracker}
	return h
}

func (h *joinHarness) shutdown(t *testing.T, grace time.Duration, logs *bytes.Buffer) {
	t.Helper()
	board := newListenerStatusBoard()
	board.register(h.member.identity, health.ListenerStateServing)
	deps := newServeTestDeps()
	deps.shutdownGracePeriod = grace
	deps.shutdownServer = func(*http.Server, context.Context) error { return nil }
	logger := slog.New(slog.NewTextHandler(logs, nil))
	shutdownServers(context.Background(), deps, testServeConfig(), []*listenerMember{h.member}, nil, metrics.NewRegistry(), board, logger)
}

// A hijacked handler that is quiet (no bytes flowing) and only exits when its
// context is canceled must be canceled by shutdown, and its audit event must
// land before the sink closes.
func TestShutdownJoinsHijackedHandlerBeforeSinkClose(t *testing.T) {
	t.Parallel()

	h := newJoinHarness(t, func(shutdown <-chan struct{}) {
		<-shutdown
		time.Sleep(100 * time.Millisecond) // finishing work after cancellation
	})
	live := dialHijack(t, h.addr)
	defer live.Close()
	<-h.started

	var logs bytes.Buffer
	h.shutdown(t, 10*time.Second, &logs)
	h.sink.close() // what runServe's deferred sink closers do right after shutdownServers

	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()
	if len(h.sink.events) != 1 || len(h.sink.late) != 0 {
		t.Fatalf("events=%v late=%v, want the session event persisted before sink close; logs=%s", h.sink.events, h.sink.late, logs.String())
	}
	if strings.Contains(logs.String(), "did not finish") {
		t.Fatalf("unexpected drain-expiry log: %s", logs.String())
	}
}

// Several sessions finishing concurrently with shutdown are all joined.
func TestShutdownJoinsConcurrentHijackedHandlers(t *testing.T) {
	t.Parallel()

	h := newJoinHarness(t, func(shutdown <-chan struct{}) {
		<-shutdown
		time.Sleep(50 * time.Millisecond)
	})
	const n = 5
	for range n {
		c := dialHijack(t, h.addr)
		defer c.Close()
		<-h.started
	}
	var logs bytes.Buffer
	h.shutdown(t, 10*time.Second, &logs)
	h.sink.close()

	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()
	if len(h.sink.events) != n || len(h.sink.late) != 0 {
		t.Fatalf("events=%d late=%d, want %d/0", len(h.sink.events), len(h.sink.late), n)
	}
}

// A handler that ignores cancellation must not hold shutdown past the shared
// deadline, and the expiry must be reported.
func TestShutdownReportsHijackedHandlersPastDeadline(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	h := newJoinHarness(t, func(<-chan struct{}) { <-release })
	t.Cleanup(func() { close(release) })
	live := dialHijack(t, h.addr)
	defer live.Close()
	<-h.started

	var logs bytes.Buffer
	start := time.Now()
	h.shutdown(t, 200*time.Millisecond, &logs)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("shutdown took %v, want bounded by the grace period", elapsed)
	}
	if !strings.Contains(logs.String(), "did not finish before the shutdown deadline") || !strings.Contains(logs.String(), "remaining=1") {
		t.Fatalf("logs = %q, want explicit drain-expiry report", logs.String())
	}
}

// A hijack that lands after shutdown began is canceled immediately instead of
// being registered as a handler shutdown will never wait for.
func TestHijackAfterShutdownIsCanceled(t *testing.T) {
	t.Parallel()

	var canceled atomic.Bool
	h := newJoinHarness(t, func(shutdown <-chan struct{}) {
		select {
		case <-shutdown:
			canceled.Store(true)
		case <-time.After(5 * time.Second):
		}
	})
	h.member.hijacked.closeAll() // shutdown already underway
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	select {
	case <-h.started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never hijacked")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !canceled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("late hijack context was not canceled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if remaining, err := h.member.hijacked.waitHandlers(context.Background()); err != nil || remaining != 0 {
		t.Fatalf("waitHandlers = (%d, %v), want drained", remaining, err)
	}
}
