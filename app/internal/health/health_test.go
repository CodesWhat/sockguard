package health

import (
	"context"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/version"
)

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

type noopConn struct{}

func (noopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (noopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (noopConn) Close() error                     { return nil }
func (noopConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "local", Net: "unix"} }
func (noopConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "remote", Net: "unix"} }
func (noopConn) SetDeadline(time.Time) error      { return nil }
func (noopConn) SetReadDeadline(time.Time) error  { return nil }
func (noopConn) SetWriteDeadline(time.Time) error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type headerCallTrackingWriter struct {
	*httptest.ResponseRecorder
	headerCalls int
}

func (w *headerCallTrackingWriter) Header() http.Header {
	w.headerCalls++
	return w.ResponseRecorder.Header()
}

func TestHealthReachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	startTime := time.Now().Add(-90 * time.Second)
	handler := Handler(sock, startTime, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "healthy" {
		t.Errorf("expected status healthy, got %v", body.Status)
	}
	if body.Upstream != "connected" {
		t.Errorf("expected upstream connected, got %v", body.Upstream)
	}
	if body.Error != "" {
		t.Errorf("expected empty error for healthy response, got %q", body.Error)
	}
	if body.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, body.Version)
	}
	if body.UptimeSeconds < 90 {
		t.Errorf("expected uptime >= 90, got %d", body.UptimeSeconds)
	}
}

func TestHealthHandlerSetsContentTypeOnce(t *testing.T) {
	handler := Handler("/nonexistent/socket.sock", time.Now(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := &headerCallTrackingWriter{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(rec, req)

	if rec.headerCalls != 1 {
		t.Fatalf("Header() calls = %d, want 1", rec.headerCalls)
	}
	if got := rec.Result().Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func TestHealthCheckerTimesOutWithBlockingDial(t *testing.T) {
	checker := newUpstreamHealthChecker(
		0,
		10*time.Millisecond,
		time.Now,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	start := time.Now()
	status, err := checker.check(context.Background(), "/tmp/upstream.sock")

	if status != "unreachable" {
		t.Fatalf("status = %q, want unreachable", status)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout check took %v, want under 250ms", elapsed)
	}
}

func TestHealthUnreachable(t *testing.T) {
	startTime := time.Now().Add(-45 * time.Second)
	handler := Handler("/nonexistent/socket.sock", startTime, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var body HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "unhealthy" {
		t.Errorf("expected status unhealthy, got %v", body.Status)
	}
	if body.Upstream != "unreachable" {
		t.Errorf("expected upstream unreachable, got %v", body.Upstream)
	}
	if body.Error != "upstream unreachable" {
		t.Errorf("expected generic error message, got %q", body.Error)
	}
	if body.Version != version.Version {
		t.Errorf("expected version %q, got %q", version.Version, body.Version)
	}
	if body.UptimeSeconds < 45 {
		t.Errorf("expected uptime >= 45, got %d", body.UptimeSeconds)
	}
	if strings.Contains(rec.Body.String(), "/nonexistent/socket.sock") {
		t.Fatalf("response leaked upstream socket path: %q", rec.Body.String())
	}
}

func TestHealthCachesUpstreamStatusWithinTTL(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return noopConn{}, nil
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("first check = (%q, %v), want connected with nil error", status, err)
	}

	nowOffset.Store(int64(1500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("cached check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls within TTL = %d, want 1", dialCalls.Load())
	}

	nowOffset.Store(int64(2500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "connected" || err != nil {
		t.Fatalf("post-TTL check = (%q, %v), want connected with nil error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after TTL = %d, want 2", dialCalls.Load())
	}
}

func TestHealthDoesNotCacheUnhealthyStatusWithinTTL(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("upstream down")
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("first check = (%q, %v), want unreachable with error", status, err)
	}

	nowOffset.Store(int64(1500 * time.Millisecond))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("second check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls within TTL after unhealthy result = %d, want 2", dialCalls.Load())
	}
}

func TestHealthBrieflyCachesUnhealthyStatusForLateCallers(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var nowOffset atomic.Int64
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time {
			return baseNow.Add(time.Duration(nowOffset.Load()))
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("upstream down")
		},
	)

	status, err := checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("first check = (%q, %v), want unreachable with error", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("immediate follow-up check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls for immediate follow-up = %d, want 1", dialCalls.Load())
	}

	nowOffset.Store(int64(time.Second))
	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("later check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after brief failure cache window = %d, want 2", dialCalls.Load())
	}
}

func TestHealthDoesNotCacheCallerCancelledFailure(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		func() time.Time { return baseNow },
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	status, err := checker.check(canceledCtx, "/tmp/upstream.sock")
	if status != "unreachable" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled check = (%q, %v), want unreachable with context canceled", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("fresh check = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after canceled failure = %d, want 2", dialCalls.Load())
	}
}

func TestHealthDoesNotCacheCallerDeadlineFailure(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		50*time.Millisecond,
		func() time.Time { return baseNow },
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	// Caller deadline fires before dial returns. Caller gave up, not upstream,
	// so we must not cache this as a health verdict.
	deadlineCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	status, err := checker.check(deadlineCtx, "/tmp/upstream.sock")
	if status != "unreachable" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline check = (%q, %v), want unreachable with context deadline exceeded", status, err)
	}

	status, err = checker.check(context.Background(), "/tmp/upstream.sock")
	if status != "unreachable" || err == nil {
		t.Fatalf("fresh check after deadline = (%q, %v), want unreachable with error", status, err)
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("dial calls after deadline failure = %d, want 2 (no cache)", dialCalls.Load())
	}
}

func TestHealthCheckerCoalescesConcurrentCacheMisses(t *testing.T) {
	const callers = 16

	releaseDial := make(chan struct{})
	startChecks := make(chan struct{})
	dialEntered := make(chan struct{}, callers)
	results := make(chan struct {
		status string
		err    error
	}, callers)

	var ready sync.WaitGroup
	ready.Add(callers)

	var wg sync.WaitGroup
	var dialCalls atomic.Int32

	checker := newUpstreamHealthChecker(
		2*time.Second,
		3*time.Second,
		time.Now,
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			dialEntered <- struct{}{}
			<-releaseDial
			return nil, errors.New("upstream down")
		},
	)
	// Keep the failure cache comfortably open so any straggler that enters
	// check() after the leader cleared inFlight still hits the cached error
	// instead of becoming a new leader. Covers scheduling jitter under -race.
	checker.failureTTL = 10 * time.Second

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-startChecks
			status, err := checker.check(context.Background(), "/tmp/upstream.sock")
			results <- struct {
				status string
				err    error
			}{status: status, err: err}
		}()
	}

	ready.Wait()
	close(startChecks)

	select {
	case <-dialEntered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected at least one upstream dial")
	}

	close(releaseDial)
	wg.Wait()
	close(results)

	if dialCalls.Load() != 1 {
		t.Fatalf("dial calls = %d, want 1", dialCalls.Load())
	}

	for result := range results {
		if result.status != "unreachable" || result.err == nil {
			t.Fatalf("check = (%q, %v), want unreachable with error", result.status, result.err)
		}
	}
}

type failingWriter struct {
	header http.Header
	status int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestHealthHandlerHealthyEncodeFailure(t *testing.T) {
	sock := fmt.Sprintf("/tmp/health-encode-%d.sock", os.Getpid())
	_ = os.Remove(sock)
	t.Cleanup(func() {
		_ = os.Remove(sock)
	})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	handler := Handler(sock, time.Now(), testLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	writer := &failingWriter{}

	handler.ServeHTTP(writer, req)

	if writer.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusOK)
	}
}

func TestHealthHandlerUnhealthyEncodeFailure(t *testing.T) {
	handler := Handler("/nonexistent/socket.sock", time.Now(), testLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	writer := &failingWriter{}

	handler.ServeHTTP(writer, req)

	if writer.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusServiceUnavailable)
	}
}
