package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

func TestIsLongLivedUpstreamRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		target string
		want   bool
	}{
		{"events", http.MethodGet, "/events", true},
		{"events versioned", http.MethodGet, "/v1.43/events", true},
		{"libpod events", http.MethodGet, "/libpod/events", true},
		{"libpod events versioned", http.MethodGet, "/v5.0.0/libpod/events", true},
		{"libpod logs follow", http.MethodGet, "/libpod/containers/abc/logs?follow=1", true},
		{"libpod stats stream", http.MethodGet, "/v5.0.0/libpod/containers/abc/stats?stream=1", true},
		{"libpod export", http.MethodGet, "/libpod/containers/abc/export", true},
		{"libpod wait", http.MethodPost, "/v5.0.0/libpod/containers/abc/wait", true},
		{"libpod build", http.MethodPost, "/libpod/build", true},
		{"libpod image push", http.MethodPost, "/v5.0.0/libpod/images/example/push", true},
		{"logs follow", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1", true},
		{"logs follow true", http.MethodGet, "/containers/abc/logs?follow=true", true},
		{"logs follow yes", http.MethodGet, "/containers/abc/logs?follow=yes", true},
		{"logs follow no", http.MethodGet, "/containers/abc/logs?follow=no", false},
		{"logs follow none", http.MethodGet, "/containers/abc/logs?follow=none", false},
		{"logs follow zero", http.MethodGet, "/containers/abc/logs?follow=0", false},
		{"logs no follow", http.MethodGet, "/containers/abc/logs?stdout=1", false},
		{"stats default stream", http.MethodGet, "/containers/abc/stats", true},
		{"stats stream=false", http.MethodGet, "/containers/abc/stats?stream=false", false},
		{"stats stream=0", http.MethodGet, "/containers/abc/stats?stream=0", false},
		{"stats stream=no", http.MethodGet, "/containers/abc/stats?stream=no", false},
		{"stats stream=none", http.MethodGet, "/containers/abc/stats?stream=none", false},
		{"stats stream=1", http.MethodGet, "/containers/abc/stats?stream=1", true},
		{"container export", http.MethodGet, "/containers/abc/export", true},
		{"container archive get (docker cp from)", http.MethodGet, "/containers/abc/archive?path=/data", true},
		{"container archive get versioned", http.MethodGet, "/v1.43/containers/abc/archive?path=/data", true},
		{"container archive put (docker cp into)", http.MethodPut, "/containers/abc/archive?path=/data", true},
		{"container archive put versioned", http.MethodPut, "/v1.43/containers/abc/archive?path=/data", true},
		{"container archive post not exempt", http.MethodPost, "/containers/abc/archive?path=/data", false},
		{"image get", http.MethodGet, "/images/myimg/get", true},
		{"image get namespaced", http.MethodGet, "/v1.43/images/ghcr.io/o/r/get", true},
		{"attach ws", http.MethodGet, "/containers/abc/attach/ws", true},
		{"wait", http.MethodPost, "/containers/abc/wait", true},
		{"build", http.MethodPost, "/build", true},
		{"image create pull", http.MethodPost, "/images/create?fromImage=redis", true},
		{"image load", http.MethodPost, "/images/load", true},
		{"image push", http.MethodPost, "/images/myimg/push", true},
		{"image push namespaced", http.MethodPost, "/images/ghcr.io/o/r/push", true},
		{"plugin pull", http.MethodPost, "/plugins/pull", true},
		{"plugin push", http.MethodPost, "/plugins/myplugin/push", true},
		{"plugin upgrade", http.MethodPost, "/plugins/myplugin/upgrade", true},
		{"service logs follow", http.MethodGet, "/services/abc/logs?follow=1", true},
		{"service logs follow versioned", http.MethodGet, "/v1.43/services/abc/logs?follow=true", true},
		{"libpod service logs follow", http.MethodGet, "/libpod/services/abc/logs?follow=1", true},
		{"task logs follow", http.MethodGet, "/tasks/abc/logs?follow=1", true},
		{"libpod task logs follow", http.MethodGet, "/libpod/tasks/abc/logs?follow=1", true},
		{"images export", http.MethodGet, "/images/export?names=redis", true},
		{"libpod images export", http.MethodGet, "/libpod/images/export?names=redis", true},
		{"libpod images pull", http.MethodPost, "/libpod/images/pull?reference=redis", true},
		{"images pull", http.MethodPost, "/images/pull?fromImage=redis", true},
		{"buildkit session", http.MethodPost, "/session", true},
		{"buildkit grpc", http.MethodPost, "/grpc", true},
		{"buildkit session versioned", http.MethodPost, "/v1.43/session", true},
		// Finite requests that must be bounded by the deadline.
		{"containers list", http.MethodGet, "/containers/json", false},
		{"container inspect", http.MethodGet, "/containers/abc/json", false},
		{"container create", http.MethodPost, "/containers/create", false},
		{"container start", http.MethodPost, "/containers/abc/start", false},
		{"image inspect", http.MethodGet, "/images/myimg/json", false},
		{"plugin create", http.MethodPost, "/plugins/create", true},
		{"version", http.MethodGet, "/version", false},
		{"info", http.MethodGet, "/info", false},
		{"service logs no follow", http.MethodGet, "/services/abc/logs", false},
		{"service inspect not exempt", http.MethodGet, "/services/abc", false},
		{"services list not exempt", http.MethodGet, "/services", false},
		{"tasks list not exempt", http.MethodGet, "/tasks", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if got := isLongLivedUpstreamRequest(httptest.NewRecorder(), req); got != tc.want {
				t.Fatalf("isLongLivedUpstreamRequest(%s %s) = %v, want %v", tc.method, tc.target, got, tc.want)
			}
		})
	}
}

func TestWithRequestTimeout_AppliesDeadlineToFiniteRequest(t *testing.T) {
	t.Parallel()
	var hasDeadline bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, hasDeadline = r.Context().Deadline()
	})
	WithRequestTimeout(next, 50*time.Millisecond).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if !hasDeadline {
		t.Fatal("expected a context deadline on a finite request")
	}
}

func TestWithRequestTimeout_SkipsDeadlineForLongLivedRequest(t *testing.T) {
	t.Parallel()
	hasDeadline := true
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, hasDeadline = r.Context().Deadline()
	})
	WithRequestTimeout(next, 50*time.Millisecond).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
	if hasDeadline {
		t.Fatal("expected no context deadline on a long-lived /events request")
	}
}

func TestWithRequestTimeout_DisabledLeavesRequestUnbounded(t *testing.T) {
	t.Parallel()
	hasDeadline := true
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, hasDeadline = r.Context().Deadline()
	})
	WithRequestTimeout(next, 0).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/json", nil))
	if hasDeadline {
		t.Fatal("expected no deadline when the request timeout is disabled")
	}
}

func TestWithRequestTimeout_HungUpstreamReturnsGatewayTimeout(t *testing.T) {
	t.Parallel()
	socketPath := tempSocketPath(t, "timeout")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release // hang until the test releases it
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	wrapped := WithRequestTimeout(NewWithOptions(socketPath, testLogger(), Options{}), 75*time.Millisecond)
	front := httptest.NewServer(wrapped)
	t.Cleanup(front.Close)

	resp, err := http.Get(front.URL + "/containers/json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusGatewayTimeout)
	}
}

// streamingRoundTripper is a mock upstream transport that answers every
// request with a 200 whose body emits one newline-delimited chunk every
// interval, up to chunks total, honoring the request's context so a deadline
// attached upstream (by WithRequestTimeout) cuts the stream exactly like a
// real dockerd connection would.
type streamingRoundTripper struct {
	interval time.Duration
	chunks   int
}

func (rt *streamingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       &streamingBody{ctx: req.Context(), interval: rt.interval, remaining: rt.chunks},
		Request:    req,
	}, nil
}

type streamingBody struct {
	ctx       context.Context
	interval  time.Duration
	remaining int
}

func (b *streamingBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-time.After(b.interval):
	}
	b.remaining--
	return copy(p, "tick\n"), nil
}

func (b *streamingBody) Close() error { return nil }

// hangingRoundTripper never returns a response until the request's context
// is done, modeling a daemon that accepts the connection but never answers.
type hangingRoundTripper struct{}

func (hangingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestWithRequestTimeout_DoesNotSeverLiveStream drives real HTTP requests
// through WithRequestTimeout wrapping a live proxy.NewWithTransport, backed
// by a mock upstream that streams a chunk every 50ms. Unlike
// TestWithRequestTimeout_SkipsDeadlineForLongLivedRequest (which only proves
// isLongLivedUpstreamRequest classifies the path correctly, using a stub
// handler and a recorder), this proves the stream actually survives the
// deadline window in behavior: each exempt path must still be receiving
// chunks well past when a 200ms deadline would have fired.
func TestWithRequestTimeout_DoesNotSeverLiveStream(t *testing.T) {
	t.Parallel()

	const (
		streamInterval = 50 * time.Millisecond
		totalChunks    = 20
		requestTimeout = 200 * time.Millisecond
		minChunks      = 8 // 8*streamInterval = 400ms, well past requestTimeout
	)

	exempt := []struct {
		name   string
		method string
		target string
	}{
		{"service logs follow", http.MethodGet, "/services/abc/logs?follow=1"},
		{"task logs follow", http.MethodGet, "/tasks/abc/logs?follow=1"},
		{"libpod images pull", http.MethodPost, "/libpod/images/pull?reference=redis"},
		{"images export", http.MethodGet, "/images/export?names=redis"},
		{"buildkit session", http.MethodPost, "/session"},
		{"buildkit grpc", http.MethodPost, "/grpc"},
	}

	for _, tc := range exempt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rt := &streamingRoundTripper{interval: streamInterval, chunks: totalChunks}
			rp := NewWithTransport(rt, testLogger(), Options{})
			handler := WithRequestTimeout(rp, requestTimeout)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)

			req, err := http.NewRequest(tc.method, srv.URL+tc.target, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}

			scanner := bufio.NewScanner(resp.Body)
			count := 0
			for count < minChunks && scanner.Scan() {
				count++
			}
			if count < minChunks {
				t.Fatalf("received %d chunks before the stream ended (err: %v), want at least %d — the request deadline likely severed it",
					count, scanner.Err(), minChunks)
			}
		})
	}

	// Control: a known-finite path whose upstream never answers still gets
	// bounded by the deadline and returns 504, proving the exemptions above
	// aren't just a blanket "never time out" change.
	t.Run("finite path with hung upstream still returns 504", func(t *testing.T) {
		t.Parallel()

		rp := NewWithTransport(hangingRoundTripper{}, testLogger(), Options{})
		handler := WithRequestTimeout(rp, 100*time.Millisecond)
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/containers/json")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusGatewayTimeout)
		}
	})
}

// The deadline's 504 is a PRE-HEADER outcome only. Once the daemon has
// committed response headers, Go's ReverseProxy cannot replace the status: a
// read error during copyResponse is not routed to ErrorHandler, so the client
// keeps the already-sent status and sees a truncated body. The deadline still
// does its real job here — it aborts the hung upstream connection instead of
// pinning the request — but it does not, and cannot, surface as 504.
//
// This is the exact case WithRequestTimeout exists for (headers arrive
// promptly, body hangs), so the distinction was easy to state backwards, and
// was: both this function's doc comment and configuration.mdx claimed a 504
// here until 2026-08-29.
func TestWithRequestTimeout_BodyPhaseTruncatesRatherThanReturning504(t *testing.T) {
	t.Parallel()
	socketPath := tempSocketPath(t, "bodyphase")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		fmt.Fprint(w, `{"partial":`)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release // hang the body well past the deadline
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	wrapped := WithRequestTimeout(NewWithOptions(socketPath, testLogger(), Options{}), 75*time.Millisecond)
	front := httptest.NewServer(wrapped)
	t.Cleanup(front.Close)

	resp, err := http.Get(front.URL + "/containers/json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (headers were already committed)", resp.StatusCode, http.StatusOK)
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr == nil {
		t.Fatalf("body read succeeded (%q), want a truncation error", string(body))
	}
	if string(body) != `{"partial":` {
		t.Fatalf("body = %q, want the partial prefix written before the hang", string(body))
	}
}

func TestRequestNormalizedPathPrefersAttachedMetaNormPath(t *testing.T) {
	// Covers the "meta.NormPath != \"\"" guard at timeout.go:192: when
	// access-log middleware has already attached a non-empty NormPath to
	// the request meta, requestNormalizedPath must return it as-is rather
	// than recomputing filter.NormalizePath from the raw URL.
	meta := &logging.RequestMeta{NormPath: "/containers/redacted/logs"}
	req := httptest.NewRequest(http.MethodGet, "/v1.43/containers/abc123/logs", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	w := httptest.NewRecorder()

	got := requestNormalizedPath(w, req)
	if got != meta.NormPath {
		t.Fatalf("requestNormalizedPath() = %q, want attached meta.NormPath %q", got, meta.NormPath)
	}
}

func TestRequestNormalizedPathFallsBackWhenMetaNormPathEmpty(t *testing.T) {
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.43/containers/abc123/logs", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	w := httptest.NewRecorder()

	got := requestNormalizedPath(w, req)
	want := filter.NormalizePath(req.URL.Path)
	if got != want {
		t.Fatalf("requestNormalizedPath() = %q, want fallback %q when meta.NormPath is empty", got, want)
	}
}
