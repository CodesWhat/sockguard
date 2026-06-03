package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		{"logs follow", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1", true},
		{"logs follow true", http.MethodGet, "/containers/abc/logs?follow=true", true},
		{"logs no follow", http.MethodGet, "/containers/abc/logs?stdout=1", false},
		{"stats default stream", http.MethodGet, "/containers/abc/stats", true},
		{"stats stream=false", http.MethodGet, "/containers/abc/stats?stream=false", false},
		{"stats stream=0", http.MethodGet, "/containers/abc/stats?stream=0", false},
		{"container export", http.MethodGet, "/containers/abc/export", true},
		{"image get", http.MethodGet, "/images/myimg/get", true},
		{"image get namespaced", http.MethodGet, "/v1.43/images/ghcr.io/o/r/get", true},
		{"attach ws", http.MethodGet, "/containers/abc/attach/ws", true},
		{"wait", http.MethodPost, "/containers/abc/wait", true},
		{"build", http.MethodPost, "/build", true},
		{"image create pull", http.MethodPost, "/images/create?fromImage=redis", true},
		{"image load", http.MethodPost, "/images/load", true},
		{"image push", http.MethodPost, "/images/myimg/push", true},
		{"image push namespaced", http.MethodPost, "/images/ghcr.io/o/r/push", true},
		// Finite requests that must be bounded by the deadline.
		{"containers list", http.MethodGet, "/containers/json", false},
		{"container inspect", http.MethodGet, "/containers/abc/json", false},
		{"container create", http.MethodPost, "/containers/create", false},
		{"container start", http.MethodPost, "/containers/abc/start", false},
		{"image inspect", http.MethodGet, "/images/myimg/json", false},
		{"version", http.MethodGet, "/version", false},
		{"info", http.MethodGet, "/info", false},
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
