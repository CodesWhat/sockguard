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
		// Finite requests that must be bounded by the deadline.
		{"containers list", http.MethodGet, "/containers/json", false},
		{"container inspect", http.MethodGet, "/containers/abc/json", false},
		{"container create", http.MethodPost, "/containers/create", false},
		{"container start", http.MethodPost, "/containers/abc/start", false},
		{"image inspect", http.MethodGet, "/images/myimg/json", false},
		{"plugin create", http.MethodPost, "/plugins/create", true},
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

func TestIsLongLivedUpstreamRequestPodmanTopStream(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"native container true", "/libpod/containers/abc/top?stream=true", true},
		{"versioned native container one", "/v5.0.0/libpod/containers/abc/top?stream=1", true},
		{"native pod lowercase t", "/libpod/pods/abc/top?stream=t", true},
		{"versioned native pod uppercase true", "/v5.0.0/libpod/pods/abc/top?stream=TRUE", true},
		{"native container mixed-case true", "/libpod/containers/abc/top?stream=True", true},
		{"native pod lowercase on", "/libpod/pods/abc/top?stream=on", true},
		{"native container uppercase query key", "/libpod/containers/abc/top?Stream=true", true},
		{"native pod mixed-case query key", "/libpod/pods/abc/top?sTrEaM=on", true},
		{"native container unsupported mixed-case true", "/libpod/containers/abc/top?stream=TrUe", false},
		{"native container false", "/libpod/containers/abc/top?stream=false", false},
		{"native pod zero", "/libpod/pods/abc/top?stream=0", false},
		{"native container lowercase f", "/libpod/containers/abc/top?stream=f", false},
		{"native container uppercase f", "/libpod/containers/abc/top?stream=F", false},
		{"native pod uppercase false", "/libpod/pods/abc/top?stream=FALSE", false},
		{"native container mixed-case false", "/libpod/containers/abc/top?stream=False", false},
		{"native pod omitted", "/libpod/pods/abc/top", false},
		{"native pod empty", "/libpod/pods/abc/top?stream=", false},
		{"native container repeated last true", "/libpod/containers/abc/top?stream=false&stream=true", true},
		{"native pod repeated last false", "/libpod/pods/abc/top?stream=true&stream=false", false},
		{"native container repeated case-insensitive key last true", "/libpod/containers/abc/top?Stream=false&Stream=true", true},
		{"native pod repeated case-insensitive key last false", "/libpod/pods/abc/top?STREAM=true&STREAM=false", false},
		{"native container invalid yes", "/libpod/containers/abc/top?stream=yes", false},
		{"native pod invalid uppercase on", "/libpod/pods/abc/top?stream=ON", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if got := isLongLivedUpstreamRequest(httptest.NewRecorder(), req); got != tc.want {
				t.Fatalf("isLongLivedUpstreamRequest(GET %s) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

func TestWithRequestTimeout_DockerCompatibleTopUsesUpstreamFlavor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		podmanUpstream bool
		target         string
		wantUnbounded  bool
	}{
		{name: "Docker remains finite", target: "/containers/abc/top?stream=true", wantUnbounded: false},
		{name: "Podman streams", podmanUpstream: true, target: "/containers/abc/top?stream=true", wantUnbounded: true},
		{name: "Podman false remains finite", podmanUpstream: true, target: "/containers/abc/top?stream=false", wantUnbounded: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			hasDeadline := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				reached = true
				_, hasDeadline = r.Context().Deadline()
			})
			WithRequestTimeoutForFlavor(next, 50*time.Millisecond, tc.podmanUpstream).
				ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.target, nil))
			if !reached {
				t.Fatal("request did not reach the wrapped handler")
			}
			if got := !hasDeadline; got != tc.wantUnbounded {
				t.Fatalf("unbounded GET %s with podman=%v = %v, want %v", tc.target, tc.podmanUpstream, got, tc.wantUnbounded)
			}
		})
	}
}

func TestIsLongLivedUpstreamRequestPodmanTopMixedCaseDuplicateStreamKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		podmanUpstream bool
		target         string
		want           bool
	}{
		{
			name:   "native truthy second case-folded group",
			target: "/libpod/containers/abc/top?stream=false&Stream=true",
			want:   true,
		},
		{
			name:   "native truthy first case-folded group",
			target: "/libpod/pods/abc/top?stream=true&Stream=false",
			want:   true,
		},
		{
			name:   "native identical-key last true",
			target: "/libpod/containers/abc/top?stream=false&stream=true&Stream=false",
			want:   true,
		},
		{
			name:   "native identical-key last false in every group",
			target: "/libpod/pods/abc/top?stream=true&stream=false&Stream=0&STREAM=F",
			want:   false,
		},
		{
			name:           "Podman-compatible truthy second case-folded group",
			podmanUpstream: true,
			target:         "/containers/abc/top?stream=false&Stream=yes",
			want:           true,
		},
		{
			name:           "Podman-compatible false in every group",
			podmanUpstream: true,
			target:         "/containers/abc/top?stream=true&stream=false&Stream=no&STREAM=none",
			want:           false,
		},
		{
			name:   "Docker-compatible remains finite",
			target: "/containers/abc/top?stream=false&Stream=true",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 256; i++ {
				req := httptest.NewRequest(http.MethodGet, tc.target, nil)
				if got := isLongLivedUpstreamRequestForFlavor(httptest.NewRecorder(), req, tc.podmanUpstream); got != tc.want {
					t.Fatalf("iteration %d: isLongLivedUpstreamRequestForFlavor(GET %s, podman=%v) = %v, want %v", i, tc.target, tc.podmanUpstream, got, tc.want)
				}
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
