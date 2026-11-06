package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/clientacl"
	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/proxy"
	"github.com/codeswhat/sockguard/v3/app/internal/ratelimit"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

func TestRuntimeRateLimitClassifierUsesEngineFlavor(t *testing.T) {
	for _, flavor := range []upstreamflavor.Flavor{upstreamflavor.Docker, upstreamflavor.Podman} {
		t.Run(string(flavor), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "ci", Limits: config.LimitsConfig{Concurrency: &config.ConcurrencyConfig{MaxInflight: 1}}}}
			logger := newDiscardLogger()
			mw, stop, active := buildRateLimitMiddleware(&cfg, logger, &serveRuntime{upstreamFlavor: flavor})
			if !active || mw == nil {
				t.Fatal("concurrency limiter was not constructed")
			}
			t.Cleanup(stop)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			done := make(chan struct{})
			handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/probe" {
					entered <- struct{}{}
					<-release
				}
			}))
			handler = clientacl.MiddlewareWithRoundTripper(nil, logger, clientacl.Options{Profiles: clientacl.ProfileOptions{DefaultProfile: "ci"}})(handler)
			go func() {
				defer close(done)
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/containers/abc/top?stream=true", nil))
			}()
			t.Cleanup(func() { close(release); <-done })
			select {
			case <-entered:
			case <-done:
				t.Fatal("initial request did not reach the handler")
			case <-time.After(2 * time.Second):
				t.Fatal("initial request stalled")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probe", nil))
			want := http.StatusTooManyRequests
			if flavor == upstreamflavor.Podman {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("probe during top request: status=%d, want %d", rec.Code, want)
			}
		})
	}
}

// With the production classifier wired in, max_inflight still bounds the
// heavy finite operations and only real streams are exempt.
func TestConcurrencyCapExemptsStreamsButBoundsBuildAndPrune(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		wantExempt bool
	}{
		{"events", http.MethodGet, "/events", true},
		{"logs follow", http.MethodGet, "/containers/abc/logs?follow=1", true},
		{"attach", http.MethodPost, "/containers/abc/attach", true},
		{"logs without follow", http.MethodGet, "/containers/abc/logs", false},
		{"build", http.MethodPost, "/build", false},
		{"prune", http.MethodPost, "/containers/prune", false},
		{"image pull", http.MethodPost, "/images/create?fromImage=alpine", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enter := make(chan struct{})
			release := make(chan struct{})
			mw, stop := ratelimit.Middleware(newDiscardLogger(), nil, nil, ratelimit.MiddlewareOptions{
				Profiles: map[string]ratelimit.ProfileOptions{
					"ci": {Concurrency: &ratelimit.ConcurrencyOptions{MaxInflight: 1, MaxStreams: 8}},
				},
				ResolveProfile: func(*http.Request) (string, bool) { return "ci", true },
				IsStreaming:    proxy.IsStreamingRequest,
			})
			t.Cleanup(stop)
			h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/probe" {
					return
				}
				enter <- struct{}{}
				<-release
			}))

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.target, nil))
			}()
			<-enter
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probe", nil))
			close(release)
			wg.Wait()

			wantCode := http.StatusTooManyRequests
			if tc.wantExempt {
				wantCode = http.StatusOK
			}
			if rec.Code != wantCode {
				t.Fatalf("probe while %s %s is open: got %d, want %d", tc.method, tc.target, rec.Code, wantCode)
			}
		})
	}
}
