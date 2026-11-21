package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/metrics"
	"github.com/codeswhat/sockguard/v3/app/internal/ratelimit"
)

// Podman's collection stats route streams unless stream is explicitly false.
// It decodes the query with gorilla/schema, so keys are case-insensitive and
// an empty value leaves the default in force.
var libpodCollectionStatsCases = []struct {
	name   string
	target string
	want   bool
}{
	{"omitted stream defaults to streaming", "/libpod/containers/stats", true},
	{"versioned omitted", "/v5.8.1/libpod/containers/stats", true},
	{"containers filter only", "/libpod/containers/stats?containers=abc", true},
	{"stream true", "/libpod/containers/stats?stream=true", true},
	{"stream one", "/libpod/containers/stats?stream=1", true},
	{"stream on", "/libpod/containers/stats?stream=on", true},
	{"uppercase key", "/libpod/containers/stats?Stream=true", true},
	{"empty value keeps the default", "/libpod/containers/stats?stream=", true},
	{"repeated last true", "/libpod/containers/stats?stream=false&stream=true", true},
	{"explicit false", "/libpod/containers/stats?stream=false", false},
	{"versioned explicit false", "/v5.8.1/libpod/containers/stats?stream=false", false},
	{"explicit zero", "/libpod/containers/stats?stream=0", false},
	{"uppercase key false", "/libpod/containers/stats?STREAM=false", false},
	{"repeated last false", "/libpod/containers/stats?stream=true&stream=false", false},
	{"invalid value is finite", "/libpod/containers/stats?stream=maybe", false},
	{"docker path is not the collection route", "/containers/stats", false},
	{"docker path with an id keeps the docker rule", "/containers/abc/stats", true},
	{"docker one-shot unchanged", "/containers/abc/stats?stream=0", false},
}

func TestLibpodCollectionStatsClassification(t *testing.T) {
	t.Parallel()
	for _, tc := range libpodCollectionStatsCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, podman := range []bool{false, true} {
				req := httptest.NewRequest(http.MethodGet, tc.target, nil)
				if got := longLivedClassification(httptest.NewRecorder(), req, podman); got != tc.want {
					t.Errorf("longLivedClassification(podman=%v, %s) = %v, want %v", podman, tc.target, got, tc.want)
				}
				if got := IsStreamingRequestForFlavor(httptest.NewRecorder(), req, podman); got != tc.want {
					t.Errorf("IsStreamingRequestForFlavor(podman=%v, %s) = %v, want %v", podman, tc.target, got, tc.want)
				}
			}
		})
	}
}

func TestLibpodCollectionStatsOtherMethodsAreNotStreams(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/libpod/containers/stats", nil)
		if longLivedClassification(httptest.NewRecorder(), req, true) || IsStreamingRequestForFlavor(httptest.NewRecorder(), req, true) {
			t.Errorf("%s /libpod/containers/stats classified as a stream", method)
		}
	}
}

func TestWithRequestTimeoutLibpodCollectionStats(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		target        string
		wantUnbounded bool
	}{
		{"/libpod/containers/stats", true},
		{"/v5.8.1/libpod/containers/stats?stream=true", true},
		{"/libpod/containers/stats?stream=false", false},
	} {
		hasDeadline := false
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, hasDeadline = r.Context().Deadline()
		})
		WithRequestTimeoutForFlavor(next, 50*time.Millisecond, true).
			ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.target, nil))
		if got := !hasDeadline; got != tc.wantUnbounded {
			t.Errorf("unbounded %s = %v, want %v", tc.target, got, tc.wantUnbounded)
		}
	}
}

// An admitted collection stream counts against max_streams, not max_inflight:
// with max_inflight 1 a second finite request still gets through while a
// collection stream is held open, and the stream cap bounds the streams.
func TestLibpodCollectionStatsUsesStreamCapNotInflightCap(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libpod/containers/stats" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	})
	opts := ratelimit.MiddlewareOptions{
		Profiles: map[string]ratelimit.ProfileOptions{
			"p": {Concurrency: &ratelimit.ConcurrencyOptions{MaxInflight: 1, MaxStreams: 1}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "p", true },
		IsStreaming: func(w http.ResponseWriter, r *http.Request) bool {
			return IsStreamingRequestForFlavor(w, r, true)
		},
	}
	mw, stop := ratelimit.Middleware(nil, metrics.NewRegistry(), nil, opts)
	t.Cleanup(stop)
	h := mw(blocking)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/stats", nil))
		done <- rec.Code
	}()
	<-entered

	// A finite request still fits under max_inflight 1.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("finite request while a stats stream is open = %d, want 200", rec.Code)
	}

	// A second collection stream hits the stream cap.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/stats", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second stats stream = %d, want 429 from max_streams", rec.Code)
	}

	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first stats stream = %d, want 200", code)
	}
}
