package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/upstream"
)

// The deadlines below are scaled down from the 30s response-header and 60s
// request defaults: the daemon sleeps well past both, which is the same shape
// as a 35s stop against the real defaults without the test sleeping 35s.
const (
	scaledDeadline = 100 * time.Millisecond
	scaledDaemon   = 400 * time.Millisecond
)

func slowDaemonFront(t *testing.T, headerTimeout, requestTimeout time.Duration) *httptest.Server {
	t.Helper()
	socketPath := tempSocketPath(t, "deadlines")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(scaledDaemon)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	res, err := upstream.New([]upstream.Endpoint{{Name: socketPath, Network: "unix", Address: socketPath}}, upstream.Options{
		Interval:              -1,
		ResponseHeaderTimeout: headerTimeout,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	rp := NewWithTransport(res, testLogger(), Options{})
	front := httptest.NewServer(WithUpstreamDeadlines(rp, requestTimeout, false))
	t.Cleanup(front.Close)
	return front
}

func doReq(t *testing.T, method, url string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestWithUpstreamDeadlines_SlowStopSucceedsUnderDeadlines(t *testing.T) {
	t.Parallel()
	front := slowDaemonFront(t, scaledDeadline, scaledDeadline)
	for _, target := range []string{
		"/containers/x/stop?t=60",
		"/containers/x/restart",
		"/libpod/containers/x/stop?t=60",
		"/containers/prune",
	} {
		if got := doReq(t, http.MethodPost, front.URL+target); got != http.StatusNoContent {
			t.Errorf("POST %s = %d, want 204 (long-lived)", target, got)
		}
	}
}

func TestWithUpstreamDeadlines_SlowStopSucceedsWithTimeoutsOff(t *testing.T) {
	t.Parallel()
	front := slowDaemonFront(t, -1, 0)
	if got := doReq(t, http.MethodPost, front.URL+"/containers/x/stop?t=60"); got != http.StatusNoContent {
		t.Errorf("stop with timeouts off = %d, want 204", got)
	}
	if got := doReq(t, http.MethodGet, front.URL+"/containers/json"); got != http.StatusOK {
		t.Errorf("ordinary request with timeouts off = %d, want 200", got)
	}
}

func TestWithUpstreamDeadlines_OrdinaryRequestsStillTimeOut(t *testing.T) {
	t.Parallel()
	// Request timeout off, header timeout on: the header deadline alone fires.
	headerOnly := slowDaemonFront(t, scaledDeadline, 0)
	if got := doReq(t, http.MethodGet, headerOnly.URL+"/containers/json"); got != http.StatusBadGateway && got != http.StatusGatewayTimeout {
		t.Errorf("ordinary request past header timeout = %d, want 502/504", got)
	}
	// Header timeout off, request timeout on: the total deadline alone fires.
	totalOnly := slowDaemonFront(t, -1, scaledDeadline)
	if got := doReq(t, http.MethodGet, totalOnly.URL+"/containers/json"); got != http.StatusGatewayTimeout {
		t.Errorf("ordinary request past request timeout = %d, want 504", got)
	}
}

func TestStopGraceFromQueryAndDeadline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		target   string
		grace    time.Duration
		deadline time.Duration // with configured request_timeout 60s
	}{
		{"absent t", "/containers/x/stop", 10 * time.Second, 60 * time.Second},
		{"t=0", "/containers/x/stop?t=0", 0, 60 * time.Second},
		{"t=5", "/containers/x/stop?t=5", 5 * time.Second, 60 * time.Second},
		{"t=90 beats configured", "/containers/x/restart?t=90", 90 * time.Second, 120 * time.Second},
		{"huge t clamped", "/containers/x/stop?t=2147483647", time.Hour, time.Hour + 30*time.Second},
		{"beyond int64 clamped", "/containers/x/stop?t=99999999999999999999", time.Hour, time.Hour + 30*time.Second},
		{"negative t clamped", "/containers/x/stop?t=-1", time.Hour, time.Hour + 30*time.Second},
		{"garbage t", "/containers/x/stop?t=abc", 10 * time.Second, 60 * time.Second},
		{"libpod timeout key", "/libpod/containers/x/stop?timeout=120", 120 * time.Second, 150 * time.Second},
		{"libpod pod t", "/libpod/pods/x/stop?t=200", 200 * time.Second, 230 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, tc.target, nil)
			mode, grace := upstreamExemptionForFlavor(httptest.NewRecorder(), req, false)
			if mode != exemptGraceBound {
				t.Fatalf("mode = %v, want exemptGraceBound", mode)
			}
			if grace != tc.grace {
				t.Errorf("grace = %v, want %v", grace, tc.grace)
			}
			if got := graceBoundDeadline(60*time.Second, grace); got != tc.deadline {
				t.Errorf("deadline = %v, want %v", got, tc.deadline)
			}
		})
	}
}

func TestWithRequestTimeout_StopHugeGraceGetsFiniteDeadline(t *testing.T) {
	t.Parallel()
	var deadline time.Time
	var ok bool
	h := WithRequestTimeoutForFlavor(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		deadline, ok = r.Context().Deadline()
	}), 60*time.Second, false)
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/x/stop?t=2147483647", nil))
	if !ok {
		t.Fatal("stop with huge t has no context deadline")
	}
	if d := deadline.Sub(start); d > time.Hour+31*time.Second || d < time.Hour {
		t.Errorf("deadline in %v, want about 1h30s", d)
	}
}

func TestWithRequestTimeout_StopStaysDisabledWhenTimeoutOff(t *testing.T) {
	t.Parallel()
	var ok bool
	h := WithRequestTimeoutForFlavor(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok = r.Context().Deadline()
	}), 0, false)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/containers/x/stop?t=5", nil))
	if ok {
		t.Error("deadline set although request_timeout is disabled")
	}
}

func TestWithUpstreamDeadlines_SystemDfHitsRequestTimeoutNotHeaderTimeout(t *testing.T) {
	t.Parallel()
	// Header timeout tiny, request timeout generous: df must succeed.
	headerTiny := slowDaemonFront(t, scaledDeadline, 5*time.Second)
	if got := doReq(t, http.MethodGet, headerTiny.URL+"/system/df"); got != http.StatusOK {
		t.Errorf("GET /system/df past header timeout = %d, want 200", got)
	}
	// Header timeout off, request timeout tiny: df must hit the total deadline.
	totalTiny := slowDaemonFront(t, -1, scaledDeadline)
	if got := doReq(t, http.MethodGet, totalTiny.URL+"/system/df"); got != http.StatusGatewayTimeout {
		t.Errorf("GET /system/df past request timeout = %d, want 504", got)
	}
}
