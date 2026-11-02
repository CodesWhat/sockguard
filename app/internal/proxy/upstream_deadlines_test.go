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
	if got := doReq(t, http.MethodGet, front.URL+"/system/df"); got != http.StatusOK {
		t.Errorf("GET /system/df = %d, want 200 (long-lived)", got)
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
