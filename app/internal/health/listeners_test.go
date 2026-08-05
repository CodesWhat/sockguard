package health

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func listenerHealthMonitor(state WatchdogState, listeners []ListenerStatus) *Monitor {
	m := newMonitorWithChecker("docker", time.Now(), slog.New(slog.NewTextHandler(io.Discard, nil)), newUpstreamHealthChecker(0, time.Second, time.Now, nil))
	m.mu.Lock()
	m.last = state
	m.hasState = true
	m.mu.Unlock()
	m.ListenersFunc = func() []ListenerStatus { return append([]ListenerStatus(nil), listeners...) }
	return m
}

func TestHealthAlwaysIncludesListenersArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		state     WatchdogState
		listeners []ListenerStatus
		wantCode  int
		wantError string
	}{
		{
			name:      "healthy",
			state:     WatchdogState{Status: "connected", Up: true},
			listeners: []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateServing}},
			wantCode:  http.StatusOK,
		},
		{
			name:      "upstream unhealthy",
			state:     WatchdogState{Status: "unreachable", Err: errors.New("dial failed")},
			listeners: []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateServing}},
			wantCode:  http.StatusServiceUnavailable,
			wantError: "upstream unreachable",
		},
		{
			name:      "listener not serving",
			state:     WatchdogState{Status: "connected", Up: true},
			listeners: []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateFailed}},
			wantCode:  http.StatusServiceUnavailable,
			wantError: "listener not serving",
		},
		{
			name:      "empty snapshot still encoded",
			state:     WatchdogState{Status: "connected", Up: true},
			listeners: []ListenerStatus{},
			wantCode:  http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			listenerHealthMonitor(tc.state, tc.listeners).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"listeners":[`) {
				t.Fatalf("response omitted listeners array: %s", rec.Body.String())
			}
			var body HealthResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Error != tc.wantError {
				t.Fatalf("error = %q, want %q", body.Error, tc.wantError)
			}
		})
	}
}

func TestHealthListenerFailureBranchIsDistinctFromUpstreamFailure(t *testing.T) {
	t.Parallel()

	listeners := []ListenerStatus{{Name: "ci", Role: "main", Network: "unix", State: ListenerStateFailed}}
	listenerRec := httptest.NewRecorder()
	listenerHealthMonitor(WatchdogState{Status: "connected", Up: true}, listeners).Handler().ServeHTTP(listenerRec, httptest.NewRequest(http.MethodGet, "/health", nil))

	upstreamRec := httptest.NewRecorder()
	listenerHealthMonitor(WatchdogState{Status: "unreachable", Err: errors.New("down")}, listeners).Handler().ServeHTTP(upstreamRec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if !strings.Contains(listenerRec.Body.String(), `"error":"listener not serving"`) {
		t.Fatalf("listener failure body = %s", listenerRec.Body.String())
	}
	if !strings.Contains(upstreamRec.Body.String(), `"error":"upstream unreachable"`) {
		t.Fatalf("upstream failure body = %s", upstreamRec.Body.String())
	}
}
