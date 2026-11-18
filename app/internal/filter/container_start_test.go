package filter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsContainerStartPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/containers/abc/start", true},
		{"/containers/a/b/start", true},
		{"/containers/a/b/c/start", true},
		{"/containers/start", false},
		{"/containers//start", false},
		{"/containers/abc/stop", false},
		{"/containers/abc/start/extra", false},
		{"/libpod/containers/abc/start", false},
		{"/exec/abc/start", false},
		{"/containers/create", false},
	}
	for _, tt := range tests {
		if got := isContainerStartPath(tt.path); got != tt.want {
			t.Errorf("isContainerStartPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// startThroughMiddleware sends one request through the filter with an allow
// rule for every container start, and reports the status and whether the
// handler behind it was reached. The path is sent as written, so a versioned
// prefix reaches NormalizePath the way it does in production.
func startThroughMiddleware(t *testing.T, method, path string, body io.Reader, chunked bool) (int, bool) {
	t.Helper()
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/**", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{
		PolicyConfig: PolicyConfig{DenyResponseVerbosity: DenyResponseVerbosityVerbose},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(method, path, body)
	if chunked {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, reached
}

func TestContainerStartRefusesAnyBody(t *testing.T) {
	const hostConfig = `{"Privileged":true,"Binds":["/:/host"]}`
	denied := []struct {
		name    string
		path    string
		body    string
		chunked bool
	}{
		{"old API prefix", "/v1.23/containers/abc/start", hostConfig, false},
		{"modern prefix", "/v1.45/containers/abc/start", hostConfig, false},
		{"unversioned", "/containers/abc/start", hostConfig, false},
		{"chunked", "/v1.23/containers/abc/start", hostConfig, true},
		{"empty object", "/containers/abc/start", `{}`, false},
		{"whitespace", "/containers/abc/start", ` `, false},
		{"slash-bearing name", "/v1.23/containers/a/b/start", hostConfig, false},
		{"escaped slash in name", "/v1.23/containers/a%2Fb/start", hostConfig, false},
		{"over the read bound", "/containers/abc/start", strings.Repeat("x", maxContainerStartBodyBytes+10), false},
	}
	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := startThroughMiddleware(t, http.MethodPost, tt.path, strings.NewReader(tt.body), tt.chunked)
			if status != http.StatusForbidden || reached {
				t.Fatalf("status = %d, reached = %v, want 403 and not reached", status, reached)
			}
		})
	}

	allowed := []struct {
		name string
		path string
		body io.Reader
	}{
		{"no body", "/v1.23/containers/abc/start", nil},
		{"empty reader", "/containers/abc/start", strings.NewReader("")},
		{"slash-bearing name without a body", "/containers/a/b/start", nil},
		{"stop with a body is not a start", "/containers/abc/stop", strings.NewReader(`{}`)},
	}
	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := startThroughMiddleware(t, http.MethodPost, tt.path, tt.body, false)
			if status != http.StatusNoContent || !reached {
				t.Fatalf("status = %d, reached = %v, want 204 and reached", status, reached)
			}
		})
	}
}

// TestContainerStartDoesNotTouchExecStart pins that the exec start inspector
// stays routed on its own path and a body on exec start is still its own
// policy's concern.
func TestContainerStartDoesNotTouchExecStart(t *testing.T) {
	if matchesContainerStartInspection("/exec/abc/start") || matchesContainerStartInspection("/libpod/exec/abc/start") {
		t.Fatal("container start inspector matched an exec start path")
	}
	reason, err := newContainerStartPolicy().inspect(nil, httptest.NewRequest(http.MethodPost, "/exec/abc/start", strings.NewReader(`{"Detach":true}`)), "/exec/abc/start")
	if reason != "" || err != nil {
		t.Fatalf("inspect() = %q, %v, want no opinion", reason, err)
	}
}
