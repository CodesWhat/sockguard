package ownership

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
)

func TestMiddlewareChecksExistingNetworkOnLibpodCreate(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	network := func(r inspectResult) map[string]map[string]inspectResult {
		return map[string]map[string]inspectResult{string(dockerresource.KindNetwork): {"net": r}}
	}
	const path = "/libpod/networks/create?ignoreIfExists=true"
	tests := []struct {
		name      string
		path      string
		body      string
		resources map[string]map[string]inspectResult
		wantCode  int
	}{
		{name: "foreign network", path: path, body: `{"name":"net"}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign network, versioned", path: "/v5.0.0" + path, body: `{"name":"net"}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign network, capitalized key", path: path, body: `{"Name":"net"}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign network, upper key", path: path, body: `{"NAME":"net"}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "foreign network without ignoreIfExists", path: "/libpod/networks/create", body: `{"name":"net"}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusForbidden},
		{name: "unlabeled network", path: path, body: `{"name":"net"}`, resources: network(inspectResult{labels: map[string]string{}, found: true}), wantCode: http.StatusForbidden},
		{name: "lookup failure", path: path, body: `{"name":"net"}`, resources: network(inspectResult{err: errors.New("boom")}), wantCode: http.StatusBadGateway},
		{name: "same owner reuse", path: path, body: `{"name":"net"}`, resources: network(ownerLabel("job-123")), wantCode: http.StatusOK},
		{name: "missing name creates", path: path, body: `{"name":"net"}`, resources: map[string]map[string]inspectResult{}, wantCode: http.StatusOK},
		{name: "generated name", path: path, body: `{}`, resources: network(ownerLabel("job-999")), wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := &recordingInspector{resources: tt.resources}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"name":"net","labels":{"com.sockguard.owner":"job-123"}}`)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body)))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestLibpodNetworkCreateResponseMustCarryTheOwnerLabel(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	tests := []struct {
		name     string
		status   int
		body     string
		wantCode int
		wantLeak string
	}{
		{name: "foreign network appears after preflight", status: 200, body: `{"name":"net","labels":{"com.sockguard.owner":"job-999"},"subnets":[{"subnet":"10.9.0.0/24","gateway":"10.9.0.1"}]}`, wantCode: http.StatusForbidden, wantLeak: "10.9.0.1"},
		{name: "no labels", status: 200, body: `{"name":"net","labels":null}`, wantCode: http.StatusForbidden},
		{name: "undecodable", status: 200, body: `not json`, wantCode: http.StatusBadGateway},
		{name: "own network", status: 200, body: `{"name":"net","labels":{"com.sockguard.owner":"job-123"}}`, wantCode: http.StatusOK},
		{name: "daemon error passes through", status: 500, body: `{"message":"boom"}`, wantCode: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi := &recordingInspector{}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/networks/create?ignoreIfExists=true", strings.NewReader(`{"name":"net"}`)))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantLeak != "" && strings.Contains(rec.Body.String(), tt.wantLeak) {
				t.Fatalf("foreign network data reached the client: %s", rec.Body.String())
			}
		})
	}
}
