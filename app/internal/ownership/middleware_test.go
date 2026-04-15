package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type inspectResult struct {
	labels map[string]string
	found  bool
	err    error
}

type execResult struct {
	containerID string
	found       bool
	err         error
}

type fakeInspector struct {
	resources map[string]map[string]inspectResult
	execs     map[string]execResult
}

func (f fakeInspector) deps() ownerDeps {
	return ownerDeps{
		inspectResource: f.inspectResource,
		inspectExec:     f.inspectExec,
	}
}

func (f fakeInspector) inspectResource(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
	if f.resources == nil {
		return nil, false, nil
	}
	result, ok := f.resources[string(kind)][id]
	if !ok {
		return nil, false, nil
	}
	return result.labels, result.found, result.err
}

func (f fakeInspector) inspectExec(_ context.Context, id string) (string, bool, error) {
	if f.execs == nil {
		return "", false, nil
	}
	result, ok := f.execs[id]
	if !ok {
		return "", false, nil
	}
	return result.containerID, result.found, result.err
}

func TestMiddlewareAddsOwnerLabelToContainerCreate(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels, ok := body["Labels"].(map[string]any)
		if !ok {
			t.Fatalf("Labels = %#v, want object", body["Labels"])
		}
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("owner label = %#v, want job-123", got)
		}
		if got := labels["existing"]; got != "value" {
			t.Fatalf("existing label = %#v, want value", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37","Labels":{"existing":"value"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestMiddlewareNoOpWhenOwnerEmpty(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{}, fakeInspector{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	handler.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusNoContent {
		t.Fatalf("reached=%v status=%d, want true/204", reached, rec.Code)
	}
}

func TestMiddlewareInjectsOwnerFilterIntoContainerList(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filtersJSON := r.URL.Query().Get("filters")
		if filtersJSON == "" {
			t.Fatal("expected filters query")
		}
		var filters map[string]any
		if err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters); err != nil {
			t.Fatalf("decode filters: %v", err)
		}
		values, ok := filters["label"].([]any)
		if !ok {
			t.Fatalf("label filters = %#v, want array", filters["label"])
		}
		got := make([]string, 0, len(values))
		for _, value := range values {
			got = append(got, value.(string))
		}
		if !slices.Contains(got, "existing=1") || !slices.Contains(got, "com.sockguard.owner=job-123") {
			t.Fatalf("label filters = %#v, want existing label and owner label", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json?filters=%7B%22label%22%3A%5B%22existing%3D1%22%5D%7D", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareInjectsOwnerFilterIntoExpandedControlPlaneLists(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	tests := []struct {
		name          string
		target        string
		wantFilterKey string
	}{
		{name: "services", target: "/services", wantFilterKey: "label"},
		{name: "tasks", target: "/tasks", wantFilterKey: "label"},
		{name: "secrets", target: "/secrets", wantFilterKey: "label"},
		{name: "configs", target: "/configs", wantFilterKey: "label"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filtersJSON := r.URL.Query().Get("filters")
				if filtersJSON == "" {
					t.Fatal("expected filters query")
				}
				var filters map[string]any
				if err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters); err != nil {
					t.Fatalf("decode filters: %v", err)
				}
				values, ok := filters[tt.wantFilterKey].([]any)
				if !ok {
					t.Fatalf("%s filters = %#v, want array", tt.wantFilterKey, filters[tt.wantFilterKey])
				}
				got := make([]string, 0, len(values))
				for _, value := range values {
					got = append(got, value.(string))
				}
				if !slices.Contains(got, "com.sockguard.owner=job-123") {
					t.Fatalf("%s filters = %#v, want owner label", tt.wantFilterKey, got)
				}
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

func TestMiddlewareReturnsBadRequestForInvalidMutationInput(t *testing.T) {
	t.Run("invalid labels object", func(t *testing.T) {
		handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fakeInspector{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("expected invalid create body to be denied")
		}))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Labels":"bad"}`))
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid filters", func(t *testing.T) {
		handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fakeInspector{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("expected invalid filters to be denied")
		}))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/containers/json?filters=%7B%22label%22%3A%22bad%22%7D", nil)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}

func TestMiddlewareDeniesCrossOwnerContainerAccess(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected cross-owner container access to be denied")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/attach", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "owner policy denied access") {
		t.Fatalf("deny body = %q, want owner policy denial", rec.Body.String())
	}
}

func TestMiddlewareAllowsOwnedContainerAccess(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/start", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareDeniesCrossOwnerExpandedControlPlaneAccess(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	tests := []struct {
		name       string
		target     string
		kind       string
		identifier string
	}{
		{name: "service inspect", target: "/services/web", kind: "services", identifier: "web"},
		{name: "service logs", target: "/services/web/logs", kind: "services", identifier: "web"},
		{name: "task inspect", target: "/tasks/task-1", kind: "tasks", identifier: "task-1"},
		{name: "task logs", target: "/tasks/task-1/logs", kind: "tasks", identifier: "task-1"},
		{name: "secret inspect", target: "/secrets/secret-1", kind: "secrets", identifier: "secret-1"},
		{name: "config inspect", target: "/configs/config-1", kind: "configs", identifier: "config-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
				resources: map[string]map[string]inspectResult{
					tt.kind: {
						tt.identifier: {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner access to be denied")
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "owner policy denied access") {
				t.Fatalf("deny body = %q, want owner policy denial", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareAllowsUnownedImageAccessByDefault(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"busybox:latest": {labels: map[string]string{}, found: true},
			},
		},
	}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/images/busybox:latest/json", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareDeniesExecAccessForCrossOwnerContainer(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		execs: map[string]execResult{
			"exec-1": {containerID: "abc123", found: true},
		},
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected exec access to be denied")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/exec/exec-1/start", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestMiddlewarePassesThroughWhenResourceMissing(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"missing": {found: false},
			},
		},
	}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/containers/missing/json", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestMiddlewareReturnsBadGatewayWhenOwnerLookupFails(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {err: errors.New("dial boom"), found: true},
			},
		},
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected owner lookup failure to short-circuit request")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/json", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

func TestMiddlewareWrapperUsesUnixSocketInspector(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/abc123/json" {
			t.Errorf("path = %q, want /containers/abc123/json", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"Config":{"Labels":{"com.sockguard.owner":"job-123"}}}`))
	}))

	handler := Middleware(socketPath, testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/json", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestOptionsNormalized(t *testing.T) {
	opts := (Options{Owner: "job-123"}).normalized()
	if opts.LabelKey != DefaultLabelKey {
		t.Fatalf("LabelKey = %q, want %q", opts.LabelKey, DefaultLabelKey)
	}
}

func TestMutateOwnershipRequest(t *testing.T) {
	t.Run("build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/build?labels=%7B%22existing%22%3A%22value%22%7D", nil)
		if err := mutateOwnershipRequest(req, "/build", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(build) error = %v", err)
		}
		var labels map[string]string
		if err := json.NewDecoder(strings.NewReader(req.URL.Query().Get("labels"))).Decode(&labels); err != nil {
			t.Fatalf("decode labels: %v", err)
		}
		if labels["com.sockguard.owner"] != "job-123" || labels["existing"] != "value" {
			t.Fatalf("labels = %#v, want owner and existing labels", labels)
		}
	})

	t.Run("noop", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		if err := mutateOwnershipRequest(req, "/info", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(noop) error = %v", err)
		}
	})

	t.Run("service create", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{"Name":"web"}`))
		if err := mutateOwnershipRequest(req, "/services/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(service create) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("service Labels owner = %#v, want job-123", got)
		}
		containerLabels := nestedMapAnyForTest(t, body, "TaskTemplate", "ContainerSpec", "Labels")
		if got := containerLabels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("service TaskTemplate.ContainerSpec.Labels owner = %#v, want job-123", got)
		}
	})

	t.Run("service update preserves existing labels", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/services/web/update", strings.NewReader(`{
			"Labels":{"existing":"value"},
			"TaskTemplate":{"ContainerSpec":{"Labels":{"workload":"api"}}}
		}`))
		if err := mutateOwnershipRequest(req, "/services/web/update", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(service update) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["existing"]; got != "value" {
			t.Fatalf("service Labels existing = %#v, want value", got)
		}
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("service Labels owner = %#v, want job-123", got)
		}
		containerLabels := nestedMapAnyForTest(t, body, "TaskTemplate", "ContainerSpec", "Labels")
		if got := containerLabels["workload"]; got != "api" {
			t.Fatalf("service TaskTemplate.ContainerSpec.Labels workload = %#v, want api", got)
		}
		if got := containerLabels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("service TaskTemplate.ContainerSpec.Labels owner = %#v, want job-123", got)
		}
	})

	t.Run("secret create", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(`{"Name":"db-password"}`))
		if err := mutateOwnershipRequest(req, "/secrets/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(secret create) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("secret Labels owner = %#v, want job-123", got)
		}
	})

	t.Run("config create", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/configs/create", strings.NewReader(`{"Name":"app-config"}`))
		if err := mutateOwnershipRequest(req, "/configs/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(config create) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("config Labels owner = %#v, want job-123", got)
		}
	})
}

func TestAllowOwnershipRequest(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	deps := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"networks": {"net-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"volumes":  {"vol-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"images":   {"busybox:latest": {labels: map[string]string{}, found: true}},
			"services": {"svc-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"tasks":    {"task-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"secrets":  {"sec-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"configs":  {"cfg-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
		},
	}.deps()

	if verdict, _, err := allowOwnershipRequest(context.Background(), "/networks/net-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(network) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/volumes/vol-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(volume) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/images/busybox:latest/json", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(image) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/services/svc-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(service) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/services/svc-1/logs", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(service logs) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/tasks/task-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(task) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/tasks/task-1/logs", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(task logs) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/secrets/sec-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(secret) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/configs/cfg-1", opts, deps); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(config) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, reason, err := allowOwnershipRequest(context.Background(), "/images/busybox:latest/json", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, deps); err != nil || verdict != verdictDeny || !strings.Contains(reason, "owner policy denied access to image") {
		t.Fatalf("allowOwnershipRequest(image deny) = (%v, %q, %v), want verdictDeny/image denial/nil", verdict, reason, err)
	}
	if verdict, reason, err := allowOwnershipRequest(context.Background(), "/exec/missing/start", opts, fakeInspector{
		execs: map[string]execResult{"missing": {found: false}},
	}.deps()); err != nil || verdict != verdictPassThrough || reason != "" {
		t.Fatalf("allowOwnershipRequest(exec missing) = (%v, %q, %v), want verdictPassThrough/\"\"/nil", verdict, reason, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/info", opts, deps); err != nil || verdict != verdictPassThrough {
		t.Fatalf("allowOwnershipRequest(no match) = (%v, %v), want verdictPassThrough/nil", verdict, err)
	}
}

func TestOwnerHelpers(t *testing.T) {
	tests := []struct {
		name         string
		labels       map[string]string
		allowUnowned bool
		want         bool
	}{
		{name: "nil labels allowed", labels: nil, allowUnowned: true, want: true},
		{name: "missing label denied", labels: map[string]string{}, allowUnowned: false, want: false},
		{name: "empty label allowed as unowned", labels: map[string]string{"com.sockguard.owner": ""}, allowUnowned: true, want: true},
		{name: "matching owner", labels: map[string]string{"com.sockguard.owner": "job-123"}, allowUnowned: false, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ownerMatches(tt.labels, "com.sockguard.owner", "job-123", tt.allowUnowned); got != tt.want {
				t.Fatalf("ownerMatches() = %v, want %v", got, tt.want)
			}
		})
	}

	if got := singularResource(resourceKindContainer); got != "container" {
		t.Fatalf("singularResource(container) = %q, want container", got)
	}
	if got := singularResource(resourceKindImage); got != "image" {
		t.Fatalf("singularResource(image) = %q, want image", got)
	}
	if got := singularResource(resourceKindNetwork); got != "network" {
		t.Fatalf("singularResource(network) = %q, want network", got)
	}
	if got := singularResource(resourceKindVolume); got != "volume" {
		t.Fatalf("singularResource(volume) = %q, want volume", got)
	}
	if got := singularResource(resourceKind("services")); got != "service" {
		t.Fatalf("singularResource(services) = %q, want service", got)
	}
	if got := singularResource(resourceKind("tasks")); got != "task" {
		t.Fatalf("singularResource(tasks) = %q, want task", got)
	}
	if got := singularResource(resourceKind("secrets")); got != "secret" {
		t.Fatalf("singularResource(secrets) = %q, want secret", got)
	}
	if got := singularResource(resourceKind("configs")); got != "config" {
		t.Fatalf("singularResource(configs) = %q, want config", got)
	}
	if got := singularResource(resourceKind("other")); got != "other" {
		t.Fatalf("singularResource(other) = %q, want other", got)
	}
}

func TestOwnershipSetDenied(t *testing.T) {
	// Ownership passes nil for the normalize callback because filter has
	// already stamped meta.NormPath by the time ownership fires.
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/json", nil)
	logging.SetDenied(&metaWriter{meta: meta}, req, "nope", nil)
	if meta.Decision != "deny" || meta.Reason != "nope" {
		t.Fatalf("meta = %#v, want deny/nope", meta)
	}
	logging.SetDenied(httptest.NewRecorder(), req, "ignored", nil)
}

func TestIdentifierHelpers(t *testing.T) {
	if id, ok := networkIdentifier("/networks/net-1"); !ok || id != "net-1" {
		t.Fatalf("networkIdentifier() = (%q, %v), want (net-1, true)", id, ok)
	}
	if _, ok := networkIdentifier("/networks/create"); ok {
		t.Fatal("expected /networks/create to be excluded")
	}
	if id, ok := volumeIdentifier("/volumes/vol-1"); !ok || id != "vol-1" {
		t.Fatalf("volumeIdentifier() = (%q, %v), want (vol-1, true)", id, ok)
	}
	if _, ok := volumeIdentifier("/volumes/prune"); ok {
		t.Fatal("expected /volumes/prune to be excluded")
	}
	if id, ok := imageIdentifier("/images/busybox:latest/json"); !ok || id != "busybox:latest" {
		t.Fatalf("imageIdentifier() = (%q, %v), want (busybox:latest, true)", id, ok)
	}
	if id, ok := imageIdentifier("/images/custom/history"); !ok || id != "custom" {
		t.Fatalf("imageIdentifier(history) = (%q, %v), want (custom, true)", id, ok)
	}
	if id, ok := imageIdentifier("/images/custom"); !ok || id != "custom" {
		t.Fatalf("imageIdentifier(raw) = (%q, %v), want (custom, true)", id, ok)
	}
	if _, ok := imageIdentifier("/images/prune"); ok {
		t.Fatal("expected /images/prune to be excluded")
	}
	if id, ok := execIdentifier("/exec/exec-1/start"); !ok || id != "exec-1" {
		t.Fatalf("execIdentifier() = (%q, %v), want (exec-1, true)", id, ok)
	}
	if _, ok := execIdentifier("/exec/"); ok {
		t.Fatal("expected empty exec identifier to be excluded")
	}
	if id, ok := serviceIdentifier("/services/web"); !ok || id != "web" {
		t.Fatalf("serviceIdentifier() = (%q, %v), want (web, true)", id, ok)
	}
	if id, ok := serviceIdentifier("/services/web/logs"); !ok || id != "web" {
		t.Fatalf("serviceIdentifier(logs) = (%q, %v), want (web, true)", id, ok)
	}
	if _, ok := serviceIdentifier("/services/create"); ok {
		t.Fatal("expected /services/create to be excluded")
	}
	if id, ok := taskIdentifier("/tasks/task-1"); !ok || id != "task-1" {
		t.Fatalf("taskIdentifier() = (%q, %v), want (task-1, true)", id, ok)
	}
	if id, ok := taskIdentifier("/tasks/task-1/logs"); !ok || id != "task-1" {
		t.Fatalf("taskIdentifier(logs) = (%q, %v), want (task-1, true)", id, ok)
	}
	if id, ok := secretIdentifier("/secrets/sec-1"); !ok || id != "sec-1" {
		t.Fatalf("secretIdentifier() = (%q, %v), want (sec-1, true)", id, ok)
	}
	if _, ok := secretIdentifier("/secrets/create"); ok {
		t.Fatal("expected /secrets/create to be excluded")
	}
	if id, ok := configIdentifier("/configs/cfg-1"); !ok || id != "cfg-1" {
		t.Fatalf("configIdentifier() = (%q, %v), want (cfg-1, true)", id, ok)
	}
	if _, ok := configIdentifier("/configs/create"); ok {
		t.Fatal("expected /configs/create to be excluded")
	}
}

func TestAddOwnerLabelToBuildQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/build", nil)
	if err := addOwnerLabelToBuildQuery(req, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelToBuildQuery() error = %v", err)
	}
	var labels map[string]string
	if err := json.NewDecoder(strings.NewReader(req.URL.Query().Get("labels"))).Decode(&labels); err != nil {
		t.Fatalf("decode labels: %v", err)
	}
	if labels["com.sockguard.owner"] != "job-123" {
		t.Fatalf("labels = %#v, want owner label", labels)
	}

	req = httptest.NewRequest(http.MethodPost, "/build?labels=not-json", nil)
	if err := addOwnerLabelToBuildQuery(req, "com.sockguard.owner", "job-123"); err == nil {
		t.Fatal("expected invalid build labels error")
	}
}

func TestAddOwnerLabelToBodyAndFilterHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox"}`))
	if err := addOwnerLabelToBody(req, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelToBody() error = %v", err)
	}
	var body map[string]any
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		t.Fatalf("decode mutated body: %v", err)
	}
	if body["Labels"].(map[string]any)["com.sockguard.owner"] != "job-123" {
		t.Fatalf("body labels = %#v, want owner label", body["Labels"])
	}

	if err := addOwnerLabelToBody(httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Labels":"bad"}`)), "com.sockguard.owner", "job-123"); err == nil {
		t.Fatal("expected invalid labels object error")
	}

	serviceReq := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{"Name":"web"}`))
	if err := addOwnerLabelToServiceBody(serviceReq, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelToServiceBody() error = %v", err)
	}
	var serviceBody map[string]any
	if err := json.NewDecoder(serviceReq.Body).Decode(&serviceBody); err != nil {
		t.Fatalf("decode mutated service body: %v", err)
	}
	if nestedMapAnyForTest(t, serviceBody, "Labels")["com.sockguard.owner"] != "job-123" {
		t.Fatalf("service Labels = %#v, want owner label", serviceBody["Labels"])
	}
	if nestedMapAnyForTest(t, serviceBody, "TaskTemplate", "ContainerSpec", "Labels")["com.sockguard.owner"] != "job-123" {
		t.Fatalf("service TaskTemplate.ContainerSpec.Labels = %#v, want owner label", nestedMapAnyForTest(t, serviceBody, "TaskTemplate", "ContainerSpec", "Labels"))
	}

	filterReq := httptest.NewRequest(http.MethodGet, "/containers/json?filters=%7B%22label%22%3A%5B%22com.sockguard.owner%3Djob-123%22%5D%7D", nil)
	if err := addOwnerLabelFilter(filterReq, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelFilter() error = %v", err)
	}
	var filters map[string][]string
	if err := json.NewDecoder(strings.NewReader(filterReq.URL.Query().Get("filters"))).Decode(&filters); err != nil {
		t.Fatalf("decode filters: %v", err)
	}
	if len(filters["label"]) != 1 {
		t.Fatalf("label filters = %#v, want one owner label without duplication", filters["label"])
	}

	badFilterReq := httptest.NewRequest(http.MethodGet, "/containers/json?filters=%7B%22label%22%3A%22bad%22%7D", nil)
	if err := addOwnerLabelFilter(badFilterReq, "com.sockguard.owner", "job-123"); err == nil {
		t.Fatal("expected invalid filters error")
	}

	taskFilterReq := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	if err := addOwnerLabelFilter(taskFilterReq, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelFilter(task) error = %v", err)
	}
	var taskFilters map[string][]string
	if err := json.NewDecoder(strings.NewReader(taskFilterReq.URL.Query().Get("filters"))).Decode(&taskFilters); err != nil {
		t.Fatalf("decode task filters: %v", err)
	}
	if len(taskFilters["label"]) != 1 || taskFilters["label"][0] != "com.sockguard.owner=job-123" {
		t.Fatalf("task label filters = %#v, want owner label", taskFilters["label"])
	}
}

func TestDecodeDockerFilters(t *testing.T) {
	if filters, err := decodeDockerFilters(""); err != nil || len(filters) != 0 {
		t.Fatalf("decodeDockerFilters(empty) = (%#v, %v), want empty nil", filters, err)
	}

	filters, err := decodeDockerFilters(`{"label":["a=1"],"dangling":{"b=2":true}}`)
	if err != nil {
		t.Fatalf("decodeDockerFilters() error = %v", err)
	}
	if len(filters["label"]) != 1 || filters["label"][0] != "a=1" {
		t.Fatalf("label filters = %#v, want [a=1]", filters["label"])
	}
	if len(filters["dangling"]) != 1 || filters["dangling"][0] != "b=2" {
		t.Fatalf("dangling filters = %#v, want [b=2]", filters["dangling"])
	}

	if _, err := decodeDockerFilters(`{"label":[1]}`); err == nil {
		t.Fatal("expected invalid filter element error")
	}
	if _, err := decodeDockerFilters(`{"label":"bad"}`); err == nil {
		t.Fatal("expected invalid filter type error")
	}
	if _, err := decodeDockerFilters(`{`); err == nil {
		t.Fatal("expected invalid JSON error")
	}

	// Negation (key!=value) must pass through verbatim. Docker treats `!=`
	// as an in-string sentinel; ownership doesn't parse it, so round-
	// tripping the literal string keeps the original semantics.
	negated, err := decodeDockerFilters(`{"label":["com.example.role!=worker"]}`)
	if err != nil {
		t.Fatalf("decodeDockerFilters(negated) error = %v", err)
	}
	if len(negated["label"]) != 1 || negated["label"][0] != "com.example.role!=worker" {
		t.Fatalf("negated label filters = %#v, want [com.example.role!=worker]", negated["label"])
	}

	// Unknown future shapes (numbers, booleans) must be rejected so the
	// decoder never silently drops a filter and weakens ownership checks.
	if _, err := decodeDockerFilters(`{"label":42}`); err == nil {
		t.Fatal("expected number filter value to be rejected")
	}
	if _, err := decodeDockerFilters(`{"label":true}`); err == nil {
		t.Fatal("expected bool filter value to be rejected")
	}
}

func TestMutateJSONBody(t *testing.T) {
	t.Run("nil body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
		req.Body = nil
		if err := mutateJSONBody(req, func(map[string]any) error { return nil }); err == nil {
			t.Fatal("expected nil body error")
		}
	})

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(""))
		if err := mutateJSONBody(req, func(map[string]any) error { return nil }); err == nil {
			t.Fatal("expected empty body error")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader("{"))
		if err := mutateJSONBody(req, func(map[string]any) error { return nil }); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("mutate error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox"}`))
		if err := mutateJSONBody(req, func(map[string]any) error { return errors.New("boom") }); err == nil {
			t.Fatal("expected mutate error")
		}
	})

	t.Run("encode error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox"}`))
		err := mutateJSONBody(req, func(decoded map[string]any) error {
			decoded["bad"] = make(chan int)
			return nil
		})
		if err == nil {
			t.Fatal("expected encode error")
		}
	})

	t.Run("close error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
		req.Body = closeErrorReadCloser{Reader: strings.NewReader(`{"Image":"busybox"}`), closeErr: errors.New("close boom")}
		if err := mutateJSONBody(req, func(map[string]any) error { return nil }); err == nil {
			t.Fatal("expected close error")
		}
	})
}

func TestMutateJSONBodyPreservesLargeIntegers(t *testing.T) {
	// Docker container create payloads routinely carry 53-bit+ integers —
	// MemorySwap, Memory, PidsLimit, NanoCpus — that float64 silently
	// truncates. UseNumber must round-trip these exactly through the
	// mutate-and-re-encode pass, even though ownership itself only writes
	// the Labels object.
	const (
		bigMemory = 9007199254740993 // 2^53 + 1, smallest integer float64 loses
		bigSwap   = 9223372036854775800
	)
	bodyIn := fmt.Sprintf(
		`{"Image":"busybox","HostConfig":{"Memory":%d,"MemorySwap":%d}}`,
		bigMemory, bigSwap,
	)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(bodyIn))

	if err := mutateJSONBody(req, func(decoded map[string]any) error {
		labels, err := nestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		labels["x"] = "y"
		return nil
	}); err != nil {
		t.Fatalf("mutateJSONBody: %v", err)
	}

	rewritten, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	got := string(rewritten)

	wantMemory := fmt.Sprintf(`"Memory":%d`, bigMemory)
	if !strings.Contains(got, wantMemory) {
		t.Fatalf("rewritten body missing exact Memory integer %d; got: %s", bigMemory, got)
	}
	wantSwap := fmt.Sprintf(`"MemorySwap":%d`, bigSwap)
	if !strings.Contains(got, wantSwap) {
		t.Fatalf("rewritten body missing exact MemorySwap integer %d; got: %s", bigSwap, got)
	}
	if !strings.Contains(got, `"x":"y"`) {
		t.Fatalf("rewritten body missing injected label: %s", got)
	}
}

func TestNestedObject(t *testing.T) {
	decoded := map[string]any{}
	obj, err := nestedObject(decoded, "Labels")
	if err != nil {
		t.Fatalf("nestedObject() error = %v", err)
	}
	obj["k"] = "v"
	if got := decoded["Labels"].(map[string]any)["k"]; got != "v" {
		t.Fatalf("nested object = %#v, want value", decoded["Labels"])
	}

	if _, err := nestedObject(map[string]any{"Labels": "bad"}, "Labels"); err == nil {
		t.Fatal("expected nested object type error")
	}
	obj, err = nestedObject(map[string]any{"Labels": nil}, "Labels")
	if err != nil || obj == nil {
		t.Fatalf("nestedObject(nil) = (%#v, %v), want object nil", obj, err)
	}
}

func TestUpstreamInspectorInspectResource(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/abc/json", "/images/busybox:latest/json":
			_, _ = w.Write([]byte(`{"Config":{"Labels":{"com.sockguard.owner":"job-123"}}}`))
		case "/networks/net-1", "/volumes/vol-1":
			_, _ = w.Write([]byte(`{"Labels":{"com.sockguard.owner":"job-123"}}`))
		case "/services/svc-1", "/secrets/secret-1", "/configs/config-1":
			_, _ = w.Write([]byte(`{"Spec":{"Labels":{"com.sockguard.owner":"job-123"}}}`))
		case "/tasks/task-1":
			_, _ = w.Write([]byte(`{"Labels":{"com.sockguard.owner":"job-123"}}`))
		case "/containers/missing/json":
			http.NotFound(w, r)
		case "/containers/bad-status/json":
			http.Error(w, "boom", http.StatusBadGateway)
		case "/containers/bad-json/json":
			_, _ = w.Write([]byte(`{`))
		case "/networks/missing":
			http.NotFound(w, r)
		case "/volumes/bad-status":
			http.Error(w, "boom", http.StatusBadGateway)
		case "/networks/bad-json":
			_, _ = w.Write([]byte(`{`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	inspector := upstreamInspector{client: newUnixHTTPClient(socketPath)}

	for _, kind := range []resourceKind{resourceKindContainer, resourceKindImage, resourceKindNetwork, resourceKindVolume} {
		identifier := map[resourceKind]string{
			resourceKindContainer: "abc",
			resourceKindImage:     "busybox:latest",
			resourceKindNetwork:   "net-1",
			resourceKindVolume:    "vol-1",
		}[kind]
		labels, found, err := inspector.inspectResource(context.Background(), kind, identifier)
		if err != nil || !found || labels["com.sockguard.owner"] != "job-123" {
			t.Fatalf("inspectResource(%s) = (%#v, %v, %v), want owner labels", kind, labels, found, err)
		}
	}

	for _, kind := range []resourceKind{resourceKind("services"), resourceKind("tasks"), resourceKind("secrets"), resourceKind("configs")} {
		identifier := map[resourceKind]string{
			resourceKind("services"): "svc-1",
			resourceKind("tasks"):    "task-1",
			resourceKind("secrets"):  "secret-1",
			resourceKind("configs"):  "config-1",
		}[kind]
		labels, found, err := inspector.inspectResource(context.Background(), kind, identifier)
		if err != nil || !found || labels["com.sockguard.owner"] != "job-123" {
			t.Fatalf("inspectResource(%s) = (%#v, %v, %v), want owner labels", kind, labels, found, err)
		}
	}

	if _, found, err := inspector.inspectResource(context.Background(), resourceKindContainer, "missing"); err != nil || found {
		t.Fatalf("inspectResource(missing) = found %v err %v, want false nil", found, err)
	}
	if _, _, err := inspector.inspectResource(context.Background(), resourceKindContainer, "bad-status"); err == nil {
		t.Fatal("expected upstream status error")
	}
	if _, _, err := inspector.inspectResource(context.Background(), resourceKindContainer, "bad-json"); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if _, found, err := inspector.inspectResource(context.Background(), resourceKindNetwork, "missing"); err != nil || found {
		t.Fatalf("inspectResource(network missing) = found %v err %v, want false nil", found, err)
	}
	if _, _, err := inspector.inspectResource(context.Background(), resourceKindVolume, "bad-status"); err == nil {
		t.Fatal("expected upstream status error for volume")
	}
	if _, _, err := inspector.inspectResource(context.Background(), resourceKindNetwork, "bad-json"); err == nil {
		t.Fatal("expected network JSON decode error")
	}
	transportErrorInspector := upstreamInspector{client: newUnixHTTPClient(filepath.Join("/tmp", "sockguard-ownership-missing-"+time.Now().Format("150405000000000")+".sock"))}
	if _, _, err := transportErrorInspector.inspectResource(context.Background(), resourceKindContainer, "abc"); err == nil {
		t.Fatal("expected transport error")
	}
	if _, _, err := inspector.inspectResource(context.Background(), resourceKind("other"), "id"); err == nil {
		t.Fatal("expected unsupported kind error")
	}
}

func nestedMapAnyForTest(t *testing.T, payload map[string]any, keys ...string) map[string]any {
	t.Helper()
	current := payload
	for _, key := range keys {
		value, ok := current[key]
		if !ok {
			t.Fatalf("missing key %q in %#v", key, current)
		}
		next, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%q = %#v, want object", key, value)
		}
		current = next
	}
	return current
}

func TestUpstreamInspectorInspectExec(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exec/exec-1/json":
			_, _ = w.Write([]byte(`{"ContainerID":"abc123"}`))
		case "/exec/missing/json":
			http.NotFound(w, r)
		case "/exec/bad-status/json":
			http.Error(w, "boom", http.StatusBadGateway)
		case "/exec/bad-json/json":
			_, _ = w.Write([]byte(`{`))
		case "/exec/empty/json":
			_, _ = w.Write([]byte(`{"ContainerID":""}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	inspector := upstreamInspector{client: newUnixHTTPClient(socketPath)}

	containerID, found, err := inspector.inspectExec(context.Background(), "exec-1")
	if err != nil || !found || containerID != "abc123" {
		t.Fatalf("inspectExec() = (%q, %v, %v), want abc123/true/nil", containerID, found, err)
	}
	if _, found, err := inspector.inspectExec(context.Background(), "missing"); err != nil || found {
		t.Fatalf("inspectExec(missing) = found %v err %v, want false nil", found, err)
	}
	if _, _, err := inspector.inspectExec(context.Background(), "bad-status"); err == nil {
		t.Fatal("expected upstream status error")
	}
	if _, _, err := inspector.inspectExec(context.Background(), "bad-json"); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if _, _, err := inspector.inspectExec(context.Background(), "empty"); err == nil {
		t.Fatal("expected empty container ID error")
	}

	transportErrorInspector := upstreamInspector{client: newUnixHTTPClient(filepath.Join("/tmp", "sockguard-ownership-missing-"+time.Now().Format("150405000000000")+".sock"))}
	if _, _, err := transportErrorInspector.inspectExec(context.Background(), "exec-1"); err == nil {
		t.Fatal("expected transport error")
	}
}

type closeErrorReadCloser struct {
	io.Reader
	closeErr error
}

func (r closeErrorReadCloser) Close() error { return r.closeErr }

type metaWriter struct {
	http.ResponseWriter
	meta *logging.RequestMeta
}

func (w *metaWriter) Header() http.Header               { return make(http.Header) }
func (w *metaWriter) Write([]byte) (int, error)         { return 0, nil }
func (w *metaWriter) WriteHeader(int)                   {}
func (w *metaWriter) RequestMeta() *logging.RequestMeta { return w.meta }

func startUnixHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	socketPath := filepath.Join("/tmp", "sockguard-ownership-"+strings.ReplaceAll(strings.ToLower(t.Name()), "/", "-")+"-"+time.Now().Format("150405000000000")+".sock")
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	return socketPath
}

func newUnixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// TestMutateJSONBodyRejectsOversizedBody locks in the OOM guard on the
// ownership mutation path. A client posting a body larger than
// maxOwnershipBodyBytes to /containers/create /networks/create /volumes/create
// must short-circuit with an error and never invoke the mutate callback, so
// we don't hand a multi-GB byte slice to json.Unmarshal.
func TestMutateJSONBodyRejectsOversizedBody(t *testing.T) {
	oversized := strings.Repeat("x", maxOwnershipBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(oversized))

	err := mutateJSONBody(req, func(map[string]any) error {
		t.Fatal("mutate callback invoked despite oversized body")
		return nil
	})
	if err == nil {
		t.Fatal("mutateJSONBody() err = nil, want 'exceeds ... byte limit'")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("mutateJSONBody() err = %v, want contains 'exceeds'", err)
	}
}
