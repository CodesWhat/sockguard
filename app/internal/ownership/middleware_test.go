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

	"github.com/codeswhat/sockguard/internal/dockerresource"
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

func (f fakeInspector) inspectResource(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
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

type resourceInspectCall struct {
	kind dockerresource.Kind
	id   string
}

type recordingInspector struct {
	resources map[string]map[string]inspectResult
	calls     []resourceInspectCall
}

func (f *recordingInspector) inspectResource(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
	f.calls = append(f.calls, resourceInspectCall{kind: kind, id: id})
	if f.resources == nil {
		return nil, false, nil
	}
	result, ok := f.resources[string(kind)][id]
	if !ok {
		return nil, false, nil
	}
	return result.labels, result.found, result.err
}

func (f *recordingInspector) inspectExec(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

func TestMiddlewareAddsOwnerLabelToContainerCreate(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestMiddlewareRejectsDuplicateCaseVariantContainerCreateKeys(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		forwarded = true
		t.Fatal("duplicate case-variant container create body was forwarded")
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox:1.37","Labels":{"existing":"value"},"labels":{"com.sockguard.owner":"attacker"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if forwarded {
		t.Fatal("duplicate case-variant body was forwarded")
	}
}

func TestMiddlewareNormalizesSingleVariantContainerCreateLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		wantLabels map[string]string
	}{
		{
			name: "lowercase labels only canonicalized",
			body: `{"Image":"busybox:1.37","labels":{"existing":"value"}}`,
			wantLabels: map[string]string{
				"com.sockguard.owner": "job-123",
				"existing":            "value",
			},
		},
		{
			name: "label keys remain case sensitive",
			body: `{"Image":"busybox:1.37","Labels":{"MyApp":"1","myapp":"2"}}`,
			wantLabels: map[string]string{
				"com.sockguard.owner": "job-123",
				"MyApp":               "1",
				"myapp":               "2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if strings.Contains(string(raw), `"labels":`) {
					t.Fatalf("rewritten body retained lowercase labels key: %s", raw)
				}

				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				var foldedLabelKeys []string
				for key := range body {
					if strings.EqualFold(key, "Labels") {
						foldedLabelKeys = append(foldedLabelKeys, key)
					}
				}
				if len(foldedLabelKeys) != 1 || foldedLabelKeys[0] != "Labels" {
					t.Fatalf("case-folded label keys = %#v, want exactly [Labels]", foldedLabelKeys)
				}

				labels := nestedMapAnyForTest(t, body, "Labels")
				for key, want := range tt.wantLabels {
					if got := labels[key]; got != want {
						t.Fatalf("%s label = %#v, want %s", key, got, want)
					}
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
			}
		})
	}
}

func TestMiddlewareRejectsDuplicateCaseVariantContainerCreateHostConfigKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{
			name: "top-level HostConfig shadow",
			body: `{"Image":"x","HostConfig":{"Privileged":false},"hostconfig":{"Privileged":true}}`,
		},
		{
			name: "nested Privileged shadow",
			body: `{"Image":"x","HostConfig":{"Privileged":false,"privileged":true}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			forwarded := false
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				forwarded = true
				t.Fatal("duplicate case-variant container create body was forwarded")
			}))

			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if forwarded {
				t.Fatal("duplicate case-variant body was forwarded")
			}
		})
	}
}

func TestMiddlewareDeniesCrossOwnerContainerCreateNamespaceSharing(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fields := []string{"NetworkMode", "PidMode", "IpcMode", "UsernsMode"}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					"containers": {
						"target": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner namespace-sharing create to be denied")
			}))

			body := fmt.Sprintf(`{"Image":"busybox","HostConfig":{%q:"container:target"}}`, field)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "namespace-sharing target container") || !strings.Contains(rec.Body.String(), "target") {
				t.Fatalf("deny body = %q, want namespace-sharing target denial", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareDeniesCrossOwnerContainerCreateNamespaceSharingCaseInsensitiveKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{
			name: "exact-case HostConfig NetworkMode",
			body: `{"Image":"busybox","HostConfig":{"NetworkMode":"container:target"}}`,
		},
		{
			name: "lowercase hostconfig networkmode",
			body: `{"Image":"busybox","hostconfig":{"networkmode":"container:target"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					"containers": {
						"target": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner namespace-sharing create to be denied")
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "namespace-sharing target container") || !strings.Contains(rec.Body.String(), "target") {
				t.Fatalf("deny body = %q, want namespace-sharing target denial", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareAllowsSameOwnerContainerCreateNamespaceSharingAndInjectsLabel(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"sidecar": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["existing"]; got != "value" {
			t.Fatalf("existing label = %#v, want value", got)
		}
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("owner label = %#v, want job-123", got)
		}
		hostConfig := nestedMapAnyForTest(t, body, "HostConfig")
		if got := hostConfig["NetworkMode"]; got != "container:sidecar" {
			t.Fatalf("NetworkMode = %#v, want container:sidecar", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"busybox","Labels":{"existing":"value"},"HostConfig":{"NetworkMode":"container:sidecar"}}`))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestMiddlewareContainerCreateNamespaceSharingLookupMisses(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	tests := []struct {
		name    string
		result  inspectResult
		reached bool
		code    int
	}{
		// A target that resolves to nothing sockguard can inspect passes
		// through — the daemon rejects a create that joins a nonexistent
		// container anyway.
		{name: "not found passes through", result: inspectResult{found: false}, reached: true, code: http.StatusNoContent},
		// An inspect *error* fails closed with 502, matching every other
		// ownership check: allowOwnershipRequest propagates the error and the
		// middleware maps it to reasonCodeOwnerPolicyLookupFailed. A lookup
		// failure must never silently bypass the cross-owner gate.
		{name: "inspect error fails closed", result: inspectResult{err: errors.New("inspect failed")}, reached: false, code: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					"containers": {
						"target": tt.result,
					},
				},
			}
			reached := false
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":{"NetworkMode":"container:target"}}`))
			handler.ServeHTTP(rec, req)

			if reached != tt.reached {
				t.Fatalf("handler reached = %v, want %v", reached, tt.reached)
			}
			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.code, rec.Body.String())
			}
		})
	}
}

func TestMiddlewareDeniesUnlabeledContainerCreateNamespaceSharingTarget(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"target": {labels: map[string]string{}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected unlabeled namespace-sharing target to be denied")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":{"NetworkMode":"container:target"}}`))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestMiddlewareAllowCrossOwnerNamespaceSharingBypassesTargetLookup(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowCrossOwnerNamespaceSharing: true}
	fi := &recordingInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"target": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("owner label = %#v, want job-123", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":{"NetworkMode":"container:target"}}`))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(fi.calls) != 0 {
		t.Fatalf("namespace target lookups = %#v, want none when AllowCrossOwnerNamespaceSharing is true", fi.calls)
	}
}

func TestMiddlewareDeniesFirstCrossOwnerContainerCreateNamespaceSharingRef(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := &recordingInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"cross": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
				"same":  {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected first cross-owner namespace-sharing ref to be denied")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":{"NetworkMode":"container:cross","PidMode":"container:same"}}`))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "namespace-sharing target container") || !strings.Contains(rec.Body.String(), "cross") {
		t.Fatalf("deny body = %q, want first cross-owner ref", rec.Body.String())
	}
	if len(fi.calls) != 1 || fi.calls[0].id != "cross" {
		t.Fatalf("inspect calls = %#v, want exactly first ref cross", fi.calls)
	}
}

func TestMiddlewareDedupesContainerCreateNamespaceSharingRefs(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := &recordingInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"same": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"HostConfig":{"NetworkMode":"container:same","PidMode":" container:same ","IpcMode":"Container:same"}}`))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(fi.calls) != 1 || fi.calls[0].kind != dockerresource.KindContainer || fi.calls[0].id != "same" {
		t.Fatalf("inspect calls = %#v, want one container lookup for same", fi.calls)
	}
}

func TestMiddlewareNoOpWhenOwnerEmpty(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		// The proxy replaces the entire label filter with only the owner label;
		// any client-supplied label values are discarded to prevent OR-bypass.
		if len(got) != 1 || got[0] != "com.sockguard.owner=job-123" {
			t.Fatalf("label filters = %#v, want exactly [com.sockguard.owner=job-123]", got)
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

func TestMiddlewareOwnerLabelFilterOverwritesClientSuppliedOwnerLabel(t *testing.T) {
	t.Parallel()
	// Attack: client sends filters={"label":["com.sockguard.owner=victim"]} to
	// list another tenant's containers. The proxy must replace — not append —
	// the label filter so the upstream request contains only the proxy-enforced
	// owner label, not an OR-union of victim and attacker labels.
	opts := Options{Owner: "attacker", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filtersJSON := r.URL.Query().Get("filters")
		var filters map[string][]string
		if err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters); err != nil {
			t.Fatalf("decode filters: %v", err)
		}
		labelFilters := filters["label"]
		if len(labelFilters) != 1 {
			t.Fatalf("label filter count = %d, want exactly 1; got %v", len(labelFilters), labelFilters)
		}
		if labelFilters[0] != "com.sockguard.owner=attacker" {
			t.Fatalf("label filter = %q, want com.sockguard.owner=attacker (victim label must not appear)", labelFilters[0])
		}
		for _, lf := range labelFilters {
			if strings.Contains(lf, "victim") {
				t.Fatalf("victim label leaked into upstream filter: %q", lf)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))

	victimFilter := `{"label":["com.sockguard.owner=victim"]}`
	req := httptest.NewRequest(http.MethodGet, "/containers/json?filters="+victimFilter, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestMiddlewareInjectsOwnerFilterIntoExpandedControlPlaneLists(t *testing.T) {
	t.Parallel()
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
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestMiddlewareInjectsOwnerFilterIntoNodesListWithNodeLabel(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filtersJSON := r.URL.Query().Get("filters")
		if filtersJSON == "" {
			t.Fatal("expected filters query")
		}
		var filters map[string]any
		if err := json.NewDecoder(strings.NewReader(filtersJSON)).Decode(&filters); err != nil {
			t.Fatalf("decode filters: %v", err)
		}
		values, ok := filters["node.label"].([]any)
		if !ok {
			t.Fatalf("node.label filters = %#v, want array", filters["node.label"])
		}
		got := make([]string, 0, len(values))
		for _, value := range values {
			got = append(got, value.(string))
		}
		if !slices.Contains(got, "com.sockguard.owner=job-123") {
			t.Fatalf("node.label filters = %#v, want owner label", got)
		}
		if _, ok := filters["label"]; ok {
			t.Fatalf("unexpected generic label filter for /nodes: %#v", filters["label"])
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareReturnsBadRequestForInvalidMutationInput(t *testing.T) {
	t.Parallel()
	t.Run("invalid labels object", func(t *testing.T) {
		handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
		handler := middlewareWithDeps(testLogger(), Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

func TestMiddlewareRolloutModePassesOwnershipDenyThrough(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"warn", "audit"} {
		t.Run("mode="+mode, func(t *testing.T) {
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					"containers": {
						"abc123": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			reached := false
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))

			meta := &logging.RequestMeta{RolloutMode: mode}
			req := httptest.NewRequest(http.MethodPost, "/containers/abc123/attach", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !reached {
				t.Fatalf("expected inner handler to be reached under mode=%s", mode)
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (inner write) under mode=%s", rec.Code, mode)
			}
			if meta.Decision != logging.DecisionWouldDeny {
				t.Fatalf("meta.Decision = %q, want would_deny", meta.Decision)
			}
			if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
			}
		})
	}
}

func TestMiddlewareAllowsOwnedContainerAccess(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Parallel()
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
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					tt.kind: {
						tt.identifier: {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

func TestMiddlewareDeniesCrossOwnerNodeAndSwarmReads(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	tests := []struct {
		name       string
		target     string
		kind       string
		identifier string
	}{
		{name: "node inspect", target: "/nodes/node-1", kind: "nodes", identifier: "node-1"},
		{name: "swarm inspect", target: "/swarm", kind: "swarm", identifier: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					tt.kind: {
						tt.identifier: {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

func TestMiddlewareClaimsUnownedNodeAndSwarmUpdates(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	tests := []struct {
		name       string
		target     string
		kind       string
		identifier string
		body       string
	}{
		{name: "node update", target: "/nodes/node-1/update?version=42", kind: "nodes", identifier: "node-1", body: `{"Availability":"active"}`},
		{name: "swarm update", target: "/swarm/update?version=42", kind: "swarm", identifier: "", body: `{"Name":"cluster"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					tt.kind: {
						tt.identifier: {labels: map[string]string{}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				labels := nestedMapAnyForTest(t, body, "Labels")
				if got := labels["com.sockguard.owner"]; got != "job-123" {
					t.Fatalf("owner label = %#v, want job-123", got)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(tt.body))
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
		})
	}
}

func TestMiddlewareDeniesCrossOwnerNodeAndSwarmUpdates(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}

	tests := []struct {
		name       string
		target     string
		kind       string
		identifier string
		body       string
	}{
		{name: "node update", target: "/nodes/node-1/update?version=42", kind: "nodes", identifier: "node-1", body: `{"Labels":{"com.sockguard.owner":"job-123"}}`},
		{name: "swarm update", target: "/swarm/update?version=42", kind: "swarm", identifier: "", body: `{"Labels":{"com.sockguard.owner":"job-123"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					tt.kind: {
						tt.identifier: {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner update to be denied")
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(tt.body))
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}
}

func TestMiddlewareAllowsUnownedImageAccessByDefault(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"busybox:latest": {labels: map[string]string{}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		execs: map[string]execResult{
			"exec-1": {containerID: "abc123", found: true},
		},
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"missing": {found: false},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc123": {err: errors.New("dial boom"), found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	t.Parallel()
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
	t.Parallel()
	opts := (Options{Owner: "job-123"}).normalized()
	if opts.LabelKey != DefaultLabelKey {
		t.Fatalf("LabelKey = %q, want %q", opts.LabelKey, DefaultLabelKey)
	}
}

func TestMutateOwnershipRequest(t *testing.T) {
	t.Parallel()
	t.Run("build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/build?labels=%7B%22existing%22%3A%22value%22%7D", nil)
		if _, err := mutateOwnershipRequest(req, "/build", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
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
		if _, err := mutateOwnershipRequest(req, "/info", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(noop) error = %v", err)
		}
	})

	t.Run("service create", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{"Name":"web"}`))
		if _, err := mutateOwnershipRequest(req, "/services/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
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
		if _, err := mutateOwnershipRequest(req, "/services/web/update", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
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

	t.Run("node update", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/nodes/node-1/update?version=42", strings.NewReader(`{"Name":"node-1"}`))
		if _, err := mutateOwnershipRequest(req, "/nodes/node-1/update", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(node update) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("node Labels owner = %#v, want job-123", got)
		}
		if got := body["Name"]; got != "node-1" {
			t.Fatalf("node Name = %#v, want node-1", got)
		}
	})

	t.Run("swarm update", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/swarm/update?version=42", strings.NewReader(`{"Name":"cluster-1"}`))
		if _, err := mutateOwnershipRequest(req, "/swarm/update", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
			t.Fatalf("mutateOwnershipRequest(swarm update) error = %v", err)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("swarm Labels owner = %#v, want job-123", got)
		}
		if got := body["Name"]; got != "cluster-1" {
			t.Fatalf("swarm Name = %#v, want cluster-1", got)
		}
	})

	t.Run("secret create", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/secrets/create", strings.NewReader(`{"Name":"db-password"}`))
		if _, err := mutateOwnershipRequest(req, "/secrets/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
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
		if _, err := mutateOwnershipRequest(req, "/configs/create", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}); err != nil {
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

func TestContainerCreateNamespaceRefs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		decoded map[string]any
		want    []string
	}{
		{
			name:    "no HostConfig",
			decoded: map[string]any{"Image": "busybox"},
		},
		{
			name:    "HostConfig non object",
			decoded: map[string]any{"HostConfig": "bad"},
		},
		{
			name: "exact-case HostConfig NetworkMode",
			decoded: map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": "container:target",
				},
			},
			want: []string{"target"},
		},
		{
			name: "lowercase HostConfig NetworkMode",
			decoded: map[string]any{
				"hostconfig": map[string]any{
					"networkmode": "container:target",
				},
			},
			want: []string{"target"},
		},
		{
			name: "non string field values",
			decoded: map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": 123,
					"PidMode":     true,
					"IpcMode":     []any{"container:ipc"},
					"UsernsMode":  nil,
				},
			},
		},
		{
			name: "mixed valid and invalid",
			decoded: map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": "container:net",
					"PidMode":     "bridge",
					"IpcMode":     "container:ipc",
					"UsernsMode":  "container:   ",
				},
			},
			want: []string{"net", "ipc"},
		},
		{
			name: "dedup preserves first occurrence order",
			decoded: map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": "container:shared",
					"PidMode":     " container:shared ",
					"IpcMode":     "Container:other",
					"UsernsMode":  "CONTAINER:shared",
				},
			},
			want: []string{"shared", "other"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containerCreateNamespaceRefs(tt.decoded)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("containerCreateNamespaceRefs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestContainerCreateNamespaceRefsInspectsDuplicateCaseVariantModeKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		decoded map[string]any
		want    []string
	}{
		{
			name: "NetworkMode case variants",
			decoded: map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": "container:A",
					"networkmode": "container:B",
				},
			},
			want: []string{"A", "B"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containerCreateNamespaceRefs(tt.decoded)
			if len(got) != len(tt.want) {
				t.Fatalf("containerCreateNamespaceRefs() = %#v, want set %#v", got, tt.want)
			}
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Fatalf("containerCreateNamespaceRefs() = %#v, want ref %q", got, want)
				}
			}
		})
	}
}

func TestAddOwnerLabelToContainerCreateBodyInjectsLabelAndExtractsNamespaceRefs(t *testing.T) {
	t.Parallel()
	const bodyIn = `{"Image":"busybox","Labels":{"existing":"value"},"HostConfig":{"NetworkMode":"container:sidecar","PidMode":"host","Memory":9007199254740993},"Cmd":["echo","hi"]}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(bodyIn))

	refs, err := addOwnerLabelToContainerCreateBody(req, "com.sockguard.owner", "job-123")
	if err != nil {
		t.Fatalf("addOwnerLabelToContainerCreateBody() error = %v", err)
	}
	if want := []string{"sidecar"}; !slices.Equal(refs, want) {
		t.Fatalf("refs = %#v, want %#v", refs, want)
	}

	var body map[string]any
	dec := json.NewDecoder(req.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("decode mutated body: %v", err)
	}
	if got := body["Image"]; got != "busybox" {
		t.Fatalf("Image = %#v, want busybox", got)
	}
	labels := nestedMapAnyForTest(t, body, "Labels")
	if got := labels["existing"]; got != "value" {
		t.Fatalf("existing label = %#v, want value", got)
	}
	if got := labels["com.sockguard.owner"]; got != "job-123" {
		t.Fatalf("owner label = %#v, want job-123", got)
	}
	hostConfig := nestedMapAnyForTest(t, body, "HostConfig")
	if got := hostConfig["NetworkMode"]; got != "container:sidecar" {
		t.Fatalf("NetworkMode = %#v, want container:sidecar", got)
	}
	if got := hostConfig["PidMode"]; got != "host" {
		t.Fatalf("PidMode = %#v, want host", got)
	}
	memory, ok := hostConfig["Memory"].(json.Number)
	if !ok || memory.String() != "9007199254740993" {
		t.Fatalf("Memory = %#v, want exact json number 9007199254740993", hostConfig["Memory"])
	}
	cmd, ok := body["Cmd"].([]any)
	if !ok || len(cmd) != 2 || cmd[0] != "echo" || cmd[1] != "hi" {
		t.Fatalf("Cmd = %#v, want [echo hi]", body["Cmd"])
	}
}

func TestAllowOwnershipRequest(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"networks": {"net-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"volumes":  {"vol-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"images":   {"busybox:latest": {labels: map[string]string{}, found: true}},
			"services": {"svc-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"tasks":    {"task-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"secrets":  {"sec-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
			"configs":  {"cfg-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
		},
	}

	if verdict, _, err := allowOwnershipRequest(context.Background(), "/networks/net-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(network) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/volumes/vol-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(volume) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/images/busybox:latest/json", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(image) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/services/svc-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(service) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/services/svc-1/logs", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(service logs) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/tasks/task-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(task) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/tasks/task-1/logs", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(task logs) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/secrets/sec-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(secret) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/configs/cfg-1", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(config) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	nodefi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"nodes": {"node-1": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
		},
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/nodes/node-1", opts, nodefi.inspectResource, nodefi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(node) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	swarmfi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"swarm": {"": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true}},
		},
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/swarm", opts, swarmfi.inspectResource, swarmfi.inspectExec, nil); err != nil || verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequest(swarm) = (%v, %v), want verdictAllow/nil", verdict, err)
	}
	if verdict, reason, err := allowOwnershipRequest(context.Background(), "/images/busybox:latest/json", Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictDeny || !strings.Contains(reason, "owner policy denied access to image") {
		t.Fatalf("allowOwnershipRequest(image deny) = (%v, %q, %v), want verdictDeny/image denial/nil", verdict, reason, err)
	}
	execfi := fakeInspector{
		execs: map[string]execResult{"missing": {found: false}},
	}
	if verdict, reason, err := allowOwnershipRequest(context.Background(), "/exec/missing/start", opts, execfi.inspectResource, execfi.inspectExec, nil); err != nil || verdict != verdictPassThrough || reason != "" {
		t.Fatalf("allowOwnershipRequest(exec missing) = (%v, %q, %v), want verdictPassThrough/\"\"/nil", verdict, reason, err)
	}
	if verdict, _, err := allowOwnershipRequest(context.Background(), "/info", opts, fi.inspectResource, fi.inspectExec, nil); err != nil || verdict != verdictPassThrough {
		t.Fatalf("allowOwnershipRequest(no match) = (%v, %v), want verdictPassThrough/nil", verdict, err)
	}
}

func TestOwnerHelpers(t *testing.T) {
	t.Parallel()
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

	if got := singularResource(dockerresource.KindContainer); got != "container" {
		t.Fatalf("singularResource(container) = %q, want container", got)
	}
	if got := singularResource(dockerresource.KindImage); got != "image" {
		t.Fatalf("singularResource(image) = %q, want image", got)
	}
	if got := singularResource(dockerresource.KindNetwork); got != "network" {
		t.Fatalf("singularResource(network) = %q, want network", got)
	}
	if got := singularResource(dockerresource.KindVolume); got != "volume" {
		t.Fatalf("singularResource(volume) = %q, want volume", got)
	}
	if got := singularResource(dockerresource.Kind("services")); got != "service" {
		t.Fatalf("singularResource(services) = %q, want service", got)
	}
	if got := singularResource(dockerresource.Kind("tasks")); got != "task" {
		t.Fatalf("singularResource(tasks) = %q, want task", got)
	}
	if got := singularResource(dockerresource.Kind("secrets")); got != "secret" {
		t.Fatalf("singularResource(secrets) = %q, want secret", got)
	}
	if got := singularResource(dockerresource.Kind("configs")); got != "config" {
		t.Fatalf("singularResource(configs) = %q, want config", got)
	}
	if got := singularResource(dockerresource.Kind("nodes")); got != "node" {
		t.Fatalf("singularResource(nodes) = %q, want node", got)
	}
	if got := singularResource(dockerresource.Kind("swarm")); got != "swarm" {
		t.Fatalf("singularResource(swarm) = %q, want swarm", got)
	}
	if got := singularResource(dockerresource.Kind("other")); got != "other" {
		t.Fatalf("singularResource(other) = %q, want other", got)
	}
}

func TestOwnershipSetDenied(t *testing.T) {
	t.Parallel()
	// Ownership passes nil for the normalize callback because filter has
	// already stamped meta.NormPath by the time ownership fires.
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/json", nil)
	logging.SetDeniedWithCode(&metaWriter{meta: meta}, req, "", "nope", nil)
	if meta.Decision != "deny" || meta.Reason != "nope" {
		t.Fatalf("meta = %#v, want deny/nope", meta)
	}
	logging.SetDeniedWithCode(httptest.NewRecorder(), req, "", "ignored", nil)
}

func TestIdentifierHelpers(t *testing.T) {
	t.Parallel()
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
	// Single-image export (data exfiltration): /images/{name}/get must resolve
	// to {name} so the owner-isolation check applies to the exported image.
	if id, ok := imageIdentifier("/images/busybox:latest/get"); !ok || id != "busybox:latest" {
		t.Fatalf("imageIdentifier(get) = (%q, %v), want (busybox:latest, true)", id, ok)
	}
	if id, ok := imageIdentifier("/images/registry.io/team/app/get"); !ok || id != "registry.io/team/app" {
		t.Fatalf("imageIdentifier(namespaced get) = (%q, %v), want (registry.io/team/app, true)", id, ok)
	}
	// Bare multi-image export (/images/get?names=) takes query params, not a
	// path identifier, and must stay excluded.
	if _, ok := imageIdentifier("/images/get"); ok {
		t.Fatal("expected bare /images/get to be excluded")
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
	if id, ok := nodeIdentifier("/nodes/node-1"); !ok || id != "node-1" {
		t.Fatalf("nodeIdentifier() = (%q, %v), want (node-1, true)", id, ok)
	}
	if _, ok := nodeIdentifier("/nodes"); ok {
		t.Fatal("expected /nodes to be excluded")
	}
	if !isSwarmPath("/swarm") {
		t.Fatal("expected /swarm to match swarm path")
	}
	if isSwarmPath("/swarm/update") {
		t.Fatal("expected /swarm/update to be excluded from swarm inspect path")
	}
}

func TestAddOwnerLabelToBuildQuery(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	nodeFilterReq := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	if err := addOwnerLabelFilter(nodeFilterReq, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelFilter(nodes) error = %v", err)
	}
	var nodeFilters map[string][]string
	if err := json.NewDecoder(strings.NewReader(nodeFilterReq.URL.Query().Get("filters"))).Decode(&nodeFilters); err != nil {
		t.Fatalf("decode node filters: %v", err)
	}
	if len(nodeFilters["node.label"]) != 1 || nodeFilters["node.label"][0] != "com.sockguard.owner=job-123" {
		t.Fatalf("node.label filters = %#v, want owner label", nodeFilters["node.label"])
	}
	if _, ok := nodeFilters["label"]; ok {
		t.Fatalf("unexpected generic label filters for nodes: %#v", nodeFilters["label"])
	}
}

// Direct decoder coverage lives in internal/dockerfilters; ownership tests
// exercise it through addOwnerLabelFilter.

func TestMutateJSONBody(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
		case "/nodes/node-1", "/swarm":
			_, _ = w.Write([]byte(`{"Spec":{"Labels":{"com.sockguard.owner":"job-123"}}}`))
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

	for _, kind := range []dockerresource.Kind{dockerresource.KindContainer, dockerresource.KindImage, dockerresource.KindNetwork, dockerresource.KindVolume} {
		identifier := map[dockerresource.Kind]string{
			dockerresource.KindContainer: "abc",
			dockerresource.KindImage:     "busybox:latest",
			dockerresource.KindNetwork:   "net-1",
			dockerresource.KindVolume:    "vol-1",
		}[kind]
		labels, found, err := inspector.inspectResource(context.Background(), kind, identifier)
		if err != nil || !found || labels["com.sockguard.owner"] != "job-123" {
			t.Fatalf("inspectResource(%s) = (%#v, %v, %v), want owner labels", kind, labels, found, err)
		}
	}

	for _, kind := range []dockerresource.Kind{dockerresource.Kind("services"), dockerresource.Kind("tasks"), dockerresource.Kind("secrets"), dockerresource.Kind("configs")} {
		identifier := map[dockerresource.Kind]string{
			dockerresource.Kind("services"): "svc-1",
			dockerresource.Kind("tasks"):    "task-1",
			dockerresource.Kind("secrets"):  "secret-1",
			dockerresource.Kind("configs"):  "config-1",
		}[kind]
		labels, found, err := inspector.inspectResource(context.Background(), kind, identifier)
		if err != nil || !found || labels["com.sockguard.owner"] != "job-123" {
			t.Fatalf("inspectResource(%s) = (%#v, %v, %v), want owner labels", kind, labels, found, err)
		}
	}
	for _, kind := range []dockerresource.Kind{dockerresource.Kind("nodes"), dockerresource.Kind("swarm")} {
		identifier := map[dockerresource.Kind]string{
			dockerresource.Kind("nodes"): "node-1",
			dockerresource.Kind("swarm"): "",
		}[kind]
		labels, found, err := inspector.inspectResource(context.Background(), kind, identifier)
		if err != nil || !found || labels["com.sockguard.owner"] != "job-123" {
			t.Fatalf("inspectResource(%s) = (%#v, %v, %v), want owner labels", kind, labels, found, err)
		}
	}

	if _, found, err := inspector.inspectResource(context.Background(), dockerresource.KindContainer, "missing"); err != nil || found {
		t.Fatalf("inspectResource(missing) = found %v err %v, want false nil", found, err)
	}
	if _, _, err := inspector.inspectResource(context.Background(), dockerresource.KindContainer, "bad-status"); err == nil {
		t.Fatal("expected upstream status error")
	}
	if _, _, err := inspector.inspectResource(context.Background(), dockerresource.KindContainer, "bad-json"); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if _, found, err := inspector.inspectResource(context.Background(), dockerresource.KindNetwork, "missing"); err != nil || found {
		t.Fatalf("inspectResource(network missing) = found %v err %v, want false nil", found, err)
	}
	if _, _, err := inspector.inspectResource(context.Background(), dockerresource.KindVolume, "bad-status"); err == nil {
		t.Fatal("expected upstream status error for volume")
	}
	if _, _, err := inspector.inspectResource(context.Background(), dockerresource.KindNetwork, "bad-json"); err == nil {
		t.Fatal("expected network JSON decode error")
	}
	transportErrorInspector := upstreamInspector{client: newUnixHTTPClient(filepath.Join("/tmp", "sockguard-ownership-missing-"+time.Now().Format("150405000000000")+".sock"))}
	if _, _, err := transportErrorInspector.inspectResource(context.Background(), dockerresource.KindContainer, "abc"); err == nil {
		t.Fatal("expected transport error")
	}
	if _, _, err := inspector.inspectResource(context.Background(), dockerresource.Kind("other"), "id"); err == nil {
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
	t.Parallel()
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
	t.Parallel()
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

func TestMiddlewareOverwritesClientSuppliedOwnerLabel(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels, ok := body["Labels"].(map[string]any)
		if !ok {
			t.Fatalf("Labels = %#v, want object", body["Labels"])
		}
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("owner label = %#v, want job-123 (attacker-supplied value must be overwritten)", got)
		}
		if got := labels["com.example.team"]; got != "data" {
			t.Fatalf("unrelated label = %#v, want data (must be preserved untouched)", got)
		}
		w.WriteHeader(http.StatusCreated)
	}))

	body := `{"Image":"busybox:1.37","Labels":{"com.sockguard.owner":"attacker","com.example.team":"data"}}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}
