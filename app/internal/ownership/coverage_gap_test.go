package ownership

// coverage_gap_test.go covers branches not exercised by the existing test suite.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

// ---------------------------------------------------------------------------
// middleware.go: middlewareWithDeps — error from owner lookup propagates to 502
// ---------------------------------------------------------------------------

func TestMiddlewareWithDepsOwnerLookupError(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	deps := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc": {err: errors.New("upstream error"), found: true},
			},
		},
	}.deps()

	handler := middlewareWithDeps(testLogger(), opts, deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected handler not to be reached")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/containers/abc/json", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: middlewareWithDeps — NormPath missing, falls back to filter.NormalizePath
// ---------------------------------------------------------------------------

func TestMiddlewareWithDepsNormPathFallback(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	reached := false
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Send a request through a plain recorder that has no access-log meta,
	// so the middleware must fall back to computing NormalizePath itself.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("expected downstream handler to be reached")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: middlewareWithDeps — mutate error from SetDenied path
// ---------------------------------------------------------------------------

func TestMiddlewareWithDepsMutateError(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected handler not to be reached")
	}))

	// Service create with a Labels that can't be decoded as object
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{"Labels":"bad"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: allowOwnershipRequest — swarm update path (isSwarmUpdatePath)
// ---------------------------------------------------------------------------

func TestAllowOwnershipRequestSwarmUpdate(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	deps := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"swarm": {"": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
		},
	}.deps()

	verdict, _, err := allowOwnershipRequest(context.Background(), "/swarm/update", opts, deps)
	if err != nil {
		t.Fatalf("allowOwnershipRequest(swarm update) error = %v", err)
	}
	// The swarm owner differs, so should be verdictDeny
	if verdict != verdictDeny {
		t.Fatalf("allowOwnershipRequest(swarm update) = %v, want verdictDeny", verdict)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: addOwnerLabelToServiceBody — error on TaskTemplate.ContainerSpec.Labels
// ---------------------------------------------------------------------------

func TestAddOwnerLabelToServiceBodyBadContainerLabels(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"Labels":{},"TaskTemplate":{"ContainerSpec":{"Labels":"bad"}}}`,
	))
	err := addOwnerLabelToServiceBody(req, "com.sockguard.owner", "job-123")
	if err == nil {
		t.Fatal("expected error for non-object ContainerSpec.Labels")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: nestedObjectPath — error from a non-object intermediate key
// ---------------------------------------------------------------------------

func TestNestedObjectPathBadIntermediate(t *testing.T) {
	decoded := map[string]any{
		"TaskTemplate": "not-an-object",
	}
	_, err := nestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels")
	if err == nil {
		t.Fatal("expected error for non-object intermediate key")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: inspectResource — image with ContainerConfig labels fallback
// ---------------------------------------------------------------------------

func TestDecodeResourceLabelsImageContainerConfigFallback(t *testing.T) {
	body := strings.NewReader(`{
		"Config":{"Labels":{}},
		"ContainerConfig":{"Labels":{"com.sockguard.owner":"job-123"}}
	}`)
	labels, err := decodeResourceLabels(body, resourceKindImage)
	if err != nil {
		t.Fatalf("decodeResourceLabels(image with ContainerConfig) error = %v", err)
	}
	if labels["com.sockguard.owner"] != "job-123" {
		t.Fatalf("labels = %#v, want com.sockguard.owner=job-123", labels)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: decodeResourceLabels — task with Spec.ContainerSpec labels fallback
// ---------------------------------------------------------------------------

func TestDecodeResourceLabelsTaskSpecFallback(t *testing.T) {
	body := strings.NewReader(`{
		"Labels":{},
		"Spec":{"ContainerSpec":{"Labels":{"com.sockguard.owner":"job-123"}}}
	}`)
	labels, err := decodeResourceLabels(body, resourceKindTask)
	if err != nil {
		t.Fatalf("decodeResourceLabels(task Spec fallback) error = %v", err)
	}
	if labels["com.sockguard.owner"] != "job-123" {
		t.Fatalf("labels = %#v, want com.sockguard.owner=job-123", labels)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: decodeResourceLabels — unsupported kind
// ---------------------------------------------------------------------------

func TestDecodeResourceLabelsUnsupportedKind(t *testing.T) {
	_, err := decodeResourceLabels(strings.NewReader(`{}`), resourceKind("other"))
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("expected unsupported resource kind error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: inspectExec — exec error path via fakeInspector
// ---------------------------------------------------------------------------

func TestAllowOwnershipRequestExecError(t *testing.T) {
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	deps := fakeInspector{
		execs: map[string]execResult{
			"exec-bad": {err: errors.New("exec lookup failed")},
		},
	}.deps()

	_, _, err := allowOwnershipRequest(context.Background(), "/exec/exec-bad/start", opts, deps)
	if err == nil {
		t.Fatal("expected error from exec lookup failure")
	}
}

// ---------------------------------------------------------------------------
// paths.go: taskIdentifier — empty identifier
// ---------------------------------------------------------------------------

func TestTaskIdentifierEmpty(t *testing.T) {
	if _, ok := taskIdentifier("/tasks/"); ok {
		t.Fatal("expected empty task identifier to be excluded")
	}
}

// paths.go: nodeIdentifier — empty identifier
func TestNodeIdentifierEmpty(t *testing.T) {
	if _, ok := nodeIdentifier("/nodes/"); ok {
		t.Fatal("expected empty node identifier to be excluded")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: SetDenied with normalize callback — exercises NormPath population
// ---------------------------------------------------------------------------

func TestSetDeniedWithNormalizeFillsNormPath(t *testing.T) {
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	logging.SetDenied(&metaWriter{meta: meta}, req, "test reason", func(path string) string {
		return "/containers/json"
	})
	if meta.NormPath != "/containers/json" {
		t.Fatalf("NormPath = %q, want /containers/json", meta.NormPath)
	}
}

func TestSetDeniedNilMeta(t *testing.T) {
	// Plain recorder has no RequestMeta — should be a no-op
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	logging.SetDenied(httptest.NewRecorder(), req, "ignored", nil)
}

// ---------------------------------------------------------------------------
// middleware.go: decodeResourceLabels — JSON decode error for each kind
// ---------------------------------------------------------------------------

func TestDecodeResourceLabelsDecodeErrors(t *testing.T) {
	kinds := []resourceKind{
		resourceKindContainer,
		resourceKindImage,
		resourceKindNetwork,
		resourceKindVolume,
		resourceKindService,
		resourceKindTask,
		resourceKindSecret,
		resourceKindConfig,
		resourceKindNode,
		resourceKindSwarm,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			_, err := decodeResourceLabels(strings.NewReader(`{`), kind)
			if err == nil {
				t.Fatalf("expected decode error for %s", kind)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// middleware.go: inspectResource — unsupported kind path
// ---------------------------------------------------------------------------

func TestInspectResourceUnsupportedKind(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))

	inspector := upstreamInspector{client: newUnixHTTPClient(socketPath)}
	_, _, err := inspector.inspectResource(context.Background(), resourceKind("bogus"), "id")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("expected unsupported resource kind error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Logging: SetDenied (0%) — covered via ownership.SetDenied calls above and
// directly below for completeness.
// ---------------------------------------------------------------------------

func TestSetDeniedPopulatesDecisionAndReason(t *testing.T) {
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	logging.SetDenied(&metaWriter{meta: meta}, req, "test deny reason", nil)

	if meta.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", meta.Decision)
	}
	if meta.Reason != "test deny reason" {
		t.Fatalf("Reason = %q, want test deny reason", meta.Reason)
	}
}

// metaWriter used by other tests in this package — defined in middleware_test.go
// but re-verified here. Declare a local one since middleware_test.go is in same package.

// ---------------------------------------------------------------------------
// middleware.go: addOwnerLabelToServiceBody — no existing TaskTemplate
// ---------------------------------------------------------------------------

func TestAddOwnerLabelToServiceBodyNoTaskTemplate(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(`{"Name":"mysvc"}`))
	if err := addOwnerLabelToServiceBody(req, "com.sockguard.owner", "job-123"); err != nil {
		t.Fatalf("addOwnerLabelToServiceBody() error = %v", err)
	}
	var body map[string]any
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// TaskTemplate and ContainerSpec must be created and contain the owner label
	tt, ok := body["TaskTemplate"].(map[string]any)
	if !ok {
		t.Fatalf("TaskTemplate = %#v, want object", body["TaskTemplate"])
	}
	cs, ok := tt["ContainerSpec"].(map[string]any)
	if !ok {
		t.Fatalf("ContainerSpec = %#v, want object", tt["ContainerSpec"])
	}
	cl, ok := cs["Labels"].(map[string]any)
	if !ok {
		t.Fatalf("Labels = %#v, want object", cs["Labels"])
	}
	if cl["com.sockguard.owner"] != "job-123" {
		t.Fatalf("owner label = %#v, want job-123", cl["com.sockguard.owner"])
	}
}
