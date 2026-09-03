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

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// ---------------------------------------------------------------------------
// middleware.go: middlewareWithDeps — error from owner lookup propagates to 502
// ---------------------------------------------------------------------------

func TestMiddlewareWithDepsOwnerLookupError(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc": {err: errors.New("upstream error"), found: true},
			},
		},
	}

	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	reached := false
	fi := fakeInspector{}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestMiddlewareWithDepsUsesPrecomputedNormPath(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"abc": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected precomputed normalized path to drive owner lookup")
	}))

	meta := &logging.RequestMeta{NormPath: "/containers/abc/json"}
	req := httptest.NewRequest(http.MethodGet, "/not-used", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: middlewareWithDeps — mutate error from SetDenied path
// ---------------------------------------------------------------------------

func TestMiddlewareWithDepsMutateError(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"swarm": {"": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true}},
		},
	}

	verdict, _, err := allowOwnershipRequest(context.Background(), http.MethodPost, "/swarm/update", opts, fi.inspectResource, fi.inspectExec, nil)
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
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(
		`{"Labels":{},"TaskTemplate":{"ContainerSpec":{"Labels":"bad"}}}`,
	))
	err := addOwnerLabelToServiceBody(req, "com.sockguard.owner", "job-123")
	if err == nil {
		t.Fatal("expected error for non-object ContainerSpec.Labels")
	}
}

// ---------------------------------------------------------------------------
// json_mutate.go: filter.NestedObjectPath — error from a non-object
// intermediate key (nestedObjectPath was consolidated into filter.NestedObjectPath;
// see internal/filter/json_mutate.go).
// ---------------------------------------------------------------------------

func TestNestedObjectPathBadIntermediate(t *testing.T) {
	t.Parallel()
	decoded := map[string]any{
		"TaskTemplate": "not-an-object",
	}
	_, err := filter.NestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels")
	if err == nil {
		t.Fatal("expected error for non-object intermediate key")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: inspectExec — exec error path via fakeInspector
// ---------------------------------------------------------------------------

func TestAllowOwnershipRequestExecError(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		execs: map[string]execResult{
			"exec-bad": {err: errors.New("exec lookup failed")},
		},
	}

	_, _, err := allowOwnershipRequest(context.Background(), http.MethodPost, "/exec/exec-bad/start", opts, fi.inspectResource, fi.inspectExec, nil)
	if err == nil {
		t.Fatal("expected error from exec lookup failure")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: checkContainerNamespaceSharingRefs — strictest verdict
// accumulation. A single owned (verdictAllow) ref must make the function
// return verdictAllow rather than leaving strictest at its verdictPassThrough
// zero value.
// ---------------------------------------------------------------------------

func TestCheckContainerNamespaceSharingRefsSingleOwnedRefReturnsAllow(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"target": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}

	verdict, reason, err := checkContainerNamespaceSharingRefs(context.Background(), fi.inspectResource, []string{"target"}, opts)
	if err != nil {
		t.Fatalf("checkContainerNamespaceSharingRefs() error = %v", err)
	}
	if verdict != verdictAllow {
		t.Fatalf("checkContainerNamespaceSharingRefs() verdict = %v, want verdictAllow", verdict)
	}
	if reason != "" {
		t.Fatalf("checkContainerNamespaceSharingRefs() reason = %q, want empty", reason)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: allowOwnershipRequestUnprefixed — namespace-sharing and
// embedded-reference verdicts must actually flow into the combined result,
// not just gate on error/deny. Each test isolates one accumulation step by
// forcing every other step to verdictPassThrough (an empty ref list, or a
// normPath allowPathOwnershipRequest does not recognize).
// ---------------------------------------------------------------------------

// TestAllowOwnershipRequestUnprefixedNamespaceSharingAllowPropagates covers
// the "if verdict == verdictAllow { strictest = verdictAllow }" step inside
// the namespace-sharing block: with embeddedResources empty and a normPath
// (POST /containers/create) that allowPathOwnershipRequest always treats as
// passthrough, the final verdict can only be verdictAllow if the namespace
// block's own verdictAllow was captured into strictest.
func TestAllowOwnershipRequestUnprefixedNamespaceSharingAllowPropagates(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"target": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	refs := &ownershipRequestReferences{namespaceContainers: []string{"target"}}

	verdict, _, err := allowOwnershipRequestUnprefixed(context.Background(), http.MethodPost, "/containers/create", "/containers/create", opts, fi.inspectResource, fi.inspectExec, refs)
	if err != nil {
		t.Fatalf("allowOwnershipRequestUnprefixed() error = %v", err)
	}
	if verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequestUnprefixed() verdict = %v, want verdictAllow (namespace-sharing allow must propagate to the combined verdict)", verdict)
	}
}

// TestAllowOwnershipRequestUnprefixedEmbeddedAllowPropagates covers the
// equivalent accumulation step for refs.embeddedResources, with
// namespaceContainers left empty so only the embedded-reference block can
// have set strictest.
func TestAllowOwnershipRequestUnprefixedEmbeddedAllowPropagates(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"registry.example/owned/app:latest": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	refs := &ownershipRequestReferences{
		embeddedResources: []embeddedOwnershipReference{
			{kind: dockerresource.KindImage, identifier: "registry.example/owned/app:latest", source: "Image"},
		},
	}

	verdict, _, err := allowOwnershipRequestUnprefixed(context.Background(), http.MethodPost, "/containers/create", "/containers/create", opts, fi.inspectResource, fi.inspectExec, refs)
	if err != nil {
		t.Fatalf("allowOwnershipRequestUnprefixed() error = %v", err)
	}
	if verdict != verdictAllow {
		t.Fatalf("allowOwnershipRequestUnprefixed() verdict = %v, want verdictAllow (embedded-reference allow must propagate to the combined verdict)", verdict)
	}
}

// TestAllowOwnershipRequestUnprefixedPathCheckNotBypassedByEmbeddedAllow
// pins the ordering the "err != nil || verdict == verdictDeny" short-circuit
// after the embedded-reference check depends on: a verdictAllow from an
// embedded reference must NOT return early. If it did, the path-level
// ownership check below it — which is what actually protects the resource
// the URL names — would never run, and a cross-owner container action could
// be smuggled past ownership by attaching an unrelated owned image
// reference. Here the embedded image is owned, but the target container in
// the URL belongs to another owner, so the path check must still deny.
func TestAllowOwnershipRequestUnprefixedPathCheckNotBypassedByEmbeddedAllow(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"registry.example/owned/app:latest": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
			"containers": {
				"other-owners-container": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	refs := &ownershipRequestReferences{
		embeddedResources: []embeddedOwnershipReference{
			{kind: dockerresource.KindImage, identifier: "registry.example/owned/app:latest", source: "Image"},
		},
	}

	verdict, reason, err := allowOwnershipRequestUnprefixed(context.Background(), http.MethodPost, "/containers/other-owners-container/start", "/containers/other-owners-container/start", opts, fi.inspectResource, fi.inspectExec, refs)
	if err != nil {
		t.Fatalf("allowOwnershipRequestUnprefixed() error = %v", err)
	}
	if verdict != verdictDeny {
		t.Fatalf("allowOwnershipRequestUnprefixed() verdict = %v, want verdictDeny (an owned embedded reference must not bypass the URL target's own ownership check)", verdict)
	}
	if !strings.Contains(reason, "container") {
		t.Fatalf("allowOwnershipRequestUnprefixed() reason = %q, want it naming the denied container", reason)
	}
}

// ---------------------------------------------------------------------------
// middleware.go: mutateJSONBody — request-body size boundary. A body of
// exactly maxOwnershipBodyBytes must succeed; only strictly more must be
// rejected (the ">" in "int64(len(body)) > maxOwnershipBodyBytes" is not a
// ">=").
// ---------------------------------------------------------------------------

func TestMutateJSONBodyAcceptsExactlyMaxSizedBody(t *testing.T) {
	t.Parallel()
	const prefix, suffix = `{"pad":"`, `"}`
	padding := maxOwnershipBodyBytes - len(prefix) - len(suffix)
	body := prefix + strings.Repeat("x", padding) + suffix
	if len(body) != maxOwnershipBodyBytes {
		t.Fatalf("constructed body length = %d, want %d", len(body), maxOwnershipBodyBytes)
	}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))

	mutated := false
	err := mutateJSONBody(req, func(map[string]any) error {
		mutated = true
		return nil
	})
	if err != nil {
		t.Fatalf("mutateJSONBody() error = %v, want nil for an at-limit body", err)
	}
	if !mutated {
		t.Fatal("mutate callback not invoked for an at-limit body")
	}
}

// ---------------------------------------------------------------------------
// paths.go: needsOwnerFilter — GET/HEAD boundary
// ---------------------------------------------------------------------------

// needsOwnerFilter's read-side branch guards on "method != GET && method !=
// HEAD", so a HEAD request must be treated the same as GET. Only asserting
// with GET leaves the "method != HEAD" comparison free to flip without any
// test noticing.
func TestNeedsOwnerFilterHeadMethodMatchesGet(t *testing.T) {
	t.Parallel()
	if !needsOwnerFilter(http.MethodHead, "/containers/json") {
		t.Fatal("needsOwnerFilter(HEAD, /containers/json) = false, want true")
	}
	if needsOwnerFilter(http.MethodDelete, "/containers/json") {
		t.Fatal("needsOwnerFilter(DELETE, /containers/json) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// paths.go: containerIdentifier/networkIdentifier/volumeIdentifier —
// collection-keyword exclusion boundaries. Mirrors the libpod counterpart
// tables in libpod_test.go: each row isolates one method/keyword comparison
// in the exclusion clause so flipping any single == to != in it changes the
// expected outcome of at least one row.
// ---------------------------------------------------------------------------

func TestContainerIdentifierCollectionKeywordBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method     string
		identifier string
		wantOK     bool
	}{
		{http.MethodGet, "json", false},
		{http.MethodHead, "json", false},
		{http.MethodPost, "create", false},
		{http.MethodPost, "prune", false},
		{http.MethodDelete, "json", true},
		{http.MethodGet, "create", true},
		{http.MethodGet, "prune", true},
		{http.MethodGet, "other", true},
		{http.MethodHead, "create", true},
		{http.MethodPost, "json", true},
		{http.MethodPost, "other", true},
	}
	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.identifier, func(t *testing.T) {
			t.Parallel()
			got, ok := containerIdentifier(tt.method, "/containers/"+tt.identifier)
			if ok != tt.wantOK {
				t.Fatalf("containerIdentifier(%s, .../%s) ok = %v, want %v", tt.method, tt.identifier, ok, tt.wantOK)
			}
			if ok && got != tt.identifier {
				t.Fatalf("containerIdentifier(%s, .../%s) = %q, want %q", tt.method, tt.identifier, got, tt.identifier)
			}
		})
	}
}

func TestNetworkIdentifierCollectionKeywordBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method     string
		identifier string
		wantOK     bool
	}{
		{http.MethodPost, "create", false},
		{http.MethodPost, "prune", false},
		{http.MethodGet, "create", true},
		{http.MethodGet, "prune", true},
		{http.MethodPost, "other", true},
	}
	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.identifier, func(t *testing.T) {
			t.Parallel()
			got, ok := networkIdentifier(tt.method, "/networks/"+tt.identifier)
			if ok != tt.wantOK {
				t.Fatalf("networkIdentifier(%s, .../%s) ok = %v, want %v", tt.method, tt.identifier, ok, tt.wantOK)
			}
			if ok && got != tt.identifier {
				t.Fatalf("networkIdentifier(%s, .../%s) = %q, want %q", tt.method, tt.identifier, got, tt.identifier)
			}
		})
	}
}

func TestVolumeIdentifierCollectionKeywordBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method     string
		identifier string
		wantOK     bool
	}{
		{http.MethodPost, "create", false},
		{http.MethodPost, "prune", false},
		{http.MethodGet, "create", true},
		{http.MethodGet, "prune", true},
		{http.MethodPost, "other", true},
	}
	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.identifier, func(t *testing.T) {
			t.Parallel()
			got, ok := volumeIdentifier(tt.method, "/volumes/"+tt.identifier)
			if ok != tt.wantOK {
				t.Fatalf("volumeIdentifier(%s, .../%s) ok = %v, want %v", tt.method, tt.identifier, ok, tt.wantOK)
			}
			if ok && got != tt.identifier {
				t.Fatalf("volumeIdentifier(%s, .../%s) = %q, want %q", tt.method, tt.identifier, got, tt.identifier)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// paths.go: imageIdentifier — GET and POST collection-keyword boundaries.
// The two method branches are independent switch-like clauses, so each gets
// its own table isolating "rest == <keyword>" comparisons.
// ---------------------------------------------------------------------------

func TestImageIdentifierGetCollectionKeywordBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rest   string
		wantOK bool
	}{
		{"json", false},
		{"search", false},
		{"get", false},
		{"other", true},
	}
	for _, tt := range tests {
		t.Run(tt.rest, func(t *testing.T) {
			t.Parallel()
			got, ok := imageIdentifier(http.MethodGet, "/images/"+tt.rest)
			if ok != tt.wantOK {
				t.Fatalf("imageIdentifier(GET, .../%s) ok = %v, want %v", tt.rest, ok, tt.wantOK)
			}
			if ok && got != tt.rest {
				t.Fatalf("imageIdentifier(GET, .../%s) = %q, want %q", tt.rest, got, tt.rest)
			}
		})
	}
}

func TestImageIdentifierPostCollectionKeywordBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rest   string
		wantOK bool
	}{
		{"create", false},
		{"load", false},
		{"prune", false},
		{"other", true},
	}
	for _, tt := range tests {
		t.Run(tt.rest, func(t *testing.T) {
			t.Parallel()
			got, ok := imageIdentifier(http.MethodPost, "/images/"+tt.rest)
			if ok != tt.wantOK {
				t.Fatalf("imageIdentifier(POST, .../%s) ok = %v, want %v", tt.rest, ok, tt.wantOK)
			}
			if ok && got != tt.rest {
				t.Fatalf("imageIdentifier(POST, .../%s) = %q, want %q", tt.rest, got, tt.rest)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// paths.go: taskIdentifier — empty identifier
// ---------------------------------------------------------------------------

func TestTaskIdentifierEmpty(t *testing.T) {
	t.Parallel()
	if _, ok := taskIdentifier("/tasks/"); ok {
		t.Fatal("expected empty task identifier to be excluded")
	}
}

// paths.go: nodeIdentifier — empty identifier
func TestNodeIdentifierEmpty(t *testing.T) {
	t.Parallel()
	if _, ok := nodeIdentifier("/nodes/"); ok {
		t.Fatal("expected empty node identifier to be excluded")
	}
}

// ---------------------------------------------------------------------------
// middleware.go: SetDenied with normalize callback — exercises NormPath population
// ---------------------------------------------------------------------------

func TestSetDeniedWithNormalizeFillsNormPath(t *testing.T) {
	t.Parallel()
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	logging.SetDeniedWithCode(&metaWriter{meta: meta}, req, "", "test reason", func(path string) string {
		return "/containers/json"
	})
	if meta.NormPath != "/containers/json" {
		t.Fatalf("NormPath = %q, want /containers/json", meta.NormPath)
	}
}

func TestSetDeniedNilMeta(t *testing.T) {
	t.Parallel()
	// Plain recorder has no RequestMeta — should be a no-op
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	logging.SetDeniedWithCode(httptest.NewRecorder(), req, "", "ignored", nil)
}

// ---------------------------------------------------------------------------
// middleware.go: inspectResource — unsupported kind path
// ---------------------------------------------------------------------------

func TestInspectResourceUnsupportedKind(t *testing.T) {
	t.Parallel()
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))

	inspector := upstreamInspector{client: newUnixHTTPClient(socketPath)}
	_, _, err := inspector.inspectResource(context.Background(), dockerresource.Kind("bogus"), "id")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("expected unsupported resource kind error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Logging: SetDenied (0%) — covered via ownership.SetDenied calls above and
// directly below for completeness.
// ---------------------------------------------------------------------------

func TestSetDeniedPopulatesDecisionAndReason(t *testing.T) {
	t.Parallel()
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	logging.SetDeniedWithCode(&metaWriter{meta: meta}, req, "", "test deny reason", nil)

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
	t.Parallel()
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
