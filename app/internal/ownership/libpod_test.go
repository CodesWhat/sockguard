package ownership

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// TestMiddlewareStampsOwnerLabelOnLibpodCreateEndpoints covers #148 PR5 item
// 1: every libpod create endpoint gets the owner label injected under its
// verified wire-exact field name/casing.
func TestMiddlewareStampsOwnerLabelOnLibpodCreateEndpoints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		body       string
		wantLabels map[string]any // nil means "check r.URL.RawQuery's labels param instead"
	}{
		{
			name:       "container create lowercase labels",
			path:       "/libpod/containers/create",
			body:       `{"labels":{"existing":"value"}}`,
			wantLabels: map[string]any{"existing": "value", "com.sockguard.owner": "job-123"},
		},
		{
			name:       "pod create lowercase labels",
			path:       "/libpod/pods/create",
			body:       `{"name":"web","labels":{"existing":"value"}}`,
			wantLabels: map[string]any{"existing": "value", "com.sockguard.owner": "job-123"},
		},
		{
			name:       "network create lowercase labels",
			path:       "/libpod/networks/create",
			body:       `{"driver":"bridge","labels":{"existing":"value"}}`,
			wantLabels: map[string]any{"existing": "value", "com.sockguard.owner": "job-123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Bodies here deliberately carry no "image"/"pod" field so this
			// test only exercises label stamping — image/pod cross-owner
			// embedded-reference checks are covered by their own dedicated
			// tests below.
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				labels := nestedMapAnyForTest(t, body, "labels")
				for k, want := range tt.wantLabels {
					if got := labels[k]; got != want {
						t.Fatalf("labels[%q] = %#v, want %#v", k, got, want)
					}
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
			}
		})
	}
}

// TestMiddlewareStampsOwnerLabelOnLibpodVolumeCreateCapitalizedLabels
// verifies the volume-create deviation from the lowercase-labels rule:
// entities.VolumeCreateOptions carries no json tags at all, so
// encoding/json falls back to the capitalized Go field name "Labels" — the
// same reason the merged libpodVolumeCreateRequest type already uses
// json:"Driver"/json:"Options" instead of lowercase.
func TestMiddlewareStampsOwnerLabelOnLibpodVolumeCreateCapitalizedLabels(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if strings.Contains(string(raw), `"labels":`) {
			t.Fatalf("volume create body carried lowercase labels key: %s", raw)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		labels := nestedMapAnyForTest(t, body, "Labels")
		if got := labels["com.sockguard.owner"]; got != "job-123" {
			t.Fatalf("Labels owner = %#v, want job-123", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(`{"Driver":"local"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

// TestMiddlewareStampsOwnerLabelOnLibpodSecretCreateQueryParam verifies
// secret create's owner label goes into the "labels" query parameter, not
// the body — libpod secret create has no JSON body envelope (the body is
// the raw secret payload), and driver/labels are query params.
func TestMiddlewareStampsOwnerLabelOnLibpodSecretCreateQueryParam(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	forwardedBody := ""
	handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		forwardedBody = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?name=db-password", strings.NewReader("super-secret-payload"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if forwardedBody != "super-secret-payload" {
		t.Fatalf("forwarded body = %q, want raw secret payload untouched", forwardedBody)
	}
	var labels map[string]string
	if err := json.NewDecoder(strings.NewReader(req.URL.Query().Get("labels"))).Decode(&labels); err != nil {
		t.Fatalf("decode labels query param: %v", err)
	}
	if labels["com.sockguard.owner"] != "job-123" {
		t.Fatalf("labels query param = %#v, want owner label", labels)
	}
}

func TestMiddlewareStampsOwnerLabelOnlyOnLibpodBuildPost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		method      string
		target      string
		wantStamped bool
		wantStatus  int
	}{
		{
			name:        "direct build",
			method:      http.MethodPost,
			target:      `/libpod/build?cachefrom=base&labels=%7B%22existing%22%3A%22value%22%2C%22com.sockguard.owner%22%3A%22attacker%22%7D`,
			wantStamped: true,
			wantStatus:  http.StatusAccepted,
		},
		{
			name:        "versioned build",
			method:      http.MethodPost,
			target:      `/v5.0.0/libpod/build?cachefrom=base&labels=%7B%22existing%22%3A%22value%22%2C%22com.sockguard.owner%22%3A%22attacker%22%7D`,
			wantStamped: true,
			wantStatus:  http.StatusAccepted,
		},
		{
			name:       "get build is untouched",
			method:     http.MethodGet,
			target:     `/libpod/build?cachefrom=base&labels=%7B%22existing%22%3A%22value%22%2C%22com.sockguard.owner%22%3A%22attacker%22%7D`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "sibling path is untouched",
			method:     http.MethodPost,
			target:     `/libpod/build/context?cachefrom=base&labels=%7B%22existing%22%3A%22value%22%2C%22com.sockguard.owner%22%3A%22attacker%22%7D`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "malformed labels fail closed",
			method:     http.MethodPost,
			target:     `/libpod/build?labels=not-json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			forwarded := false
			handler := middlewareWithDeps(
				testLogger(),
				Options{Owner: "job-123", LabelKey: "com.sockguard.owner"},
				fakeInspector{}.inspectResource,
				fakeInspector{}.inspectExec,
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				if got := r.URL.Query().Get("cachefrom"); got != "base" && tt.wantStatus != http.StatusBadRequest {
					t.Fatalf("cachefrom = %q, want base", got)
				}
				var labels map[string]string
				if err := json.Unmarshal([]byte(r.URL.Query().Get("labels")), &labels); err != nil {
					t.Fatalf("decode forwarded labels: %v", err)
				}
				wantOwner := "attacker"
				if tt.wantStamped {
					wantOwner = "job-123"
				}
				if got := labels["com.sockguard.owner"]; got != wantOwner {
					t.Fatalf("owner label = %q, want %q", got, wantOwner)
				}
				if got := labels["existing"]; got != "value" {
					t.Fatalf("existing label = %q, want value", got)
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(tt.method, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if got := forwarded; got != (tt.wantStatus != http.StatusBadRequest) {
				t.Fatalf("forwarded = %v, want %v", got, tt.wantStatus != http.StatusBadRequest)
			}
		})
	}
}

// TestMiddlewareDeniesCrossOwnerLibpodPodCreateNamespaceSharing covers
// #148 PR5 item 4: POST /libpod/pods/create joining another owner's
// container namespace is denied, mirroring the existing
// container:<ref> namespace-sharing cross-owner check.
func TestMiddlewareDeniesCrossOwnerLibpodPodCreateNamespaceSharing(t *testing.T) {
	t.Parallel()
	fields := []string{"netns", "pidns", "ipcns", "userns", "utsns"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					"containers": {
						"target": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner libpod pod create namespace sharing to be denied")
			}))

			body := `{"name":"web","` + field + `":{"nsmode":"container","value":"target"}}`
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			var resp struct {
				Message string `json:"message"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode deny body: %v", err)
			}
			if !strings.HasPrefix(resp.Message, "libpod ") {
				t.Fatalf("deny message = %q, want libpod-prefixed reason", resp.Message)
			}
			if !strings.Contains(resp.Message, "target") {
				t.Fatalf("deny message = %q, want reference to target container", resp.Message)
			}
		})
	}
}

// TestMiddlewareAllowsSameOwnerLibpodPodCreateNamespaceSharing is the
// positive counterpart: joining an owned container's namespace succeeds and
// still gets the owner label injected.
func TestMiddlewareAllowsSameOwnerLibpodPodCreateNamespaceSharing(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"target": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(`{"name":"web","netns":{"nsmode":"container","value":"target"}}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !forwarded {
		t.Fatal("expected same-owner libpod pod create namespace sharing to be forwarded")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

// TestMiddlewareDeniesCrossOwnerLibpodContainerCreatePod covers the other
// direction of #148 PR5 item 4: POST /libpod/containers/create targeting a
// pod (SpecGenerator's "pod" field) owned by a different owner is denied.
func TestMiddlewareDeniesCrossOwnerLibpodContainerCreatePod(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"libpod-pods": {
				"other-pod": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected cross-owner libpod container create pod target to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"pod":"other-pod"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "libpod ") || !strings.Contains(rec.Body.String(), "other-pod") {
		t.Fatalf("deny body = %q, want libpod-prefixed pod denial referencing other-pod", rec.Body.String())
	}
}

// TestMiddlewareAllowsSameOwnerLibpodContainerCreatePod is the positive
// counterpart of the pod cross-owner check.
func TestMiddlewareAllowsSameOwnerLibpodContainerCreatePod(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner", AllowUnownedImages: true}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"libpod-pods": {
				"my-pod": {labels: map[string]string{"com.sockguard.owner": "job-123"}, found: true},
			},
		},
	}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"pod":"my-pod"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !forwarded || rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d forwarded=%v, want 202/forwarded; body: %s", rec.Code, forwarded, rec.Body.String())
	}
}

// TestMiddlewareDeniesCrossOwnerLibpodPodCreateInfraImage covers the
// infra_image embedded-reference check: an explicit, non-default infra
// image owned by a different owner is denied the same way container
// create's "image" field is.
func TestMiddlewareDeniesCrossOwnerLibpodPodCreateInfraImage(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"registry.example/other/infra:latest": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected cross-owner libpod pod create infra_image to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(`{"name":"web","infra_image":"registry.example/other/infra:latest"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestMiddlewareDeniesCrossOwnerLibpodContainerCreateImage mirrors the
// Docker-compat "image" embedded-reference denial for the libpod container
// create's lowercase "image" field.
func TestMiddlewareDeniesCrossOwnerLibpodContainerCreateImage(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"images": {
				"registry.example/other/app:latest": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected cross-owner libpod container create image to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/containers/create", strings.NewReader(`{"image":"registry.example/other/app:latest"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestMiddlewareLibpodReadPathOwnershipDispatch covers item 2/3: read/action
// paths under /libpod/ are ownership-checked the same way their Docker-compat
// counterparts are.
func TestMiddlewareLibpodReadPathOwnershipDispatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		kind dockerresource.Kind
		id   string
	}{
		{name: "container inspect", path: "/libpod/containers/abc/json", kind: dockerresource.KindContainer, id: "abc"},
		{name: "container action", path: "/libpod/containers/abc/start", kind: dockerresource.KindContainer, id: "abc"},
		{name: "pod inspect", path: "/libpod/pods/pod-1/json", kind: dockerresource.KindLibpodPod, id: "pod-1"},
		{name: "network inspect", path: "/libpod/networks/bridge/json", kind: dockerresource.KindNetwork, id: "bridge"},
		{name: "volume inspect", path: "/libpod/volumes/data/json", kind: dockerresource.KindVolume, id: "data"},
		{name: "secret inspect", path: "/libpod/secrets/db-pw/json", kind: dockerresource.KindSecret, id: "db-pw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			fi := fakeInspector{
				resources: map[string]map[string]inspectResult{
					string(tt.kind): {
						tt.id: {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
					},
				},
			}
			handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("expected cross-owner libpod read/action path to be denied")
			}))

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "libpod ") {
				t.Fatalf("deny body = %q, want libpod-prefixed reason", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareLibpodChecksKeywordNamedResourcesOutsideCollectionActions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		target     string
		kind       dockerresource.Kind
		identifier string
	}{
		{name: "container create action", method: http.MethodPost, target: "/libpod/containers/create/start", kind: dockerresource.KindContainer, identifier: "create"},
		{name: "container json inspect", method: http.MethodGet, target: "/libpod/containers/json/json", kind: dockerresource.KindContainer, identifier: "json"},
		{name: "container prune action", method: http.MethodPost, target: "/libpod/containers/prune/start", kind: dockerresource.KindContainer, identifier: "prune"},
		{name: "pod create inspect", method: http.MethodGet, target: "/libpod/pods/create/json", kind: dockerresource.KindLibpodPod, identifier: "create"},
		{name: "pod stats inspect", method: http.MethodGet, target: "/libpod/pods/stats/json", kind: dockerresource.KindLibpodPod, identifier: "stats"},
		{name: "network create inspect", method: http.MethodGet, target: "/libpod/networks/create/json", kind: dockerresource.KindNetwork, identifier: "create"},
		{name: "network prune inspect", method: http.MethodGet, target: "/libpod/networks/prune/json", kind: dockerresource.KindNetwork, identifier: "prune"},
		{name: "volume json inspect", method: http.MethodGet, target: "/libpod/volumes/json/json", kind: dockerresource.KindVolume, identifier: "json"},
		{name: "secret create inspect", method: http.MethodGet, target: "/libpod/secrets/create/json", kind: dockerresource.KindSecret, identifier: "create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotKind dockerresource.Kind
			var gotIdentifier string
			handler := middlewareWithDeps(testLogger(), Options{
				Owner:    "alice",
				LabelKey: "com.sockguard.owner",
			}, func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
				gotKind = kind
				gotIdentifier = identifier
				return map[string]string{"com.sockguard.owner": "bob"}, true, nil
			}, fakeInspector{}.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("keyword-named cross-owner libpod resource reached upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if gotKind != tt.kind || gotIdentifier != tt.identifier {
				t.Fatalf("inspect = %s/%q, want %s/%q", gotKind, gotIdentifier, tt.kind, tt.identifier)
			}
		})
	}
}

// TestMiddlewareLibpodExecDispatchResolvesContainerOwner covers the
// libpod exec identifier path: /libpod/exec/{id}/... resolves to its owning
// container via the shared (Docker-compat) exec-session store.
func TestMiddlewareLibpodExecDispatchResolvesContainerOwner(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"containers": {
				"container-1": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
		execs: map[string]execResult{
			"exec-1": {containerID: "container-1", found: true},
		},
	}
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected cross-owner libpod exec-start to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/libpod/exec/exec-1/start", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestMiddlewareLibpodListInjectsOwnerFilter covers libpodNeedsOwnerFilter
// dispatch for every libpod list endpoint (item 2/3).
func TestMiddlewareLibpodListInjectsOwnerFilter(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/libpod/containers/json",
		"/libpod/pods/json",
		"/libpod/networks/json",
		"/libpod/volumes/json",
		"/libpod/secrets/json",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
			var gotQuery string
			handler := middlewareWithDeps(testLogger(), opts, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.Query().Get("filters")
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			var filters map[string][]string
			if err := json.NewDecoder(strings.NewReader(gotQuery)).Decode(&filters); err != nil {
				t.Fatalf("decode filters query: %v", err)
			}
			want := "com.sockguard.owner=job-123"
			found := false
			for _, v := range filters["label"] {
				if v == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("filters[label] = %#v, want to contain %q", filters["label"], want)
			}
		})
	}
}

// TestMiddlewareLibpodDoesNotAffectDockerCompatPaths is the negative
// counterpart proving the libpod additions never fire for Docker-compat
// paths that happen to share a resource-kind name.
func TestMiddlewareLibpodDoesNotAffectDockerCompatPaths(t *testing.T) {
	t.Parallel()
	opts := Options{Owner: "job-123", LabelKey: "com.sockguard.owner"}
	fi := fakeInspector{
		resources: map[string]map[string]inspectResult{
			"libpod-pods": {
				"abc": {labels: map[string]string{"com.sockguard.owner": "job-999"}, found: true},
			},
		},
	}
	forwarded := false
	handler := middlewareWithDeps(testLogger(), opts, fi.inspectResource, fi.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))

	// "/pods/abc/json" is not a real Docker Engine API path (Docker has no
	// pods concept at all), but it must not accidentally match any libpod
	// predicate — every libpod matcher in this package is exact-prefix
	// guarded on "/libpod/".
	req := httptest.NewRequest(http.MethodGet, "/pods/abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !forwarded || rec.Code != http.StatusOK {
		t.Fatalf("status = %d forwarded=%v, want 200/forwarded (libpod predicates must not match non-/libpod/ paths)", rec.Code, forwarded)
	}
}
