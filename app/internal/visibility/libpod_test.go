package visibility

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

func testVisibilityLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMiddlewareLibpodListInjectsVisibilityLabelFilter covers #148 PR5 item
// 2: every libpod list endpoint gets the visibility label filter injected,
// mirroring needsVisibilityLabelFilter's existing Docker-compat coverage.
func TestMiddlewareLibpodListInjectsVisibilityLabelFilter(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/libpod/containers/json",
		"/libpod/pods/json",
		"/libpod/networks/json",
		"/libpod/volumes/json",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			var gotQuery string
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.RequestURI()
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			if !strings.Contains(gotQuery, "com.sockguard.visible%3Dtrue") {
				t.Fatalf("forwarded query = %q, want visibility label filter", gotQuery)
			}
		})
	}
}

// TestMiddlewareLibpodPodListAndInspectVisibility covers item 3:
// KindLibpodPod list and inspect visibility filtering.
func TestMiddlewareLibpodPodListAndInspectVisibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// rolloutMode is applied to the request's logging.RequestMeta when
		// non-empty; left unset (nil meta) otherwise, matching the two
		// non-rollout cases below which never inspect meta.
		rolloutMode string
		labels      map[string]string
		// checkInspectArgs additionally asserts inspectResource is called
		// with kind=KindLibpodPod id=pod-1, as the original single-case
		// "hidden pod" test did.
		checkInspectArgs bool
		// innerStatus is what the wrapped next-handler writes when reached.
		innerStatus      int
		wantForwarded    bool
		wantStatus       int
		wantBodyContains string
		wantDecision     string
		wantReasonCode   string
		wantReasonPrefix string
	}{
		{
			name:             "inspect hidden pod returns 404",
			labels:           map[string]string{"com.sockguard.visible": "false"},
			checkInspectArgs: true,
			innerStatus:      http.StatusOK,
			wantForwarded:    false,
			wantStatus:       http.StatusNotFound,
			wantBodyContains: "resource not found",
		},
		{
			name:          "inspect visible pod is forwarded",
			labels:        map[string]string{"com.sockguard.visible": "true"},
			innerStatus:   http.StatusOK,
			wantForwarded: true,
			wantStatus:    http.StatusOK,
		},
		{
			name:             "rollout mode passes hidden pod through with would-deny",
			labels:           map[string]string{"com.sockguard.visible": "false"},
			rolloutMode:      "warn",
			innerStatus:      http.StatusNoContent,
			wantForwarded:    true,
			wantStatus:       http.StatusNoContent,
			wantDecision:     logging.DecisionWouldDeny,
			wantReasonCode:   reasonCodeVisibilityPolicyHidResource,
			wantReasonPrefix: "libpod ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nextCalled := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
					if tt.checkInspectArgs && (kind != dockerresource.KindLibpodPod || id != "pod-1") {
						t.Fatalf("inspectResource called with kind=%s id=%s, want KindLibpodPod pod-1", kind, id)
					}
					return tt.labels, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(tt.innerStatus)
			}))

			req := httptest.NewRequest(http.MethodGet, "/libpod/pods/pod-1/json", nil)
			var meta *logging.RequestMeta
			if tt.rolloutMode != "" {
				meta = &logging.RequestMeta{RolloutMode: tt.rolloutMode}
				req = req.WithContext(logging.WithMeta(req.Context(), meta))
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if nextCalled != tt.wantForwarded {
				t.Fatalf("nextCalled = %v, want %v", nextCalled, tt.wantForwarded)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantBodyContains != "" && !strings.Contains(rec.Body.String(), tt.wantBodyContains) {
				t.Fatalf("body = %s, want contains %q", rec.Body.String(), tt.wantBodyContains)
			}
			if tt.wantDecision != "" {
				if meta.Decision != tt.wantDecision {
					t.Fatalf("meta.Decision = %q, want %q", meta.Decision, tt.wantDecision)
				}
				if meta.ReasonCode != tt.wantReasonCode {
					t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, tt.wantReasonCode)
				}
				if !strings.HasPrefix(meta.Reason, tt.wantReasonPrefix) {
					t.Fatalf("meta.Reason = %q, want prefix %q", meta.Reason, tt.wantReasonPrefix)
				}
			}
		})
	}
}

// TestMiddlewareLibpodHiddenResourceReasonHasLibpodPrefix covers item 5: the
// hidden-resource deny reason is prefixed "libpod " for libpod-family
// requests and left unprefixed for Docker-compat ones.
func TestMiddlewareLibpodHiddenResourceReasonHasLibpodPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		kind       dockerresource.Kind
		wantPrefix bool
	}{
		{name: "libpod pod inspect", path: "/libpod/pods/pod-1/json", kind: dockerresource.KindLibpodPod, wantPrefix: true},
		{name: "libpod container inspect", path: "/libpod/containers/abc/json", kind: dockerresource.KindContainer, wantPrefix: true},
		{name: "docker-compat container inspect", path: "/containers/abc/json", kind: dockerresource.KindContainer, wantPrefix: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
			}
			gotPrefix := strings.HasPrefix(meta.Reason, "libpod ")
			if gotPrefix != tt.wantPrefix {
				t.Fatalf("meta.Reason = %q, wantPrefix = %v", meta.Reason, tt.wantPrefix)
			}
		})
	}
}

// TestUpstreamInspectorLibpodNetworkArrayUnwrapRoundTrip is the end-to-end
// counterpart of dockerresource's array-unwrap unit tests: a real
// upstreamInspector.inspectResource call against a mock libpod-shaped
// single-element-array response for GET /libpod/networks/{id}/json must
// decode successfully rather than surfacing a decode error (which the
// middleware would otherwise turn into a 502 for a legitimate response —
// #148 design doc C6, "network-inspect array unwrap").
func TestUpstreamInspectorLibpodNetworkArrayUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "bare object", body: `{"labels":{"team":"a"}}`},
		{name: "single-element array", body: `[{"labels":{"team":"a"}}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotPath string
			ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tt.body)
			}))

			labels, found, err := ins.inspectResource(context.Background(), dockerresource.KindLibpodNetwork, "bridge")
			if err != nil {
				t.Fatalf("inspectResource error = %v", err)
			}
			if !found {
				t.Fatal("found = false, want true")
			}
			if labels["team"] != "a" {
				t.Fatalf("labels = %#v, want team=a", labels)
			}
			if gotPath != "/libpod/networks/bridge/json" {
				t.Fatalf("requested path = %q, want /libpod/networks/bridge/json", gotPath)
			}
		})
	}
}

// TestMiddlewareLibpodDoesNotAffectDockerCompatVisibilityPaths is the
// negative counterpart proving libpod predicates never fire for
// Docker-compat paths.
func TestMiddlewareLibpodDoesNotAffectDockerCompatVisibilityPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{
			// Docker has no pods concept, so "/pods/abc/json" is not a real
			// Docker Engine API path — it must not accidentally match a
			// libpod predicate, since every libpod matcher here is
			// exact-prefix guarded on "/libpod/".
			name: "docker-compat path resembling a libpod pod route",
			path: "/pods/abc/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nextCalled := false
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !nextCalled || rec.Code != http.StatusOK {
				t.Fatalf("status = %d nextCalled=%v, want 200/forwarded (libpod predicates must not match non-/libpod/ paths)", rec.Code, nextCalled)
			}
		})
	}
}
