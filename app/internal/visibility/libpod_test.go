package visibility

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/logging"
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
		"/libpod/secrets/json",
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

	t.Run("inspect hidden pod returns 404", func(t *testing.T) {
		t.Parallel()
		nextCalled := false
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
				if kind != dockerresource.KindLibpodPod || id != "pod-1" {
					t.Fatalf("inspectResource called with kind=%s id=%s, want KindLibpodPod pod-1", kind, id)
				}
				return map[string]string{"com.sockguard.visible": "false"}, true, nil
			},
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/libpod/pods/pod-1/json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Fatal("expected invisible pod inspect to be short-circuited")
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "resource not found") {
			t.Fatalf("body = %s, want resource not found", rec.Body.String())
		}
	})

	t.Run("inspect visible pod is forwarded", func(t *testing.T) {
		t.Parallel()
		nextCalled := false
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				return map[string]string{"com.sockguard.visible": "true"}, true, nil
			},
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/libpod/pods/pod-1/json", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled || rec.Code != http.StatusOK {
			t.Fatalf("status = %d nextCalled=%v, want 200/forwarded; body: %s", rec.Code, nextCalled, rec.Body.String())
		}
	})

	t.Run("rollout mode passes hidden pod through with would-deny", func(t *testing.T) {
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
			w.WriteHeader(http.StatusNoContent)
		}))

		meta := &logging.RequestMeta{RolloutMode: "warn"}
		req := httptest.NewRequest(http.MethodGet, "/libpod/pods/pod-1/json", nil)
		req = req.WithContext(logging.WithMeta(req.Context(), meta))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Fatal("expected invisible libpod pod inspect to pass through under rollout mode")
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (inner write)", rec.Code)
		}
		if meta.Decision != logging.DecisionWouldDeny {
			t.Fatalf("meta.Decision = %q, want would_deny", meta.Decision)
		}
		if meta.ReasonCode != reasonCodeVisibilityPolicyHidResource {
			t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyHidResource)
		}
		if !strings.HasPrefix(meta.Reason, "libpod ") {
			t.Fatalf("meta.Reason = %q, want libpod-prefixed reason", meta.Reason)
		}
	})
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

	// Docker has no pods concept, so "/pods/abc/json" is not a real Docker
	// Engine API path — it must not accidentally match a libpod predicate,
	// since every libpod matcher here is exact-prefix guarded on "/libpod/".
	req := httptest.NewRequest(http.MethodGet, "/pods/abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled || rec.Code != http.StatusOK {
		t.Fatalf("status = %d nextCalled=%v, want 200/forwarded (libpod predicates must not match non-/libpod/ paths)", rec.Code, nextCalled)
	}
}
