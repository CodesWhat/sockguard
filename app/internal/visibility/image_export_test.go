package visibility

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

func TestVisibilityImageExportRouteClassification(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   imageExportRoute
	}{
		{name: "Docker batch export", method: http.MethodGet, path: "/images/get", want: imageExportRouteDockerBatch},
		{name: "Docker per-image export", method: http.MethodGet, path: "/images/app/get", want: imageExportRouteDockerSingle},
		{name: "Docker namespaced per-image export", method: http.MethodGet, path: "/images/registry.example/team/app/get", want: imageExportRouteDockerSingle},
		{name: "libpod batch export", method: http.MethodGet, path: "/libpod/images/export", want: imageExportRouteLibpodBatch},
		{name: "Docker image list collection", method: http.MethodGet, path: "/images/json"},
		{name: "Docker batch export HEAD", method: http.MethodHead, path: "/images/get"},
		{name: "Docker per-image export POST", method: http.MethodPost, path: "/images/app/get"},
		{name: "libpod batch export POST", method: http.MethodPost, path: "/libpod/images/export"},
		{name: "native libpod per-image export", method: http.MethodGet, path: "/libpod/images/app/get"},
		{name: "unrelated subresource", method: http.MethodGet, path: "/containers/app/get"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyImageExportRoute(tt.method, tt.path); got != tt.want {
				t.Fatalf("classifyImageExportRoute(%q, %q) = %d, want %d", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestVisibilityRefusesDockerImageExportsWithUnenumerablePlatformEffects(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "query-selected batch export", target: "/v1.53/images/get?names=visible%3A1"},
		{name: "per-image export with omitted platform", target: "/v1.53/images/visible%3A1/get"},
		{name: "per-image export with explicit platform", target: "/v1.53/images/visible%3A1/get?platform=linux%2Farm64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspectCalls := 0
			handler := middlewareWithDeps(testVisibilityLogger(), Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					inspectCalls++
					return map[string]string{"com.sockguard.visible": "true"}, true, nil
				},
			})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("Docker image export with unenumerable platform effects reached the upstream")
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if inspectCalls != 0 {
				t.Fatalf("inspect calls = %d, want none before refusing an effect set that cannot be enumerated", inspectCalls)
			}
		})
	}
}

func TestVisibilityPreflightsEveryLibpodBatchExportReference(t *testing.T) {
	var gotIDs []string
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindImage {
				t.Fatalf("inspect kind = %q, want %q", kind, dockerresource.KindImage)
			}
			gotIDs = append(gotIDs, id)
			return map[string]string{"com.sockguard.visible": "true"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v5.8.1/libpod/images/export?references=one%3A1&references=two%3A1", nil))

	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
	}
	if strings.Join(gotIDs, ",") != "one:1,two:1" {
		t.Fatalf("inspected images = %#v, want both selected references in order", gotIDs)
	}
}

func TestVisibilityDeniesWholeLibpodBatchExportWhenAnyReferenceIsHidden(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, id string) (map[string]string, bool, error) {
			visible := "true"
			if id == "hidden:1" {
				visible = "false"
			}
			return map[string]string{"com.sockguard.visible": visible}, true, nil
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=visible%3A1&references=hidden%3A1", nil))

	if rec.Code != http.StatusNotFound || reached {
		t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusNotFound, rec.Body.String())
	}
}

func TestVisibilityDeniesLibpodBatchExportWhenReferenceIsMissing(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindImage {
				t.Fatalf("inspect kind = %q, want %q", kind, dockerresource.KindImage)
			}
			if id != "missing:1" {
				t.Fatalf("inspect id = %q, want %q", id, "missing:1")
			}
			return nil, false, nil
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=missing%3A1", nil))

	if rec.Code != http.StatusNotFound || reached {
		t.Fatalf("status = %d reached = %v, want %d and false; body: %s", rec.Code, reached, http.StatusNotFound, rec.Body.String())
	}
}

func TestVisibilityLibpodBatchExportLookupFailureStopsBeforeUpstream(t *testing.T) {
	handler := middlewareWithDeps(testVisibilityLogger(), Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
			return nil, false, errors.New("inspect failed")
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("batch export with a failed visibility lookup reached the upstream")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/images/export?references=broken%3A1", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

func TestVisibilityLibpodBatchExportReferenceLimit(t *testing.T) {
	const maxSelectedReferences = 256

	t.Run("exact limit is allowed and duplicate lookups are coalesced", func(t *testing.T) {
		inspectCalls := 0
		reached := false
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				inspectCalls++
				return map[string]string{"com.sockguard.visible": "true"}, true, nil
			},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}))

		target := "/libpod/images/export?" + strings.Repeat("references=visible%3A1&", maxSelectedReferences)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != http.StatusNoContent || !reached {
			t.Fatalf("status = %d reached = %v, want %d and true; body: %s", rec.Code, reached, http.StatusNoContent, rec.Body.String())
		}
		if inspectCalls != 1 {
			t.Fatalf("inspect calls = %d, want one coalesced lookup", inspectCalls)
		}
	})

	t.Run("one over limit is rejected before lookup", func(t *testing.T) {
		inspectCalls := 0
		handler := middlewareWithDeps(testVisibilityLogger(), Options{
			VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		}, visibilityDeps{
			inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				inspectCalls++
				return map[string]string{"com.sockguard.visible": "true"}, true, nil
			},
		})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("oversized image batch reached the upstream")
		}))

		target := "/libpod/images/export?" + strings.Repeat("references=visible%3A1&", maxSelectedReferences+1)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if inspectCalls != 0 {
			t.Fatalf("inspect calls = %d, want none", inspectCalls)
		}
	})
}
