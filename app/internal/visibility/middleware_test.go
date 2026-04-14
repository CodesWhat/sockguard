package visibility

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareInjectsVisibilityLabelsIntoContainerListAndEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gotPaths []string

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
		Profiles: map[string]Policy{
			"watchtower": {VisibleResourceLabels: []string{"com.sockguard.client=watchtower"}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "watchtower", true },
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, target := range []string{
		"/v1.53/containers/json",
		`/v1.53/events?filters={"type":["container"]}`,
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status for %s = %d, want %d", target, rec.Code, http.StatusNoContent)
		}
	}

	if len(gotPaths) != 2 {
		t.Fatalf("got %d forwarded requests, want 2", len(gotPaths))
	}
	if !strings.Contains(gotPaths[0], "com.sockguard.visible%3Dtrue") {
		t.Fatalf("container list query = %q, want default visibility label filter", gotPaths[0])
	}
	if !strings.Contains(gotPaths[0], "com.sockguard.client%3Dwatchtower") {
		t.Fatalf("container list query = %q, want profile visibility label filter", gotPaths[0])
	}
	if !strings.Contains(gotPaths[1], "type") || !strings.Contains(gotPaths[1], "com.sockguard.visible%3Dtrue") {
		t.Fatalf("events query = %q, want preserved filters plus visibility labels", gotPaths[1])
	}
}

func TestMiddlewareReturnsNotFoundForInvisibleContainerInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(context.Context, resourceKind, string) (map[string]string, bool, error) {
			return map[string]string{"com.sockguard.visible": "false"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected invisible inspect request to be short-circuited")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "resource not found") {
		t.Fatalf("body = %s, want resource not found", rec.Body.String())
	}
}

func TestMiddlewareAllowsVisibleExecInspectViaContainerLabels(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectExec: func(context.Context, string) (string, bool, error) {
			return "container-123", true, nil
		},
		inspectResource: func(_ context.Context, kind resourceKind, identifier string) (map[string]string, bool, error) {
			if kind != resourceKindContainer || identifier != "container-123" {
				t.Fatalf("inspectResource kind/id = %s/%s, want containers/container-123", kind, identifier)
			}
			return map[string]string{"com.sockguard.visible": "true"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/exec/exec-123/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected visible exec inspect to reach next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}
