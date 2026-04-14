package visibility

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestMiddlewareRejectsMalformedFilterQuery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json?filters=not-json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected malformed filters query to be rejected before next handler")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "decode filters") {
		t.Fatalf("body = %s, want decode filters error", rec.Body.String())
	}
}

func TestMiddlewareReturnsInternalServerErrorWhenResolvedProfileIsMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		Profiles: map[string]Policy{
			"readonly": {VisibleResourceLabels: []string{"com.sockguard.visible=true"}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "missing", true },
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected unresolved profile to short-circuit request")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "visibility profile could not be resolved") {
		t.Fatalf("body = %s, want unresolved profile error", rec.Body.String())
	}
}

func TestMiddlewarePassesThroughWhenInspectTargetIsMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{
		inspectResource: func(context.Context, resourceKind, string) (map[string]string, bool, error) {
			return nil, false, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/missing/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected missing inspect target to pass through to upstream")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestDecodeDockerFilters(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string][]string
		wantErr string
	}{
		{
			name:  "empty",
			input: "",
			want:  map[string][]string{},
		},
		{
			name:  "modern array syntax",
			input: `{"label":["a=b"],"type":["container"]}`,
			want: map[string][]string{
				"label": {"a=b"},
				"type":  {"container"},
			},
		},
		{
			name:  "legacy object syntax",
			input: `{"label":{"a=b":true,"c=d":true}}`,
			want: map[string][]string{
				"label": {"a=b", "c=d"},
			},
		},
		{
			name:    "non string array entry",
			input:   `{"label":[true]}`,
			wantErr: "unexpected label filter element type",
		},
		{
			name:    "unsupported top level filter type",
			input:   `{"label":true}`,
			wantErr: "unexpected label filter type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeDockerFilters(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("decodeDockerFilters(%q) error = nil, want %q", tt.input, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("decodeDockerFilters(%q) error = %v, want substring %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeDockerFilters(%q) error = %v, want nil", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("decodeDockerFilters(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}
