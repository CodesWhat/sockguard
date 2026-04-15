package visibility

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func missingSocketPath(t *testing.T) string {
	t.Helper()

	file, err := os.CreateTemp("/tmp", "sockguard-visibility-*.sock")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := file.Name()
	_ = file.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

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

func TestMiddlewareUpstreamInspectNetworkFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := Middleware(missingSocketPath(t), logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected upstream inspect failure to short-circuit request")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "visibility policy lookup failed") {
		t.Fatalf("body = %s, want visibility lookup failure", rec.Body.String())
	}
}

func TestVisibilityInspectTimeout(t *testing.T) {
	newTimeoutInspector := func() upstreamInspector {
		return upstreamInspector{
			client: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}),
			},
		}
	}

	t.Run("resource inspect", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, _, err := newTimeoutInspector().inspectResource(ctx, resourceKindContainer, "abc123")
		if err == nil {
			t.Fatal("expected inspectResource() to fail")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
		}
	})

	t.Run("exec inspect", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, _, err := newTimeoutInspector().inspectExec(ctx, "exec-123")
		if err == nil {
			t.Fatal("expected inspectExec() to fail")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
		}
	})
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

func TestMiddlewareInjectsVisibilityLabelsIntoExpandedLists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gotPaths []string

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	}))

	targets := []string{
		"/v1.53/services",
		"/v1.53/tasks",
		"/v1.53/secrets",
		"/v1.53/configs",
		"/v1.53/nodes",
	}
	for _, target := range targets {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status for %s = %d, want %d", target, rec.Code, http.StatusNoContent)
		}
	}

	if len(gotPaths) != len(targets) {
		t.Fatalf("got %d forwarded requests, want %d", len(gotPaths), len(targets))
	}
	for _, got := range gotPaths[:4] {
		if !strings.Contains(got, "com.sockguard.visible%3Dtrue") {
			t.Fatalf("query = %q, want label visibility filter", got)
		}
	}
	if !strings.Contains(gotPaths[4], "node.label") || !strings.Contains(gotPaths[4], "com.sockguard.visible%3Dtrue") {
		t.Fatalf("node list query = %q, want node.label visibility filter", gotPaths[4])
	}
}

func TestMiddlewareReturnsNotFoundForInvisibleExpandedReadTargets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name       string
		target     string
		kind       resourceKind
		identifier string
	}{
		{name: "service inspect", target: "/v1.53/services/web", kind: resourceKindService, identifier: "web"},
		{name: "service logs", target: "/v1.53/services/web/logs", kind: resourceKindService, identifier: "web"},
		{name: "task inspect", target: "/v1.53/tasks/task-1", kind: resourceKindTask, identifier: "task-1"},
		{name: "task logs", target: "/v1.53/tasks/task-1/logs", kind: resourceKindTask, identifier: "task-1"},
		{name: "secret inspect", target: "/v1.53/secrets/sec-1", kind: resourceKindSecret, identifier: "sec-1"},
		{name: "config inspect", target: "/v1.53/configs/cfg-1", kind: resourceKindConfig, identifier: "cfg-1"},
		{name: "node inspect", target: "/v1.53/nodes/node-1", kind: resourceKindNode, identifier: "node-1"},
		{name: "swarm inspect", target: "/v1.53/swarm", kind: resourceKindSwarm, identifier: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			var gotKind resourceKind
			var gotIdentifier string

			handler := middlewareWithDeps(logger, Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind resourceKind, identifier string) (map[string]string, bool, error) {
					gotKind = kind
					gotIdentifier = identifier
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if nextCalled {
				t.Fatal("expected hidden read target to be short-circuited")
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
			}
			if gotKind != tt.kind || gotIdentifier != tt.identifier {
				t.Fatalf("inspectResource kind/id = %s/%s, want %s/%s", gotKind, gotIdentifier, tt.kind, tt.identifier)
			}
		})
	}
}
