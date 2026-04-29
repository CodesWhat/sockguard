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

	"github.com/codeswhat/sockguard/internal/logging"
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

// ---- middlewareWithDeps error paths ----

func TestMiddlewareWithDepsInvalidDefaultPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Empty string is an invalid selector.
	mw := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{""},
	}, visibilityDeps{})

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach next handler")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestMiddlewareWithDepsInvalidProfilePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"valid=ok"},
		Profiles: map[string]Policy{
			"bad": {VisibleResourceLabels: []string{"has,comma"}},
		},
	}, visibilityDeps{})

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach next handler")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestMiddlewarePassesThroughNonGetMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false
	mw := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"k=v"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/json", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !nextCalled {
		t.Fatal("POST should pass through without visibility checks")
	}
}

func TestMiddlewarePassesThroughWhenNoSelectors(t *testing.T) {
	// ResolveProfile returns empty string → no selectors → pass through.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false
	mw := middlewareWithDeps(logger, Options{
		Profiles: map[string]Policy{
			"empty": {VisibleResourceLabels: []string{}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "", false },
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !nextCalled {
		t.Fatal("empty selectors should pass through")
	}
}

func TestMiddlewareNoOpWhenBothDefaultAndProfilesEmpty(t *testing.T) {
	// Both VisibleResourceLabels empty and no Profiles → early-return no-op middleware.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false
	mw := middlewareWithDeps(logger, Options{}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/abc/json", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !nextCalled {
		t.Fatal("no-op middleware should pass through to next handler")
	}
}

// ---- parseSelector branches ----

func TestParseSelectorErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "must not be empty"},
		{"comma", "a,b", "must not contain commas"},
		{"missing key", "=value", "missing a label key"},
		{"missing value", "key=", "missing a label value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSelector(tt.input)
			if err == nil {
				t.Fatalf("parseSelector(%q) expected error", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseSelector(%q) error = %v, want substring %q", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseSelectorKeyOnly(t *testing.T) {
	sel, err := parseSelector("mykey")
	if err != nil {
		t.Fatalf("parseSelector(\"mykey\") error = %v", err)
	}
	if sel.key != "mykey" || sel.hasValue {
		t.Fatalf("selector = %+v, want key=mykey hasValue=false", sel)
	}
}

// ---- matchesSelectors branches ----

func TestMatchesSelectorsEmptySelectors(t *testing.T) {
	if !matchesSelectors(nil, nil) {
		t.Fatal("empty selectors should always match")
	}
}

func TestMatchesSelectorsEmptyLabels(t *testing.T) {
	sel := []compiledSelector{{key: "k", value: "v", hasValue: true}}
	if matchesSelectors(nil, sel) {
		t.Fatal("empty labels should not match non-empty selectors")
	}
	if matchesSelectors(map[string]string{}, sel) {
		t.Fatal("empty labels map should not match non-empty selectors")
	}
}

func TestMatchesSelectorsKeyMissing(t *testing.T) {
	labels := map[string]string{"other": "x"}
	sel := []compiledSelector{{key: "k", hasValue: false}}
	if matchesSelectors(labels, sel) {
		t.Fatal("should not match when selector key is absent from labels")
	}
}

func TestMatchesSelectorsValueMismatch(t *testing.T) {
	labels := map[string]string{"k": "wrong"}
	sel := []compiledSelector{{key: "k", value: "right", hasValue: true}}
	if matchesSelectors(labels, sel) {
		t.Fatal("should not match when label value differs from selector value")
	}
}

func TestMatchesSelectorsKeyPresentNoValueConstraint(t *testing.T) {
	labels := map[string]string{"k": "anything"}
	sel := []compiledSelector{{key: "k", hasValue: false}}
	if !matchesSelectors(labels, sel) {
		t.Fatal("key-only selector should match when key is present regardless of value")
	}
}

// ---- identifier helpers — uncovered branches ----

func TestImageInspectIdentifierBranches(t *testing.T) {
	// Wrong prefix
	if _, ok := imageInspectIdentifier("/containers/foo/json"); ok {
		t.Fatal("wrong prefix should not match")
	}
	// No trailing /json
	if _, ok := imageInspectIdentifier("/images/foo/notjson"); ok {
		t.Fatal("/images/id/notjson should not match")
	}
	// No slash at all (no Cut separator)
	if _, ok := imageInspectIdentifier("/images/justid"); ok {
		t.Fatal("/images/justid (no slash) should not match")
	}
	// Happy path
	if id, ok := imageInspectIdentifier("/images/sha256:abc/json"); !ok || id != "sha256:abc" {
		t.Fatalf("expected match with sha256:abc, got id=%q ok=%v", id, ok)
	}
}

func TestNetworkInspectIdentifierBranches(t *testing.T) {
	// Wrong prefix
	if _, ok := networkInspectIdentifier("/containers/net"); ok {
		t.Fatal("wrong prefix should not match")
	}
	// Empty rest
	if _, ok := networkInspectIdentifier("/networks/"); ok {
		t.Fatal("empty rest should not match")
	}
	// Contains slash (sub-path)
	if _, ok := networkInspectIdentifier("/networks/net/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	// Reserved word: create
	if _, ok := networkInspectIdentifier("/networks/create"); ok {
		t.Fatal("create should not match")
	}
	// Reserved word: prune
	if _, ok := networkInspectIdentifier("/networks/prune"); ok {
		t.Fatal("prune should not match")
	}
	// Happy path
	if id, ok := networkInspectIdentifier("/networks/net-abc"); !ok || id != "net-abc" {
		t.Fatalf("expected match net-abc, got id=%q ok=%v", id, ok)
	}
}

func TestVolumeInspectIdentifierBranches(t *testing.T) {
	// Wrong prefix
	if _, ok := volumeInspectIdentifier("/networks/vol"); ok {
		t.Fatal("wrong prefix should not match")
	}
	// Empty rest
	if _, ok := volumeInspectIdentifier("/volumes/"); ok {
		t.Fatal("empty rest should not match")
	}
	// Contains slash
	if _, ok := volumeInspectIdentifier("/volumes/vol/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	// Reserved word: create
	if _, ok := volumeInspectIdentifier("/volumes/create"); ok {
		t.Fatal("create should not match")
	}
	// Reserved word: prune
	if _, ok := volumeInspectIdentifier("/volumes/prune"); ok {
		t.Fatal("prune should not match")
	}
	// Happy path
	if id, ok := volumeInspectIdentifier("/volumes/vol-abc"); !ok || id != "vol-abc" {
		t.Fatalf("expected match vol-abc, got id=%q ok=%v", id, ok)
	}
}

func TestExecInspectIdentifierBranches(t *testing.T) {
	// Wrong prefix
	if _, ok := execInspectIdentifier("/containers/exec"); ok {
		t.Fatal("wrong prefix should not match")
	}
	// No trailing /json
	if _, ok := execInspectIdentifier("/exec/abc/start"); ok {
		t.Fatal("non-json tail should not match")
	}
	// Happy path
	if id, ok := execInspectIdentifier("/exec/exec-99/json"); !ok || id != "exec-99" {
		t.Fatalf("expected match exec-99, got id=%q ok=%v", id, ok)
	}
}

func TestSecretInspectIdentifierBranches(t *testing.T) {
	if _, ok := secretInspectIdentifier("/configs/sec"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := secretInspectIdentifier("/secrets/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := secretInspectIdentifier("/secrets/sec/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if _, ok := secretInspectIdentifier("/secrets/create"); ok {
		t.Fatal("create should not match")
	}
	if id, ok := secretInspectIdentifier("/secrets/sec-1"); !ok || id != "sec-1" {
		t.Fatalf("expected match sec-1, got id=%q ok=%v", id, ok)
	}
}

func TestConfigInspectIdentifierBranches(t *testing.T) {
	if _, ok := configInspectIdentifier("/secrets/cfg"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := configInspectIdentifier("/configs/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := configInspectIdentifier("/configs/cfg/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if _, ok := configInspectIdentifier("/configs/create"); ok {
		t.Fatal("create should not match")
	}
	if id, ok := configInspectIdentifier("/configs/cfg-1"); !ok || id != "cfg-1" {
		t.Fatalf("expected match cfg-1, got id=%q ok=%v", id, ok)
	}
}

func TestNodeInspectIdentifierBranches(t *testing.T) {
	if _, ok := nodeInspectIdentifier("/swarm/node"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := nodeInspectIdentifier("/nodes/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := nodeInspectIdentifier("/nodes/n/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if id, ok := nodeInspectIdentifier("/nodes/node-1"); !ok || id != "node-1" {
		t.Fatalf("expected match node-1, got id=%q ok=%v", id, ok)
	}
}

// ---- upstreamInspector.inspectResource via httptest mock ----

func newMockInspector(handler http.Handler) upstreamInspector {
	srv := httptest.NewServer(handler)
	return upstreamInspector{
		client: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				// Rewrite the URL so it hits the local test server.
				r2 := r.Clone(r.Context())
				r2.URL.Scheme = "http"
				r2.URL.Host = srv.Listener.Addr().String()
				return srv.Client().Transport.RoundTrip(r2)
			}),
		},
	}
}

func TestInspectResourceNotFound(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	labels, found, err := ins.inspectResource(context.Background(), resourceKindContainer, "missing")
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if found {
		t.Fatal("found = true, want false for 404")
	}
	if labels != nil {
		t.Fatalf("labels = %v, want nil", labels)
	}
}

func TestInspectResourceNon200Error(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, _, err := ins.inspectResource(context.Background(), resourceKindContainer, "abc")
	if err == nil {
		t.Fatal("expected error for non-200 non-404 status")
	}
	if !strings.Contains(err.Error(), "returned status") {
		t.Fatalf("error = %v, want 'returned status'", err)
	}
}

func TestInspectResourceUnsupportedKind(t *testing.T) {
	ins := upstreamInspector{client: &http.Client{}}
	_, _, err := ins.inspectResource(context.Background(), "bogus", "id")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("error = %v, want unsupported resource kind", err)
	}
}

func TestInspectResourceDecodesContainerLabels(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Config":{"Labels":{"com.example.env":"prod"}}}`)
	}))
	labels, found, err := ins.inspectResource(context.Background(), resourceKindContainer, "abc")
	if err != nil || !found {
		t.Fatalf("err=%v found=%v", err, found)
	}
	if labels["com.example.env"] != "prod" {
		t.Fatalf("labels = %v, want com.example.env=prod", labels)
	}
}

// ---- upstreamInspector.inspectExec via httptest mock ----

func TestInspectExecNotFound(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	id, found, err := ins.inspectExec(context.Background(), "exec-1")
	if err != nil || found || id != "" {
		t.Fatalf("err=%v found=%v id=%q, want nil/false/empty", err, found, id)
	}
}

func TestInspectExecNon200Error(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	_, _, err := ins.inspectExec(context.Background(), "exec-1")
	if err == nil {
		t.Fatal("expected error for non-200 non-404 status")
	}
	if !strings.Contains(err.Error(), "returned status") {
		t.Fatalf("error = %v, want 'returned status'", err)
	}
}

func TestInspectExecEmptyContainerID(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ContainerID":""}`)
	}))
	id, found, err := ins.inspectExec(context.Background(), "exec-1")
	if err != nil || found || id != "" {
		t.Fatalf("err=%v found=%v id=%q, want nil/false/empty for empty ContainerID", err, found, id)
	}
}

func TestInspectExecReturnsContainerID(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ContainerID":"container-xyz"}`)
	}))
	id, found, err := ins.inspectExec(context.Background(), "exec-1")
	if err != nil || !found || id != "container-xyz" {
		t.Fatalf("err=%v found=%v id=%q, want nil/true/container-xyz", err, found, id)
	}
}

// ---- decodeResourceLabels — all resource kinds ----

func TestDecodeResourceLabelsAllKinds(t *testing.T) {
	tests := []struct {
		name   string
		kind   resourceKind
		body   string
		wantK  string
		wantV  string
	}{
		{
			name:  "container",
			kind:  resourceKindContainer,
			body:  `{"Config":{"Labels":{"env":"prod"}}}`,
			wantK: "env", wantV: "prod",
		},
		{
			name:  "image config labels",
			kind:  resourceKindImage,
			body:  `{"Config":{"Labels":{"tier":"web"}},"ContainerConfig":{"Labels":{}}}`,
			wantK: "tier", wantV: "web",
		},
		{
			name:  "image fallback to ContainerConfig",
			kind:  resourceKindImage,
			body:  `{"Config":{"Labels":{}},"ContainerConfig":{"Labels":{"tier":"db"}}}`,
			wantK: "tier", wantV: "db",
		},
		{
			name:  "network",
			kind:  resourceKindNetwork,
			body:  `{"Labels":{"net":"overlay"}}`,
			wantK: "net", wantV: "overlay",
		},
		{
			name:  "volume",
			kind:  resourceKindVolume,
			body:  `{"Labels":{"vol":"data"}}`,
			wantK: "vol", wantV: "data",
		},
		{
			name:  "service",
			kind:  resourceKindService,
			body:  `{"Spec":{"Labels":{"svc":"api"}}}`,
			wantK: "svc", wantV: "api",
		},
		{
			name:  "secret",
			kind:  resourceKindSecret,
			body:  `{"Spec":{"Labels":{"sec":"key"}}}`,
			wantK: "sec", wantV: "key",
		},
		{
			name:  "config",
			kind:  resourceKindConfig,
			body:  `{"Spec":{"Labels":{"cfg":"app"}}}`,
			wantK: "cfg", wantV: "app",
		},
		{
			name:  "node",
			kind:  resourceKindNode,
			body:  `{"Spec":{"Labels":{"role":"worker"}}}`,
			wantK: "role", wantV: "worker",
		},
		{
			name:  "swarm",
			kind:  resourceKindSwarm,
			body:  `{"Spec":{"Labels":{"cluster":"prod"}}}`,
			wantK: "cluster", wantV: "prod",
		},
		{
			name:  "task with top-level labels",
			kind:  resourceKindTask,
			body:  `{"Labels":{"t":"1"},"Spec":{"ContainerSpec":{"Labels":{"t":"2"}}}}`,
			wantK: "t", wantV: "1",
		},
		{
			name:  "task fallback to ContainerSpec",
			kind:  resourceKindTask,
			body:  `{"Labels":{},"Spec":{"ContainerSpec":{"Labels":{"t":"2"}}}}`,
			wantK: "t", wantV: "2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, err := decodeResourceLabels(strings.NewReader(tt.body), tt.kind)
			if err != nil {
				t.Fatalf("decodeResourceLabels error = %v", err)
			}
			if labels[tt.wantK] != tt.wantV {
				t.Fatalf("labels[%q] = %q, want %q", tt.wantK, labels[tt.wantK], tt.wantV)
			}
		})
	}
}

func TestDecodeResourceLabelsUnsupportedKind(t *testing.T) {
	_, err := decodeResourceLabels(strings.NewReader(`{}`), "bogus")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("error = %v, want unsupported resource kind", err)
	}
}

func TestDecodeResourceLabelsDecodeErrors(t *testing.T) {
	// Exercise the decode-error branch for every resource kind.
	kinds := []resourceKind{
		resourceKindContainer,
		resourceKindImage,
		resourceKindNetwork,
		resourceKindVolume,
		resourceKindService,
		resourceKindSecret,
		resourceKindConfig,
		resourceKindNode,
		resourceKindSwarm,
		resourceKindTask,
	}
	for _, kind := range kinds {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			_, err := decodeResourceLabels(strings.NewReader(`not-json`), kind)
			if err == nil {
				t.Fatalf("decodeResourceLabels(bad JSON, %s) expected decode error", kind)
			}
		})
	}
}

// ---- requestVisible — swarm path ----

func TestRequestVisibleSwarmInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "cluster", value: "prod", hasValue: true}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindSwarm {
				t.Fatalf("unexpected kind=%s", kind)
			}
			return map[string]string{"cluster": "prod"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/swarm", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

// ---- requestVisible exec path: exec not found → pass through ----

func TestRequestVisibleExecNotFound(t *testing.T) {
	selectors := []compiledSelector{{key: "k", value: "v", hasValue: true}}
	deps := visibilityDeps{
		inspectExec: func(context.Context, string) (string, bool, error) {
			return "", false, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/exec/exec-1/json", selectors, deps)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !visible {
		t.Fatal("exec not found should be treated as visible (pass-through)")
	}
}

// ---- requestVisible exec path: exec inspect error ----

func TestRequestVisibleExecInspectError(t *testing.T) {
	selectors := []compiledSelector{{key: "k", value: "v", hasValue: true}}
	wantErr := errors.New("exec error")
	deps := visibilityDeps{
		inspectExec: func(context.Context, string) (string, bool, error) {
			return "", false, wantErr
		},
	}
	_, err := requestVisible(context.Background(), "/exec/exec-1/json", selectors, deps)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

// ---- normalizedPathForRequest ----

func TestNormalizedPathForRequestNoMeta(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	rec := httptest.NewRecorder()
	got := normalizedPathForRequest(rec, req)
	if got != "/containers/json" {
		t.Fatalf("normalizedPathForRequest = %q, want /containers/json", got)
	}
}

func TestNormalizedPathForRequestUsesMetaNormPath(t *testing.T) {
	// Inject a RequestMeta via context so MetaForRequest returns it with NormPath set.
	meta := &logging.RequestMeta{NormPath: "/containers/abc/json"}
	ctx := logging.WithMeta(context.Background(), meta)
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/abc/json", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	got := normalizedPathForRequest(rec, req)
	if got != "/containers/abc/json" {
		t.Fatalf("normalizedPathForRequest with meta = %q, want /containers/abc/json", got)
	}
}

// ---- serviceInspectIdentifier missing branches ----

func TestServiceInspectIdentifierBranches(t *testing.T) {
	if _, ok := serviceInspectIdentifier("/nodes/svc"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := serviceInspectIdentifier("/services/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := serviceInspectIdentifier("/services/svc/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if _, ok := serviceInspectIdentifier("/services/create"); ok {
		t.Fatal("create should not match")
	}
	if id, ok := serviceInspectIdentifier("/services/svc-1"); !ok || id != "svc-1" {
		t.Fatalf("expected match svc-1, got id=%q ok=%v", id, ok)
	}
}

// ---- inspectResource — all resource kinds ----

func TestInspectResourceAllKinds(t *testing.T) {
	tests := []struct {
		kind resourceKind
		body string
	}{
		{resourceKindImage, `{"Config":{"Labels":{"env":"staging"}}}`},
		{resourceKindNetwork, `{"Labels":{"net":"bridge"}}`},
		{resourceKindVolume, `{"Labels":{"vol":"data"}}`},
		{resourceKindService, `{"Spec":{"Labels":{"svc":"api"}}}`},
		{resourceKindTask, `{"Labels":{"t":"1"},"Spec":{"ContainerSpec":{"Labels":{}}}}`},
		{resourceKindSecret, `{"Spec":{"Labels":{"sec":"key"}}}`},
		{resourceKindConfig, `{"Spec":{"Labels":{"cfg":"app"}}}`},
		{resourceKindNode, `{"Spec":{"Labels":{"role":"worker"}}}`},
		{resourceKindSwarm, `{"Spec":{"Labels":{"cluster":"prod"}}}`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(string(tt.kind), func(t *testing.T) {
			ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tt.body)
			}))
			labels, found, err := ins.inspectResource(context.Background(), tt.kind, "id-1")
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !found {
				t.Fatal("found = false, want true")
			}
			if len(labels) == 0 {
				t.Fatal("expected non-empty labels")
			}
		})
	}
}

func TestInspectResourceDecodeError(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `not-valid-json`)
	}))
	_, _, err := ins.inspectResource(context.Background(), resourceKindContainer, "abc")
	if err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

func TestInspectResourceNilContextError(t *testing.T) {
	ins := upstreamInspector{client: &http.Client{}}
	//nolint:staticcheck // SA1012: intentionally passing nil context to exercise the error path
	_, _, err := ins.inspectResource(nil, resourceKindContainer, "abc") //nolint:staticcheck
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestInspectExecNilContextError(t *testing.T) {
	ins := upstreamInspector{client: &http.Client{}}
	//nolint:staticcheck // SA1012: intentionally passing nil context to exercise the error path
	_, _, err := ins.inspectExec(nil, "exec-1") //nolint:staticcheck
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

// ---- inspectExec decode error ----

func TestInspectExecDecodeError(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `not-valid-json`)
	}))
	_, _, err := ins.inspectExec(context.Background(), "exec-1")
	if err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

// ---- requestVisible — remaining resource type paths ----

func TestRequestVisibleImageInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "env", value: "prod", hasValue: true}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindImage || id != "sha256:abc" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"env": "prod"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/images/sha256:abc/json", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleNetworkInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "net", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindNetwork || id != "net-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"net": "overlay"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/networks/net-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleVolumeInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "vol", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, _ string) (map[string]string, bool, error) {
			return map[string]string{"vol": "data"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/volumes/vol-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleUnknownPathPassesThrough(t *testing.T) {
	selectors := []compiledSelector{{key: "k", hasValue: false}}
	visible, err := requestVisible(context.Background(), "/ping", selectors, visibilityDeps{})
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true for unknown path", err, visible)
	}
}

func TestRequestVisibleServiceLogs(t *testing.T) {
	selectors := []compiledSelector{{key: "svc", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindService || id != "web" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"svc": "api"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/services/web/logs", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleTaskInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "t", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindTask || id != "task-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"t": "1"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/tasks/task-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleTaskLogs(t *testing.T) {
	selectors := []compiledSelector{{key: "t", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindTask || id != "task-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"t": "1"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/tasks/task-1/logs", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleSecretInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "sec", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindSecret || id != "sec-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"sec": "key"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/secrets/sec-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleConfigInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "cfg", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindConfig || id != "cfg-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"cfg": "app"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/configs/cfg-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleNodeInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "role", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindNode || id != "node-1" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"role": "worker"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/nodes/node-1", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleServiceInspect(t *testing.T) {
	selectors := []compiledSelector{{key: "svc", hasValue: false}}
	deps := visibilityDeps{
		inspectResource: func(_ context.Context, kind resourceKind, id string) (map[string]string, bool, error) {
			if kind != resourceKindService || id != "web" {
				t.Fatalf("unexpected kind=%s id=%s", kind, id)
			}
			return map[string]string{"svc": "api"}, true, nil
		},
	}
	visible, err := requestVisible(context.Background(), "/services/web", selectors, deps)
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true", err, visible)
	}
}

func TestRequestVisibleEmptySelectors(t *testing.T) {
	visible, err := requestVisible(context.Background(), "/containers/abc/json", nil, visibilityDeps{})
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true for empty selectors", err, visible)
	}
}

// ---- middlewareWithDeps — missing branch: profile resolution returns ok=false ----

func TestMiddlewareProfileResolveReturnsFalse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false
	// ResolveProfile returns ok=false → selectors stay as default → selectors non-empty
	// → request is checked normally.
	mw := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"k=v"},
		ResolveProfile:        func(*http.Request) (string, bool) { return "", false },
	}, visibilityDeps{
		inspectResource: func(context.Context, resourceKind, string) (map[string]string, bool, error) {
			return map[string]string{"k": "v"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/abc/json", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !nextCalled {
		t.Fatal("matching labels should reach next handler")
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

func TestAddVisibilityLabelFiltersLeavesQueryUntouchedWhenSelectorsAlreadyPresent(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		`/v1.53/containers/json?all=1&filters={"label":["com.sockguard.visible=true","com.sockguard.client=watchtower"]}`,
		nil,
	)
	originalRawQuery := req.URL.RawQuery

	err := addVisibilityLabelFilters(req, "/containers/json", []compiledSelector{
		{key: "com.sockguard.visible", value: "true", hasValue: true},
		{key: "com.sockguard.client", value: "watchtower", hasValue: true},
	})
	if err != nil {
		t.Fatalf("addVisibilityLabelFilters() error = %v, want nil", err)
	}
	if req.URL.RawQuery != originalRawQuery {
		t.Fatalf("RawQuery = %q, want unchanged %q", req.URL.RawQuery, originalRawQuery)
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
