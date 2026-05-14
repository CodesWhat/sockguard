package visibility

import (
	"context"
	"encoding/json"
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

	"github.com/codeswhat/sockguard/internal/dockerresource"
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
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
			if kind != dockerresource.KindContainer || identifier != "container-123" {
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
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
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

		_, _, err := newTimeoutInspector().inspectResource(ctx, dockerresource.KindContainer, "abc123")
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
	labels, found, err := ins.inspectResource(context.Background(), dockerresource.KindContainer, "missing")
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
	_, _, err := ins.inspectResource(context.Background(), dockerresource.KindContainer, "abc")
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
	labels, found, err := ins.inspectResource(context.Background(), dockerresource.KindContainer, "abc")
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
		name  string
		kind  dockerresource.Kind
		body  string
		wantK string
		wantV string
	}{
		{
			name:  "container",
			kind:  dockerresource.KindContainer,
			body:  `{"Config":{"Labels":{"env":"prod"}}}`,
			wantK: "env", wantV: "prod",
		},
		{
			name:  "image config labels",
			kind:  dockerresource.KindImage,
			body:  `{"Config":{"Labels":{"tier":"web"}},"ContainerConfig":{"Labels":{}}}`,
			wantK: "tier", wantV: "web",
		},
		{
			name:  "image fallback to ContainerConfig",
			kind:  dockerresource.KindImage,
			body:  `{"Config":{"Labels":{}},"ContainerConfig":{"Labels":{"tier":"db"}}}`,
			wantK: "tier", wantV: "db",
		},
		{
			name:  "network",
			kind:  dockerresource.KindNetwork,
			body:  `{"Labels":{"net":"overlay"}}`,
			wantK: "net", wantV: "overlay",
		},
		{
			name:  "volume",
			kind:  dockerresource.KindVolume,
			body:  `{"Labels":{"vol":"data"}}`,
			wantK: "vol", wantV: "data",
		},
		{
			name:  "service",
			kind:  dockerresource.KindService,
			body:  `{"Spec":{"Labels":{"svc":"api"}}}`,
			wantK: "svc", wantV: "api",
		},
		{
			name:  "secret",
			kind:  dockerresource.KindSecret,
			body:  `{"Spec":{"Labels":{"sec":"key"}}}`,
			wantK: "sec", wantV: "key",
		},
		{
			name:  "config",
			kind:  dockerresource.KindConfig,
			body:  `{"Spec":{"Labels":{"cfg":"app"}}}`,
			wantK: "cfg", wantV: "app",
		},
		{
			name:  "node",
			kind:  dockerresource.KindNode,
			body:  `{"Spec":{"Labels":{"role":"worker"}}}`,
			wantK: "role", wantV: "worker",
		},
		{
			name:  "swarm",
			kind:  dockerresource.KindSwarm,
			body:  `{"Spec":{"Labels":{"cluster":"prod"}}}`,
			wantK: "cluster", wantV: "prod",
		},
		{
			name:  "task with top-level labels",
			kind:  dockerresource.KindTask,
			body:  `{"Labels":{"t":"1"},"Spec":{"ContainerSpec":{"Labels":{"t":"2"}}}}`,
			wantK: "t", wantV: "1",
		},
		{
			name:  "task fallback to ContainerSpec",
			kind:  dockerresource.KindTask,
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
	kinds := []dockerresource.Kind{
		dockerresource.KindContainer,
		dockerresource.KindImage,
		dockerresource.KindNetwork,
		dockerresource.KindVolume,
		dockerresource.KindService,
		dockerresource.KindSecret,
		dockerresource.KindConfig,
		dockerresource.KindNode,
		dockerresource.KindSwarm,
		dockerresource.KindTask,
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindSwarm {
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
		kind dockerresource.Kind
		body string
	}{
		{dockerresource.KindImage, `{"Config":{"Labels":{"env":"staging"}}}`},
		{dockerresource.KindNetwork, `{"Labels":{"net":"bridge"}}`},
		{dockerresource.KindVolume, `{"Labels":{"vol":"data"}}`},
		{dockerresource.KindService, `{"Spec":{"Labels":{"svc":"api"}}}`},
		{dockerresource.KindTask, `{"Labels":{"t":"1"},"Spec":{"ContainerSpec":{"Labels":{}}}}`},
		{dockerresource.KindSecret, `{"Spec":{"Labels":{"sec":"key"}}}`},
		{dockerresource.KindConfig, `{"Spec":{"Labels":{"cfg":"app"}}}`},
		{dockerresource.KindNode, `{"Spec":{"Labels":{"role":"worker"}}}`},
		{dockerresource.KindSwarm, `{"Spec":{"Labels":{"cluster":"prod"}}}`},
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
	_, _, err := ins.inspectResource(context.Background(), dockerresource.KindContainer, "abc")
	if err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

func TestInspectResourceNilContextError(t *testing.T) {
	ins := upstreamInspector{client: &http.Client{}}
	//nolint:staticcheck // SA1012: intentionally passing nil context to exercise the error path
	_, _, err := ins.inspectResource(nil, dockerresource.KindContainer, "abc") //nolint:staticcheck
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindImage || id != "sha256:abc" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindNetwork || id != "net-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, _ string) (map[string]string, bool, error) {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindService || id != "web" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindTask || id != "task-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindTask || id != "task-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindSecret || id != "sec-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindConfig || id != "cfg-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindNode || id != "node-1" {
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
		inspectResource: func(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
			if kind != dockerresource.KindService || id != "web" {
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
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
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
		kind       dockerresource.Kind
		identifier string
	}{
		{name: "service inspect", target: "/v1.53/services/web", kind: dockerresource.KindService, identifier: "web"},
		{name: "service logs", target: "/v1.53/services/web/logs", kind: dockerresource.KindService, identifier: "web"},
		{name: "task inspect", target: "/v1.53/tasks/task-1", kind: dockerresource.KindTask, identifier: "task-1"},
		{name: "task logs", target: "/v1.53/tasks/task-1/logs", kind: dockerresource.KindTask, identifier: "task-1"},
		{name: "secret inspect", target: "/v1.53/secrets/sec-1", kind: dockerresource.KindSecret, identifier: "sec-1"},
		{name: "config inspect", target: "/v1.53/configs/cfg-1", kind: dockerresource.KindConfig, identifier: "cfg-1"},
		{name: "node inspect", target: "/v1.53/nodes/node-1", kind: dockerresource.KindNode, identifier: "node-1"},
		{name: "swarm inspect", target: "/v1.53/swarm", kind: dockerresource.KindSwarm, identifier: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			var gotKind dockerresource.Kind
			var gotIdentifier string

			handler := middlewareWithDeps(logger, Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
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

// ---- name_patterns and image_patterns: container list filtering ----

// containerListHandler builds a handler that returns a JSON array of Docker-style
// container list items, each with Names and Image fields.
func containerListHandler(items []map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	}
}

// imageListHandler returns a JSON array of Docker-style image list items.
func imageListHandler(items []map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	}
}

func TestNamePatternHidesContainerFromList(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Upstream returns two containers; only "traefik" should match the pattern.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containerListHandler([]map[string]any{
			{"Names": []string{"/traefik"}, "Image": "traefik:latest"},
			{"Names": []string{"/portainer"}, "Image": "portainer/portainer:latest"},
		}).ServeHTTP(w, r)
	})

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d containers, want 1; items = %v", len(got), got)
	}
	names, _ := got[0]["Names"].([]any)
	if len(names) == 0 || names[0] != "/traefik" {
		t.Fatalf("unexpected container: %v", got[0])
	}
}

func TestImagePatternHidesContainerFromList(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containerListHandler([]map[string]any{
			{"Names": []string{"/traefik"}, "Image": "traefik:latest"},
			{"Names": []string{"/redis"}, "Image": "redis:7"},
		}).ServeHTTP(w, r)
	})

	handler := middlewareWithDeps(logger, Options{
		ImagePatterns: []string{"redis:*"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d containers, want 1; items = %v", len(got), got)
	}
	if got[0]["Image"] != "redis:7" {
		t.Fatalf("unexpected container image: %v", got[0]["Image"])
	}
}

func TestNameAndLabelANDSemanticsContainerList(t *testing.T) {
	// Both name pattern AND label selector must pass.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Two containers both named "traefik" but one has the wrong label.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Label filter is injected into the query; we serve all items and let the
		// pattern filter handle the name axis.
		containerListHandler([]map[string]any{
			{"Names": []string{"/traefik"}, "Image": "traefik:latest"},
			{"Names": []string{"/portainer"}, "Image": "portainer/portainer:latest"},
		}).ServeHTTP(w, r)
	})

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.example.team=platform"},
		NamePatterns:          []string{"traefik"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Label filter is injected into the upstream query.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Pattern axis filtered to only traefik from the upstream response.
	if len(got) != 1 {
		t.Fatalf("got %d containers, want 1; items = %v", len(got), got)
	}
	names, _ := got[0]["Names"].([]any)
	if len(names) == 0 || names[0] != "/traefik" {
		t.Fatalf("unexpected container: %v", got[0])
	}
}

func TestEmptyPatternsPassthroughContainerList(t *testing.T) {
	// No patterns configured → all containers pass through.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containerListHandler([]map[string]any{
			{"Names": []string{"/traefik"}, "Image": "traefik:latest"},
			{"Names": []string{"/portainer"}, "Image": "portainer/portainer:latest"},
		}).ServeHTTP(w, r)
	})

	// No patterns set → middleware is a no-op.
	handler := middlewareWithDeps(logger, Options{}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d containers, want 2 (passthrough); items = %v", len(got), got)
	}
}

func TestInvalidPatternFailsFastAtConfigLoad(t *testing.T) {
	// An empty pattern string is invalid and causes compilePolicy to error, which
	// causes middlewareWithDeps to return a 500-only handler (no panic, no serve).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mw := middlewareWithDeps(logger, Options{
		NamePatterns: []string{""},
	}, visibilityDeps{})

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach next handler with invalid pattern")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d for invalid (empty) pattern", rec.Code, http.StatusInternalServerError)
	}
}

// ---- name_patterns and image_patterns: image list filtering ----

func TestNamePatternHidesImageFromList(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imageListHandler([]map[string]any{
			{"RepoTags": []string{"traefik:latest"}},
			{"RepoTags": []string{"redis:7"}},
		}).ServeHTTP(w, r)
	})

	// Short name "traefik" matched via imageShortName — "traefik:latest" → "traefik:latest".
	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik:*"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/images/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d images, want 1; items = %v", len(got), got)
	}
	tags, _ := got[0]["RepoTags"].([]any)
	if len(tags) == 0 || tags[0] != "traefik:latest" {
		t.Fatalf("unexpected image tags: %v", got[0])
	}
}

func TestImagePatternHidesImageFromList(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imageListHandler([]map[string]any{
			{"RepoTags": []string{"ghcr.io/org/traefik:v2"}},
			{"RepoTags": []string{"redis:7"}},
		}).ServeHTTP(w, r)
	})

	// Full-ref image pattern — only "ghcr.io/org/traefik:v2" should match.
	handler := middlewareWithDeps(logger, Options{
		ImagePatterns: []string{"ghcr.io/org/**"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/images/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d images, want 1; items = %v", len(got), got)
	}
}

// ---- name_patterns and image_patterns: container inspect ----

func TestNamePatternHidesContainerInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik"},
	}, visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			return &resourceMeta{names: []string{"/portainer"}, image: "portainer/portainer:latest"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("container with non-matching name should be hidden by name pattern")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestImagePatternHidesContainerInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		ImagePatterns: []string{"traefik:*"},
	}, visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			return &resourceMeta{names: []string{"/portainer"}, image: "portainer/portainer:latest"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("container with non-matching image should be hidden by image pattern")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestNamePatternAllowsContainerInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik"},
	}, visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			return &resourceMeta{names: []string{"/traefik"}, image: "traefik:latest"}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("container with matching name should be visible")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ---- name_patterns and image_patterns: image inspect ----

func TestNamePatternHidesImageInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik:*"},
	}, visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			return &resourceMeta{repoTags: []string{"redis:7"}}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/images/sha256:abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("image with non-matching name should be hidden by name pattern")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestImagePatternHidesImageInspect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false

	handler := middlewareWithDeps(logger, Options{
		ImagePatterns: []string{"ghcr.io/org/**"},
	}, visibilityDeps{
		inspectResourceMeta: func(_ context.Context, kind dockerresource.Kind, id string) (*resourceMeta, bool, error) {
			return &resourceMeta{repoTags: []string{"redis:7"}}, true, nil
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/images/sha256:abc/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("image with non-matching image pattern should be hidden")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---- inspectResourceMeta via httptest mock ----

func TestInspectResourceMetaContainerNotFound(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	meta, found, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "missing")
	if err != nil || found || meta != nil {
		t.Fatalf("err=%v found=%v meta=%v, want nil/false/nil", err, found, meta)
	}
}

func TestInspectResourceMetaContainerNon200(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "abc")
	if err == nil || !strings.Contains(err.Error(), "returned status") {
		t.Fatalf("err = %v, want 'returned status'", err)
	}
}

func TestInspectResourceMetaContainerDecodes(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Name":"/traefik","Image":"traefik:latest"}`)
	}))
	meta, found, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "abc")
	if err != nil || !found {
		t.Fatalf("err=%v found=%v", err, found)
	}
	if len(meta.names) == 0 || meta.names[0] != "/traefik" {
		t.Fatalf("names = %v, want [/traefik]", meta.names)
	}
	if meta.image != "traefik:latest" {
		t.Fatalf("image = %q, want traefik:latest", meta.image)
	}
}

func TestInspectResourceMetaImageDecodes(t *testing.T) {
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"RepoTags":["traefik:latest","traefik:v2"]}`)
	}))
	meta, found, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindImage, "sha256:abc")
	if err != nil || !found {
		t.Fatalf("err=%v found=%v", err, found)
	}
	if len(meta.repoTags) != 2 {
		t.Fatalf("repoTags = %v, want [traefik:latest traefik:v2]", meta.repoTags)
	}
}

func TestInspectResourceMetaUnsupportedKind(t *testing.T) {
	ins := upstreamInspector{client: &http.Client{}}
	_, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindNetwork, "net-1")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("err = %v, want unsupported resource kind", err)
	}
}

// ---- decodeResourceMeta ----

func TestDecodeResourceMetaContainerUsesNamesWhenPresent(t *testing.T) {
	body := strings.NewReader(`{"Name":"/single","Names":["/multi"],"Image":"img:tag"}`)
	meta, err := decodeResourceMeta(body, dockerresource.KindContainer)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// Names takes priority over Name when present.
	if len(meta.names) != 1 || meta.names[0] != "/multi" {
		t.Fatalf("names = %v, want [/multi]", meta.names)
	}
}

func TestDecodeResourceMetaContainerFallsBackToName(t *testing.T) {
	body := strings.NewReader(`{"Name":"/solo","Names":[],"Image":"img:tag"}`)
	meta, err := decodeResourceMeta(body, dockerresource.KindContainer)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(meta.names) != 1 || meta.names[0] != "/solo" {
		t.Fatalf("names = %v, want [/solo]", meta.names)
	}
}

func TestDecodeResourceMetaUnsupportedKind(t *testing.T) {
	_, err := decodeResourceMeta(strings.NewReader(`{}`), dockerresource.KindNetwork)
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("err = %v, want unsupported resource kind", err)
	}
}

func TestDecodeResourceMetaDecodeError(t *testing.T) {
	_, err := decodeResourceMeta(strings.NewReader(`not-json`), dockerresource.KindContainer)
	if err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

// ---- compilePatterns ----

func TestCompilePatternsEmptyGlob(t *testing.T) {
	_, err := compilePatterns([]string{""})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("err = %v, want 'must not be empty'", err)
	}
}

func TestCompilePatternsInvalidEmptyPattern(t *testing.T) {
	// The glob-to-regex converter escapes all special regex characters, so the
	// only way to produce an invalid pattern is an empty string.
	_, err := compilePatterns([]string{"valid", ""})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("err = %v, want 'must not be empty'", err)
	}
}

func TestCompilePatternsHappyPath(t *testing.T) {
	patterns, err := compilePatterns([]string{"traefik", "redis:*"})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(patterns) != 2 {
		t.Fatalf("len = %d, want 2", len(patterns))
	}
}

// ---- matchesAnyPattern ----

func TestMatchesAnyPatternEmptyPatternsAlwaysTrue(t *testing.T) {
	if !matchesAnyPattern("anything", nil) {
		t.Fatal("empty patterns should always return true")
	}
}

func TestMatchesAnyPatternNoMatch(t *testing.T) {
	patterns, _ := compilePatterns([]string{"traefik"})
	if matchesAnyPattern("portainer", patterns) {
		t.Fatal("portainer should not match traefik pattern")
	}
}

func TestMatchesAnyPatternMatch(t *testing.T) {
	patterns, _ := compilePatterns([]string{"redis:*"})
	if !matchesAnyPattern("redis:7", patterns) {
		t.Fatal("redis:7 should match redis:* pattern")
	}
}

// ---- containerNameFromNames and imageShortName ----

func TestContainerNameFromNamesEmpty(t *testing.T) {
	if got := containerNameFromNames(nil); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

func TestContainerNameFromNamesStripsLeadingSlash(t *testing.T) {
	if got := containerNameFromNames([]string{"/traefik"}); got != "traefik" {
		t.Fatalf("got %q, want traefik", got)
	}
}

func TestImageShortNameNoSlash(t *testing.T) {
	if got := imageShortName("traefik:latest"); got != "traefik:latest" {
		t.Fatalf("got %q, want traefik:latest", got)
	}
}

func TestImageShortNameWithRegistry(t *testing.T) {
	if got := imageShortName("ghcr.io/org/traefik:v2"); got != "traefik:v2" {
		t.Fatalf("got %q, want traefik:v2", got)
	}
}

func TestFilterWriterWriteHeaderCapturesCode(t *testing.T) {
	// Drive patternFilterWriter via a fake upstream that returns 404 with a
	// plain-text body. The middleware must record the status via WriteHeader,
	// then pass the 404 through the non-2xx flush path without attempting JSON
	// parsing or pattern filtering.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	const notFoundBody = "No such container"

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(notFoundBody))
	})

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (non-2xx must pass through with original status)", rec.Code, http.StatusNotFound)
	}
	if got := rec.Body.String(); got != notFoundBody {
		t.Fatalf("body = %q, want %q (non-2xx body must be forwarded unchanged)", got, notFoundBody)
	}
}

func TestFilterWriterFlushFilteredPassesThroughNon2xx(t *testing.T) {
	// Drive patternFilterWriter via a fake upstream that returns 500 with a
	// plain-text (non-JSON) error body. The middleware must forward the 500
	// status and body byte-for-byte without attempting to filter it.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	const errBody = "internal server error"

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(errBody))
	})

	handler := middlewareWithDeps(logger, Options{
		NamePatterns: []string{"traefik"},
	}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (non-2xx must pass through)", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Body.String(); got != errBody {
		t.Fatalf("body = %q, want %q (body must be forwarded byte-for-byte)", got, errBody)
	}
}
