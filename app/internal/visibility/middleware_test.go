package visibility

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// warnCapturingLogger returns a *slog.Logger backed by a bytes.Buffer of
// slog's text output, so tests can assert on which Warn calls fired (and with
// which attributes) without depending on internal logging package plumbing.
func warnCapturingLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

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
	t.Parallel()
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

func TestPatternsWithoutSelectorsWarningNamesEveryFilteredListPath(t *testing.T) {
	t.Parallel()

	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	middlewareWithDeps(logger, Options{
		NamePatterns: []string{"allowed-*"},
	}, visibilityDeps{})

	for _, path := range []string{
		"/containers/json",
		"/libpod/containers/json",
		"/images/json",
		"/libpod/images/json",
	} {
		if !strings.Contains(logs.String(), path) {
			t.Errorf("startup warning = %q, want filtered list path %q", logs.String(), path)
		}
	}
}

func TestMiddlewareReturnsNotFoundForInvisibleContainerInspect(t *testing.T) {
	t.Parallel()
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

// TestMiddlewareHidesContainerReadSubresources asserts that read endpoints
// beyond /json (logs, stats, top, changes, export, archive, attach/ws) are
// gated by visibility too — otherwise a hidden container leaks data through
// them. Each must 404 without reaching upstream.
func TestMiddlewareHidesContainerReadSubresources(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/v1.53/containers/abc123/logs?stdout=1",
		"/v1.53/containers/abc123/stats?stream=0",
		"/v1.53/containers/abc123/top",
		"/v1.53/containers/abc123/changes",
		"/v1.53/containers/abc123/export",
		"/v1.53/containers/abc123/archive?path=/etc",
		"/v1.53/containers/abc123/attach/ws",
	} {
		t.Run(path, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			nextCalled := false
			handler := middlewareWithDeps(logger, Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if nextCalled {
				t.Fatalf("%s: hidden container sub-resource reached upstream", path)
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: status = %d, want 404; body: %s", path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestMiddlewareProtectsImageReadSubresources is the image-side counterpart.
// Ordinary hidden-image reads return 404. Docker-compatible exports are
// refused before lookup because their platform effects cannot be enumerated.
func TestMiddlewareProtectsImageReadSubresources(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path       string
		wantStatus int
	}{
		{path: "/v1.53/images/secretimg/history", wantStatus: http.StatusNotFound},
		{path: "/v1.53/images/secretimg/get", wantStatus: http.StatusForbidden},
		{path: "/v1.53/images/registry.io/team/app/get", wantStatus: http.StatusForbidden},
		{path: "/v1.53/images/secretimg/attestations", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			nextCalled := false
			handler := middlewareWithDeps(logger, Options{
				VisibleResourceLabels: []string{"com.sockguard.visible=true"},
			}, visibilityDeps{
				inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					return map[string]string{"com.sockguard.visible": "false"}, true, nil
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if nextCalled {
				t.Fatalf("%s: hidden image sub-resource reached upstream", tt.path)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("%s: status = %d, want %d; body: %s", tt.path, rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestMiddlewareRolloutModePassesInvisibleInspectThrough asserts that in warn /
// audit rollout mode an invisible single-resource inspect is forwarded to the
// upstream with a would_deny verdict, instead of being hard-404'd — consistent
// with every other deny gate.
func TestMiddlewareRolloutModePassesInvisibleInspectThrough(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"warn", "audit"} {
		t.Run("mode="+mode, func(t *testing.T) {
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

			meta := &logging.RequestMeta{RolloutMode: mode}
			req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/abc123/json", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !nextCalled {
				t.Fatalf("expected invisible inspect to pass through under mode=%s", mode)
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (inner write) under mode=%s", rec.Code, mode)
			}
			if meta.Decision != logging.DecisionWouldDeny {
				t.Fatalf("meta.Decision = %q, want would_deny", meta.Decision)
			}
			if meta.ReasonCode != reasonCodeVisibilityPolicyHidResource {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyHidResource)
			}
		})
	}
}

func TestMiddlewareAllowsVisibleExecInspectViaContainerLabels(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestMiddlewareEmptyEffectivePolicySkipsFilterInjection is the boundary
// regression for hasSelectors := len(effectivePolicy.selectors) > 0: when the
// resolved policy has zero selectors, hasSelectors must be false so the
// middleware takes the "nothing configured" fast path and never calls
// addVisibilityLabelFilters. A `>=` in place of `>` would make hasSelectors
// true for a genuinely empty selector slice (0 >= 0), driving the request
// into addVisibilityLabelFilters anyway — observable here because that
// function decodes the existing `filters` query parameter, and a malformed
// one would then produce a 400 instead of passing straight through.
func TestMiddlewareEmptyEffectivePolicySkipsFilterInjection(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nextCalled := false
	mw := middlewareWithDeps(logger, Options{
		// A non-empty Profiles map keeps compileVisibilityPolicies from
		// installing the fully-empty pass-through middleware, while
		// ResolveProfile falling back to the (empty) default policy for this
		// request makes effectivePolicy.selectors genuinely empty.
		Profiles: map[string]Policy{
			"restricted": {VisibleResourceLabels: []string{"env=prod"}},
		},
		ResolveProfile: func(*http.Request) (string, bool) { return "", false },
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json?filters=not-json", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("empty effective policy should pass straight through, even with a malformed filters query")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareNoOpWhenBothDefaultAndProfilesEmpty(t *testing.T) {
	t.Parallel()
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

// TestWarnPatternsWithoutSelectorsNilLoggerNeverWarns is the negation
// regression for `logger == nil` in warnPatternsWithoutSelectors: with a nil
// logger there is nothing to warn to, so the guard must return before
// reaching logger.Warn. A `!=` in place of `==` would skip the early return
// for a genuinely nil logger and call Warn on it, a nil pointer panic.
func TestWarnPatternsWithoutSelectorsNilLoggerNeverWarns(t *testing.T) {
	t.Parallel()
	// Must not panic.
	_ = middlewareWithDeps(nil, Options{NamePatterns: []string{"prod-*"}}, visibilityDeps{})
}

// TestWarnPatternsWithoutSelectorsWarnsWhenPatternsHaveNoSelector is the
// boundary regression for `len(policy.selectors) > 0` in
// warnPatternsWithoutSelectors: a patterns-only default policy (zero
// selectors) must log the warning. A `>=` in place of `>` makes that clause
// true for a genuinely empty selector slice (0 >= 0), short-circuiting the
// whole OR to true and skipping the warning unconditionally.
func TestWarnPatternsWithoutSelectorsWarnsWhenPatternsHaveNoSelector(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()

	_ = middlewareWithDeps(logger, Options{NamePatterns: []string{"prod-*"}}, visibilityDeps{})

	if !strings.Contains(buf.String(), "visibility name/image patterns are set without any visible_resource_labels selector") {
		t.Fatalf("log output = %q, want the patterns-without-selector warning", buf.String())
	}
}

// TestWarnPatternsWithoutSelectorsSilentWhenSelectorPresent is the negation
// regression for the same `len(policy.selectors) > 0` clause: a policy that
// pairs patterns with a label selector must NOT warn. A `<=` in place of `>`
// flips this clause to true only when selectors are empty, so a genuinely
// non-empty selector slice makes the whole OR false and the warning fires
// anyway.
func TestWarnPatternsWithoutSelectorsSilentWhenSelectorPresent(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()

	_ = middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"env=prod"},
		NamePatterns:          []string{"prod-*"},
	}, visibilityDeps{})

	if strings.Contains(buf.String(), "visibility name/image patterns are set without any visible_resource_labels selector") {
		t.Fatalf("log output = %q, want no patterns-without-selector warning when a selector is configured", buf.String())
	}
}

// TestDefaultWarnedSuppressesRepeatedProfileWarning is the negation
// regression for `len(defaultPolicy.selectors) == 0` inside defaultWarned:
// when the default policy already triggered the patterns-without-selector
// warning, every profile that inherits the same empty-selector patterns must
// NOT warn again. A `!=` in place of `==` computes defaultWarned as false in
// exactly this case, so the per-profile warning fires a second time.
func TestDefaultWarnedSuppressesRepeatedProfileWarning(t *testing.T) {
	t.Parallel()
	logger, buf := warnCapturingLogger()

	_ = middlewareWithDeps(logger, Options{
		NamePatterns: []string{"prod-*"},
		Profiles: map[string]Policy{
			"restricted": {},
		},
	}, visibilityDeps{})

	got := buf.String()
	if !strings.Contains(got, "scope=default") {
		t.Fatalf("log output = %q, want the default-scope warning", got)
	}
	if strings.Contains(got, "profile restricted") {
		t.Fatalf("log output = %q, want the profile warning suppressed once the default already warned", got)
	}
}

// ---- parseSelector branches ----

func TestParseSelectorErrors(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	if !matchesSelectors(nil, nil) {
		t.Fatal("empty selectors should always match")
	}
}

func TestMatchesSelectorsEmptyLabels(t *testing.T) {
	t.Parallel()
	sel := []compiledSelector{{key: "k", value: "v", hasValue: true}}
	if matchesSelectors(nil, sel) {
		t.Fatal("empty labels should not match non-empty selectors")
	}
	if matchesSelectors(map[string]string{}, sel) {
		t.Fatal("empty labels map should not match non-empty selectors")
	}
}

func TestMatchesSelectorsKeyMissing(t *testing.T) {
	t.Parallel()
	labels := map[string]string{"other": "x"}
	sel := []compiledSelector{{key: "k", hasValue: false}}
	if matchesSelectors(labels, sel) {
		t.Fatal("should not match when selector key is absent from labels")
	}
}

func TestMatchesSelectorsValueMismatch(t *testing.T) {
	t.Parallel()
	labels := map[string]string{"k": "wrong"}
	sel := []compiledSelector{{key: "k", value: "right", hasValue: true}}
	if matchesSelectors(labels, sel) {
		t.Fatal("should not match when label value differs from selector value")
	}
}

func TestMatchesSelectorsKeyPresentNoValueConstraint(t *testing.T) {
	t.Parallel()
	labels := map[string]string{"k": "anything"}
	sel := []compiledSelector{{key: "k", hasValue: false}}
	if !matchesSelectors(labels, sel) {
		t.Fatal("key-only selector should match when key is present regardless of value")
	}
}

// ---- identifier helpers — uncovered branches ----

func TestImageReadIdentifierBranches(t *testing.T) {
	t.Parallel()
	// Wrong prefix
	if _, ok := imageReadIdentifier("/containers/foo/json"); ok {
		t.Fatal("wrong prefix should not match")
	}
	// No recognized read suffix
	if _, ok := imageReadIdentifier("/images/foo/notjson"); ok {
		t.Fatal("/images/id/notjson should not match")
	}
	// No suffix at all
	if _, ok := imageReadIdentifier("/images/justid"); ok {
		t.Fatal("/images/justid (no read suffix) should not match")
	}
	// Bare collection endpoints must not match
	if _, ok := imageReadIdentifier("/images/get"); ok {
		t.Fatal("bare /images/get (multi-export) should not match a single id")
	}
	if _, ok := imageReadIdentifier("/images/json"); ok {
		t.Fatal("bare /images/json (list) should not match a single id")
	}
	// Happy path: inspect
	if id, ok := imageReadIdentifier("/images/sha256:abc/json"); !ok || id != "sha256:abc" {
		t.Fatalf("expected match with sha256:abc, got id=%q ok=%v", id, ok)
	}
	// Read sub-resources: history + single-image export must gate too
	if id, ok := imageReadIdentifier("/images/sha256:abc/history"); !ok || id != "sha256:abc" {
		t.Fatalf("history: expected sha256:abc, got id=%q ok=%v", id, ok)
	}
	if id, ok := imageReadIdentifier("/images/sha256:abc/get"); !ok || id != "sha256:abc" {
		t.Fatalf("get: expected sha256:abc, got id=%q ok=%v", id, ok)
	}
	// Namespaced image ref (contains "/") must be preserved, not truncated
	if id, ok := imageReadIdentifier("/images/registry.io/team/app/json"); !ok || id != "registry.io/team/app" {
		t.Fatalf("namespaced: expected registry.io/team/app, got id=%q ok=%v", id, ok)
	}
	// Attestation listing (Engine API 1.53+) must gate too, so a hidden image's
	// signer/predicate metadata isn't disclosed through this unrecognized path.
	if id, ok := imageReadIdentifier("/images/sha256:abc/attestations"); !ok || id != "sha256:abc" {
		t.Fatalf("attestations: expected sha256:abc, got id=%q ok=%v", id, ok)
	}
}

func TestContainerReadIdentifierGatesSubresources(t *testing.T) {
	t.Parallel()
	// Every read sub-resource of a container must resolve to the container id so
	// the visibility gate hides it for a hidden container.
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/containers/abc/json", "abc"},
		{"/containers/abc/logs", "abc"},
		{"/containers/abc/stats", "abc"},
		{"/containers/abc/top", "abc"},
		{"/containers/abc/changes", "abc"},
		{"/containers/abc/export", "abc"},
		{"/containers/abc/archive", "abc"},
		{"/containers/abc/attach/ws", "abc"},
	} {
		id, ok := containerReadIdentifier(tc.path)
		if !ok || id != tc.want {
			t.Fatalf("containerReadIdentifier(%q) = (%q, %v), want (%q, true)", tc.path, id, ok, tc.want)
		}
	}
	// The list endpoint and write-only paths must not match a single id.
	if _, ok := containerReadIdentifier("/containers/json"); ok {
		t.Fatal("bare /containers/json (list) should not match a single id")
	}
	if _, ok := containerReadIdentifier("/containers/create"); ok {
		t.Fatal("/containers/create should not match a read sub-resource")
	}
}

func TestNetworkInspectIdentifierBranches(t *testing.T) {
	t.Parallel()
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
	if id, ok := networkInspectIdentifier("/networks/create"); !ok || id != "create" {
		t.Fatalf("keyword-named resource = (%q, %v), want (create, true)", id, ok)
	}
	if id, ok := networkInspectIdentifier("/networks/prune"); !ok || id != "prune" {
		t.Fatalf("keyword-named resource = (%q, %v), want (prune, true)", id, ok)
	}
	// Happy path
	if id, ok := networkInspectIdentifier("/networks/net-abc"); !ok || id != "net-abc" {
		t.Fatalf("expected match net-abc, got id=%q ok=%v", id, ok)
	}
}

func TestVolumeInspectIdentifierBranches(t *testing.T) {
	t.Parallel()
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
	if id, ok := volumeInspectIdentifier("/volumes/create"); !ok || id != "create" {
		t.Fatalf("keyword-named resource = (%q, %v), want (create, true)", id, ok)
	}
	if id, ok := volumeInspectIdentifier("/volumes/prune"); !ok || id != "prune" {
		t.Fatalf("keyword-named resource = (%q, %v), want (prune, true)", id, ok)
	}
	// Happy path
	if id, ok := volumeInspectIdentifier("/volumes/vol-abc"); !ok || id != "vol-abc" {
		t.Fatalf("expected match vol-abc, got id=%q ok=%v", id, ok)
	}
}

func TestExecInspectIdentifierBranches(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	if _, ok := secretInspectIdentifier("/configs/sec"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := secretInspectIdentifier("/secrets/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := secretInspectIdentifier("/secrets/sec/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if id, ok := secretInspectIdentifier("/secrets/create"); !ok || id != "create" {
		t.Fatalf("keyword-named resource = (%q, %v), want (create, true)", id, ok)
	}
	if id, ok := secretInspectIdentifier("/secrets/sec-1"); !ok || id != "sec-1" {
		t.Fatalf("expected match sec-1, got id=%q ok=%v", id, ok)
	}
}

func TestConfigInspectIdentifierBranches(t *testing.T) {
	t.Parallel()
	if _, ok := configInspectIdentifier("/secrets/cfg"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := configInspectIdentifier("/configs/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := configInspectIdentifier("/configs/cfg/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if id, ok := configInspectIdentifier("/configs/create"); !ok || id != "create" {
		t.Fatalf("keyword-named resource = (%q, %v), want (create, true)", id, ok)
	}
	if id, ok := configInspectIdentifier("/configs/cfg-1"); !ok || id != "cfg-1" {
		t.Fatalf("expected match cfg-1, got id=%q ok=%v", id, ok)
	}
}

func TestNodeInspectIdentifierBranches(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ins := upstreamInspector{client: &http.Client{}}
	_, _, err := ins.inspectResource(context.Background(), "bogus", "id")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("error = %v, want unsupported resource kind", err)
	}
}

func TestInspectResourceDecodesContainerLabels(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	id, found, err := ins.inspectExec(context.Background(), "exec-1")
	if err != nil || found || id != "" {
		t.Fatalf("err=%v found=%v id=%q, want nil/false/empty", err, found, id)
	}
}

func TestInspectExecNon200Error(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ContainerID":"container-xyz"}`)
	}))
	id, found, err := ins.inspectExec(context.Background(), "exec-1")
	if err != nil || !found || id != "container-xyz" {
		t.Fatalf("err=%v found=%v id=%q, want nil/true/container-xyz", err, found, id)
	}
}

// ---- requestVisible — swarm path ----

func TestRequestVisibleSwarmInspect(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	rec := httptest.NewRecorder()
	got := normalizedPathForRequest(rec, req)
	if got != "/containers/json" {
		t.Fatalf("normalizedPathForRequest = %q, want /containers/json", got)
	}
}

func TestNormalizedPathForRequestUsesMetaNormPath(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	if _, ok := serviceInspectIdentifier("/nodes/svc"); ok {
		t.Fatal("wrong prefix should not match")
	}
	if _, ok := serviceInspectIdentifier("/services/"); ok {
		t.Fatal("empty rest should not match")
	}
	if _, ok := serviceInspectIdentifier("/services/svc/sub"); ok {
		t.Fatal("sub-path should not match")
	}
	if id, ok := serviceInspectIdentifier("/services/create"); !ok || id != "create" {
		t.Fatalf("keyword-named resource = (%q, %v), want (create, true)", id, ok)
	}
	if id, ok := serviceInspectIdentifier("/services/svc-1"); !ok || id != "svc-1" {
		t.Fatalf("expected match svc-1, got id=%q ok=%v", id, ok)
	}
}

// ---- inspectResource — all resource kinds ----

func TestInspectResourceAllKinds(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ins := upstreamInspector{client: &http.Client{}}
	//nolint:staticcheck // SA1012: intentionally passing nil context to exercise the error path
	_, _, err := ins.inspectResource(nil, dockerresource.KindContainer, "abc") //nolint:staticcheck
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestInspectExecNilContextError(t *testing.T) {
	t.Parallel()
	ins := upstreamInspector{client: &http.Client{}}
	//nolint:staticcheck // SA1012: intentionally passing nil context to exercise the error path
	_, _, err := ins.inspectExec(nil, "exec-1") //nolint:staticcheck
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

// ---- inspectExec decode error ----

func TestInspectExecDecodeError(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	selectors := []compiledSelector{{key: "k", hasValue: false}}
	visible, err := requestVisible(context.Background(), "/ping", selectors, visibilityDeps{})
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true for unknown path", err, visible)
	}
}

// TestRequestVisibleWithPolicyEmptyPolicySkipsInspect is the boundary
// regression for hasSelectors := len(policy.selectors) > 0 inside
// requestVisibleWithPolicy: a genuinely empty policy (no selectors, no
// patterns) must return visible=true without ever calling the inspector. A
// `>=` in place of `>` would make hasSelectors true for an empty slice
// (0 >= 0), so the function would fall through to the network-inspect branch
// and actually call deps.inspectResource — observable here because the stub
// always errors.
func TestRequestVisibleWithPolicyEmptyPolicySkipsInspect(t *testing.T) {
	t.Parallel()
	deps := visibilityDeps{
		inspectResource: func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
			return nil, false, errors.New("inspect must not be called for an empty policy")
		},
	}

	visible, err := requestVisibleWithPolicy(context.Background(), "/networks/abc", &compiledPolicy{}, deps)
	if err != nil {
		t.Fatalf("requestVisibleWithPolicy() error = %v, want nil", err)
	}
	if !visible {
		t.Fatal("requestVisibleWithPolicy() = false, want true for an empty policy")
	}
}

func TestRequestVisibleServiceLogs(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	visible, err := requestVisible(context.Background(), "/containers/abc/json", nil, visibilityDeps{})
	if err != nil || !visible {
		t.Fatalf("err=%v visible=%v, want nil/true for empty selectors", err, visible)
	}
}

// ---- middlewareWithDeps — missing branch: profile resolution returns ok=false ----

func TestMiddlewareProfileResolveReturnsFalse(t *testing.T) {
	t.Parallel()
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

// Direct decoder coverage lives in internal/dockerfilters; visibility tests
// exercise it through addVisibilityLabelFilters.

func TestAddVisibilityLabelFiltersLeavesQueryUntouchedWhenSelectorsAlreadyPresent(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(
		http.MethodGet,
		`/v1.53/containers/json?all=1&filters={"label":["com.sockguard.visible=true","com.sockguard.client=watchtower"]}`,
		nil,
	)
	originalRawQuery := req.URL.RawQuery

	forwarded, err := addVisibilityLabelFilters(req, "/containers/json", []compiledSelector{
		{key: "com.sockguard.visible", value: "true", hasValue: true},
		{key: "com.sockguard.client", value: "watchtower", hasValue: true},
	})
	if err != nil {
		t.Fatalf("addVisibilityLabelFilters() error = %v, want nil", err)
	}
	if forwarded.URL.RawQuery != originalRawQuery {
		t.Fatalf("RawQuery = %q, want unchanged %q", forwarded.URL.RawQuery, originalRawQuery)
	}
	// A selector the client already sent is still policy-enforced, so it must
	// be recorded as proxy-injected even though the query needed no rewrite —
	// otherwise ownership's client-value drop would strip it downstream.
	if got := dockerfilters.InjectedSelectors(forwarded, "label"); len(got) != 2 {
		t.Fatalf("InjectedSelectors = %v, want both selectors recorded", got)
	}
}

// TestAddVisibilityLabelFiltersAppendedQueryMatchesEncodedForm pins the
// append path against the parse-and-re-encode path it replaces. A request
// with no filters parameter of its own has the encoded selectors appended to
// its raw query instead of being parsed into a url.Values and rebuilt, so the
// result has to carry the same parameters with the same escaping. Byte
// equality holds wherever the parameters already there sort before "filters";
// where they do not, url.Values.Encode's key sort is the only difference, so
// every case is compared re-encoded as well.
func TestAddVisibilityLabelFiltersAppendedQueryMatchesEncodedForm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		rawQuery      string
		wantByteEqual bool
	}{
		{name: "empty query", rawQuery: "", wantByteEqual: true},
		{name: "parameter sorting before filters", rawQuery: "all=true", wantByteEqual: true},
		{name: "parameter sorting after filters", rawQuery: "limit=25"},
		{name: "several parameters", rawQuery: "all=true&limit=25&size=1"},
		{name: "percent escape falls back to the encode path", rawQuery: "name=web%2Dtier", wantByteEqual: true},
		{name: "existing filters falls back to the encode path", rawQuery: `filters={"status":["running"]}`, wantByteEqual: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
			req.URL.RawQuery = tt.rawQuery

			forwarded, err := addVisibilityLabelFilters(req, "/containers/json", []compiledSelector{
				{key: "com.sockguard.visible", value: "true", hasValue: true},
			})
			if err != nil {
				t.Fatalf("addVisibilityLabelFilters() error = %v, want nil", err)
			}
			got := forwarded.URL.RawQuery

			parsed, err := url.ParseQuery(got)
			if err != nil {
				t.Fatalf("ParseQuery(%q) error = %v", got, err)
			}
			// Rebuild the query the way the encode path builds it, from the
			// filters value this call produced.
			reference := (&url.URL{RawQuery: tt.rawQuery}).Query()
			reference.Set("filters", parsed.Get("filters"))
			want := reference.Encode()

			if tt.wantByteEqual && got != want {
				t.Fatalf("RawQuery = %q, want byte-identical to the encoded form %q", got, want)
			}
			if canonical := parsed.Encode(); canonical != want {
				t.Fatalf("RawQuery = %q re-encodes to %q, want %q", got, canonical, want)
			}
			if parsed.Get("filters") == "" {
				t.Fatalf("RawQuery = %q, want a filters parameter", got)
			}
		})
	}
}

// TestMiddlewareRejectsFalseValuedLegacyFilterBypass exercises the full
// middleware, filters query and all, against a fake upstream: a client that
// sends the policy's own selector spelled with Docker's legacy object
// encoding and a `false` value must still get the selector forwarded.
// dockerd and Podman only install a legacy-object filter entry whose value is
// true, so a false-valued entry is not a filter at all; a decoder that kept
// the key regardless of the boolean let this exact query make the
// "selector already present" check in addVisibilityLabelFilters believe the
// selector was already there, forwarding the request unfiltered and — on a
// Podman upstream with no other filter — returning hidden resources.
func TestMiddlewareRejectsFalseValuedLegacyFilterBypass(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gotRawQuery string

	handler := middlewareWithDeps(logger, Options{
		VisibleResourceLabels: []string{"com.sockguard.visible=true"},
	}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))

	query := url.Values{
		"filters": {`{"label":{"com.sockguard.visible=true":false}}`},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	forwardedFilters, err := url.ParseQuery(gotRawQuery)
	if err != nil {
		t.Fatalf("ParseQuery(%q) error = %v", gotRawQuery, err)
	}
	filters, err := dockerfilters.Decode(forwardedFilters.Get("filters"))
	if err != nil {
		t.Fatalf("Decode(%q) error = %v", forwardedFilters.Get("filters"), err)
	}
	if !slices.Contains(filters["label"], "com.sockguard.visible=true") {
		t.Fatalf("forwarded label filters = %#v, want com.sockguard.visible=true present", filters["label"])
	}
}

func TestMiddlewareInjectsVisibilityLabelsIntoExpandedLists(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestMiddlewareHidesKeywordNamedResourcesOnReads(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		target     string
		kind       dockerresource.Kind
		identifier string
	}{
		{name: "network create", method: http.MethodGet, target: "/v1.53/networks/create", kind: dockerresource.KindNetwork, identifier: "create"},
		{name: "network prune", method: http.MethodHead, target: "/v1.53/networks/prune", kind: dockerresource.KindNetwork, identifier: "prune"},
		{name: "volume create", method: http.MethodGet, target: "/v1.53/volumes/create", kind: dockerresource.KindVolume, identifier: "create"},
		{name: "volume prune", method: http.MethodHead, target: "/v1.53/volumes/prune", kind: dockerresource.KindVolume, identifier: "prune"},
		{name: "service create", method: http.MethodGet, target: "/v1.53/services/create", kind: dockerresource.KindService, identifier: "create"},
		{name: "secret create", method: http.MethodHead, target: "/v1.53/secrets/create", kind: dockerresource.KindSecret, identifier: "create"},
		{name: "config create", method: http.MethodGet, target: "/v1.53/configs/create", kind: dockerresource.KindConfig, identifier: "create"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nextCalled := false
			var gotKind dockerresource.Kind
			var gotIdentifier string
			handler := middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
				VisibleResourceLabels: []string{"team=alice"},
			}, visibilityDeps{
				inspectResource: func(_ context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
					gotKind = kind
					gotIdentifier = identifier
					return map[string]string{"team": "bob"}, true, nil
				},
			})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if nextCalled {
				t.Fatal("hidden keyword-named resource reached upstream")
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
			}
			if gotKind != tt.kind || gotIdentifier != tt.identifier {
				t.Fatalf("inspect = %s/%q, want %s/%q", gotKind, gotIdentifier, tt.kind, tt.identifier)
			}
		})
	}
}

func TestCombinedVisibilityPolicyUsesOneFreshInspect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		kind   dockerresource.Kind
		body   string
		policy compiledPolicy
	}{
		{
			name: "container",
			kind: dockerresource.KindContainer,
			body: `{"Name":"/web","Image":"nginx:latest","Config":{"Labels":{"team":"alice"}}}`,
			policy: compiledPolicy{
				selectors:    []compiledSelector{{key: "team", value: "alice", hasValue: true}},
				namePatterns: mustCompilePatterns(t, "web"),
			},
		},
		{
			name: "image",
			kind: dockerresource.KindImage,
			body: `{"RepoTags":["nginx:latest"],"Config":{"Labels":{"team":"alice"}}}`,
			policy: compiledPolicy{
				selectors:     []compiledSelector{{key: "team", value: "alice", hasValue: true}},
				imagePatterns: mustCompilePatterns(t, "nginx:*"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, tt.body)
			}))
			t.Cleanup(srv.Close)
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				r2 := r.Clone(r.Context())
				r2.URL.Scheme = "http"
				r2.URL.Host = srv.Listener.Addr().String()
				return srv.Client().Transport.RoundTrip(r2)
			})}
			deps := newVisibilityDepsClient(client)

			for attempt := int32(1); attempt <= 2; attempt++ {
				visible, err := resourceVisibleWithPolicy(context.Background(), deps, tt.kind, "shared", &tt.policy)
				if err != nil || !visible {
					t.Fatalf("attempt %d: visible = %v, err = %v; want true, nil", attempt, visible, err)
				}
				if got := calls.Load(); got != attempt {
					t.Fatalf("attempt %d: upstream inspect calls = %d, want %d", attempt, got, attempt)
				}
			}
		})
	}
}

func mustCompilePatterns(t *testing.T, patterns ...string) []compiledPattern {
	t.Helper()
	compiled, err := compilePatterns(patterns)
	if err != nil {
		t.Fatalf("compilePatterns() error = %v", err)
	}
	return compiled
}

// TestResourceVisibleWithPolicyEmptySelectorsSkipsCombinedPath is the
// boundary regression for len(policy.selectors) > 0 in the combined-path
// gate of resourceVisibleWithPolicy: a patterns-only policy (zero selectors)
// must use the separate inspectResourceMeta path, not the combined
// inspectResourceDetails path meant for selectors+patterns together. A `>=`
// in place of `>` would take the combined path anyway (0 >= 0) — observable
// here because inspectResourceDetails is wired to always error while
// inspectResourceMeta returns a matching name.
func TestResourceVisibleWithPolicyEmptySelectorsSkipsCombinedPath(t *testing.T) {
	t.Parallel()
	policy := &compiledPolicy{namePatterns: mustCompilePatterns(t, "web-*")}
	deps := visibilityDeps{
		inspectResourceMeta: func(context.Context, dockerresource.Kind, string) (*resourceMeta, bool, error) {
			return &resourceMeta{names: []string{"/web-1"}}, true, nil
		},
		inspectResourceDetails: func(context.Context, dockerresource.Kind, string) (*resourceDetails, bool, error) {
			return nil, false, errors.New("combined inspect must not be used when there are no label selectors")
		},
	}

	visible, err := resourceVisibleWithPolicy(context.Background(), deps, dockerresource.KindContainer, "abc", policy)
	if err != nil {
		t.Fatalf("resourceVisibleWithPolicy() error = %v, want nil", err)
	}
	if !visible {
		t.Fatal("resourceVisibleWithPolicy() = false, want true (name matches web-*)")
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	meta, found, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "missing")
	if err != nil || found || meta != nil {
		t.Fatalf("err=%v found=%v meta=%v, want nil/false/nil", err, found, meta)
	}
}

func TestInspectResourceMetaContainerNon200(t *testing.T) {
	t.Parallel()
	ins := newMockInspector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindContainer, "abc")
	if err == nil || !strings.Contains(err.Error(), "returned status") {
		t.Fatalf("err = %v, want 'returned status'", err)
	}
}

func TestInspectResourceMetaContainerDecodes(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	ins := upstreamInspector{client: &http.Client{}}
	_, _, err := ins.inspectResourceMeta(context.Background(), dockerresource.KindNetwork, "net-1")
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("err = %v, want unsupported resource kind", err)
	}
}

// ---- decodeResourceMeta ----

func TestDecodeResourceMetaContainerUsesNamesWhenPresent(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	_, err := decodeResourceMeta(strings.NewReader(`{}`), dockerresource.KindNetwork)
	if err == nil || !strings.Contains(err.Error(), "unsupported resource kind") {
		t.Fatalf("err = %v, want unsupported resource kind", err)
	}
}

func TestDecodeResourceMetaDecodeError(t *testing.T) {
	t.Parallel()
	_, err := decodeResourceMeta(strings.NewReader(`not-json`), dockerresource.KindContainer)
	if err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

// ---- compilePatterns ----

func TestCompilePatternsEmptyGlob(t *testing.T) {
	t.Parallel()
	_, err := compilePatterns([]string{""})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("err = %v, want 'must not be empty'", err)
	}
}

func TestCompilePatternsInvalidEmptyPattern(t *testing.T) {
	t.Parallel()
	// The glob-to-regex converter escapes all special regex characters, so the
	// only way to produce an invalid pattern is an empty string.
	_, err := compilePatterns([]string{"valid", ""})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("err = %v, want 'must not be empty'", err)
	}
}

func TestCompilePatternsHappyPath(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	if !matchesAnyPattern("anything", nil) {
		t.Fatal("empty patterns should always return true")
	}
}

func TestMatchesAnyPatternNoMatch(t *testing.T) {
	t.Parallel()
	patterns, _ := compilePatterns([]string{"traefik"})
	if matchesAnyPattern("portainer", patterns) {
		t.Fatal("portainer should not match traefik pattern")
	}
}

func TestMatchesAnyPatternMatch(t *testing.T) {
	t.Parallel()
	patterns, _ := compilePatterns([]string{"redis:*"})
	if !matchesAnyPattern("redis:7", patterns) {
		t.Fatal("redis:7 should match redis:* pattern")
	}
}

// ---- containerNameFromNames and imageShortName ----

func TestContainerNameFromNamesEmpty(t *testing.T) {
	t.Parallel()
	if got := containerNameFromNames(nil); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

func TestContainerNameFromNamesStripsLeadingSlash(t *testing.T) {
	t.Parallel()
	if got := containerNameFromNames([]string{"/traefik"}); got != "traefik" {
		t.Fatalf("got %q, want traefik", got)
	}
}

func TestImageShortNameNoSlash(t *testing.T) {
	t.Parallel()
	if got := imageShortName("traefik:latest"); got != "traefik:latest" {
		t.Fatalf("got %q, want traefik:latest", got)
	}
}

func TestImageShortNameWithRegistry(t *testing.T) {
	t.Parallel()
	if got := imageShortName("ghcr.io/org/traefik:v2"); got != "traefik:v2" {
		t.Fatalf("got %q, want traefik:v2", got)
	}
}

// TestImageShortNameLeadingSlashBoundary is the boundary regression for
// `idx >= 0` in imageShortName: a `>` in its place would treat idx==0 (a
// leading "/") as "no separator found" and return the reference unchanged
// instead of stripping the empty prefix.
func TestImageShortNameLeadingSlashBoundary(t *testing.T) {
	t.Parallel()
	if got := imageShortName("/traefik:v2"); got != "traefik:v2" {
		t.Fatalf("got %q, want traefik:v2", got)
	}
}

func TestFilterWriterWriteHeaderCapturesCode(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestAcquireReleasePatternBuffer exercises the pool acquire/release cycle so
// the nil-guard in releasePatternBuffer is covered.
func TestAcquireReleasePatternBuffer(t *testing.T) {
	t.Parallel()

	// Acquire produces a non-nil, reset buffer.
	buf := acquirePatternBuffer()
	if buf == nil {
		t.Fatal("acquirePatternBuffer() returned nil")
	}

	// Write something so we can verify Reset is called on re-acquire.
	buf.WriteString("stale data")
	releasePatternBuffer(buf)

	buf2 := acquirePatternBuffer()
	if buf2.Len() != 0 {
		t.Errorf("re-acquired buffer not reset: len = %d", buf2.Len())
	}
	releasePatternBuffer(buf2)

	// Releasing nil must not panic.
	releasePatternBuffer(nil)
}

// TestAcquirePatternBufferGuardsAgainstNilFromPool pins the `buf == nil`
// guard at middleware.go:39. sync.Pool.Get does not reliably return an entry
// that was just Put — Get may skip it, and under -race Put drops roughly a
// quarter of its objects — so seeding the pool with a manual Put and reading
// it straight back is not a deterministic way to exercise this path. Instead
// this overrides the pool's New func to return a typed nil *bytes.Buffer,
// then calls acquirePatternBuffer many times without releasing any of them:
// each Get first drains whatever real entries other tests left in the pool,
// and once those run out every subsequent Get falls through to New, which now
// returns nil deterministically. The original code must allocate a fresh
// buffer on that path (asserted non-nil and usable on every iteration);
// CONDITIONALS_NEGATION turning == into != would instead try to Reset() the
// nil entry and panic.
//
// Deliberately not t.Parallel(): every other test in this file is, and the Go
// test runner runs all non-parallel tests to completion (in the order
// declared) before any parallel test's body resumes past its t.Parallel()
// call, so this test's override of the shared package-level
// patternBufferPool's New func is isolated from them.
func TestAcquirePatternBufferGuardsAgainstNilFromPool(t *testing.T) {
	originalNew := patternBufferPool.New
	patternBufferPool.New = func() any { return (*bytes.Buffer)(nil) }
	t.Cleanup(func() { patternBufferPool.New = originalNew })

	for i := 0; i < 1024; i++ {
		buf := acquirePatternBuffer()
		if buf == nil {
			t.Fatalf("iteration %d: acquirePatternBuffer() returned nil", i)
		}
		buf.WriteString("ok")
		if got := buf.String(); got != "ok" {
			t.Fatalf("iteration %d: buffer not usable after guard: got %q", i, got)
		}
	}
}

// TestReleasePatternBufferNilIsNoop pins the `buf == nil` guard at
// middleware.go:47: releasing nil must return before reaching Put, or it
// poisons the pool with a nil entry a later acquirePatternBuffer would have
// to catch. CONDITIONALS_NEGATION turning == into != would skip the early
// return and call patternBufferPool.Put on the nil argument instead.
//
// Detecting that can't depend on Pool.Get returning the exact entry a paired
// Put just added — sync.Pool makes no such promise (see
// TestAcquirePatternBufferGuardsAgainstNilFromPool). Instead this overrides
// New to a counting sentinel, calls releasePatternBuffer(nil) many times,
// then draws from the pool many times and checks every draw: under the real
// guard releasePatternBuffer never calls Put, so every draw is either a
// pre-existing valid entry or a fresh one from New, never nil. Under the
// mutant, releasePatternBuffer(nil) seeds the pool with nil entries that a
// draw of this size is overwhelmingly likely to surface before it can be
// explained away as bad luck.
//
// Deliberately not t.Parallel(), for the same reason as
// TestAcquirePatternBufferGuardsAgainstNilFromPool.
func TestReleasePatternBufferNilIsNoop(t *testing.T) {
	originalNew := patternBufferPool.New
	var newCalls int
	patternBufferPool.New = func() any {
		newCalls++
		return new(bytes.Buffer)
	}
	t.Cleanup(func() { patternBufferPool.New = originalNew })

	for i := 0; i < 1024; i++ {
		releasePatternBuffer(nil) // must not panic, must not Put
	}

	for i := 0; i < 2048; i++ {
		got := patternBufferPool.Get()
		buf, ok := got.(*bytes.Buffer)
		if !ok || buf == nil {
			t.Fatalf("draw %d: pool yielded %#v, want a valid *bytes.Buffer (releasePatternBuffer(nil) must not Put a nil entry)", i, got)
		}
	}
	if newCalls == 0 {
		t.Fatal("New was never invoked; this draw did not actually exercise the pool")
	}
}

// TestContainerItemVisibleByPatternsEmptyPatternsAlwaysVisible documents why
// middleware.go:553 and :559 in containerItemVisibleByPatterns are genuinely
// equivalent mutants (a `>=` in place of `>` on either gate does not change
// observable behavior): both blocks call matchesAnyPattern directly on a
// single string (item's container name or Image field), and
// matchesAnyPattern's own empty-pattern-list guard returns true
// unconditionally, regardless of what value it's given — including missing,
// null, or empty Names/Image. This is not a mutant-kill test; it pins the
// production contract these two lines actually implement.
func TestContainerItemVisibleByPatternsEmptyPatternsAlwaysVisible(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{name: "Names and Image missing", raw: `{}`},
		{name: "Names explicit null, Image empty", raw: `{"Names":null,"Image":""}`},
		{name: "Names empty slice, Image empty", raw: `{"Names":[],"Image":""}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			visible, err := containerItemVisibleByPatterns(json.RawMessage(tt.raw), &compiledPolicy{})
			if err != nil {
				t.Fatalf("containerItemVisibleByPatterns(%s) error = %v", tt.raw, err)
			}
			if !visible {
				t.Fatalf("containerItemVisibleByPatterns(%s) = false, want true when no pattern axis is configured", tt.raw)
			}
		})
	}
}

// TestImageItemVisibleByPatternsEmptyPatternsWithNoRepoTagsStillVisible is
// the boundary regression for middleware.go:574 and :586 in
// imageItemVisibleByPatterns. These are NOT equivalent mutants, unlike their
// containerItemVisibleByPatterns twins at :553/:559 above: both blocks here
// loop over item.RepoTags via matchesAnyPattern per-iteration, so an image
// whose RepoTags is missing, JSON null, or an empty array never reaches
// matchesAnyPattern at all — its own "empty patterns always match" guard
// never gets a chance to run. With the real `> 0` gate, an empty pattern list
// skips the loop and the block entirely, so the item stays visible. A `>=`
// mutant enters the block anyway (0 >= 0), the loop runs zero times,
// `matched` stays false, and the item is wrongly rejected. A single test case
// per RepoTags shape (with both namePatterns and imagePatterns empty) is
// enough to kill each mutant independently: whichever gate is mutated, the
// other one's real code still skips its own block, so the mutated block is
// the one that decides the (wrong) result.
func TestImageItemVisibleByPatternsEmptyPatternsWithNoRepoTagsStillVisible(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{name: "RepoTags key missing", raw: `{}`},
		{name: "RepoTags is JSON null", raw: `{"RepoTags":null}`},
		{name: "RepoTags is an empty array", raw: `{"RepoTags":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			visible, err := imageItemVisibleByPatterns(json.RawMessage(tt.raw), &compiledPolicy{})
			if err != nil {
				t.Fatalf("imageItemVisibleByPatterns(%s) error = %v", tt.raw, err)
			}
			if !visible {
				t.Fatalf("imageItemVisibleByPatterns(%s) = false, want true when no pattern axis is configured", tt.raw)
			}
		})
	}
}

// TestResourceMetaMatchesPatternsUnknownKind covers the default branch that
// returns true for any kind that is neither KindContainer nor KindImage.
func TestResourceMetaMatchesPatternsUnknownKind(t *testing.T) {
	t.Parallel()

	namePatterns, err := compilePatterns([]string{"traefik"})
	if err != nil {
		t.Fatalf("compilePatterns: %v", err)
	}
	policy := &compiledPolicy{namePatterns: namePatterns}
	meta := &resourceMeta{names: []string{"/unrelated"}}

	// A volume or service kind should always return true (no name/image meta).
	if !resourceMetaMatchesPatterns(meta, dockerresource.KindVolume, policy) {
		t.Error("expected true for unknown kind, got false")
	}
}

// TestContainerMetaMatchesPatternsNoAxesNeverTouchesMeta pins the guard's
// contract at middleware.go:916/:921 in containerMetaMatchesPatterns against
// a nil meta. These two gates are genuinely equivalent: a `>=` mutant enters
// the block for an empty pattern list, but the block calls matchesAnyPattern
// directly on a single string (not through a RepoTags-style loop), and
// matchesAnyPattern's own empty-list guard makes it return true regardless of
// the value being matched — so with any non-nil meta, mutant and original
// return the same result (see TestImageMetaMatchesPatternsEmptyRepoTags...
// below for why the image twin does NOT share this equivalence). The only
// way this test distinguishes the mutant at all is that meta is nil here, so
// the mutant's field read (containerNameFromNames(meta.names) / meta.image)
// panics on a nil pointer dereference; production never constructs a nil
// *resourceMeta, so this pins a defensive contract rather than covering a
// reachable boundary.
func TestContainerMetaMatchesPatternsNoAxesNeverTouchesMeta(t *testing.T) {
	t.Parallel()
	if !containerMetaMatchesPatterns(nil, &compiledPolicy{}) {
		t.Fatal("containerMetaMatchesPatterns() = false, want true when no pattern axis is configured")
	}
}

// TestImageMetaMatchesPatternsEmptyRepoTagsWithNoAxesStillVisible is the
// boundary regression for the namePatterns/imagePatterns length gates at
// middleware.go:930 and :933 in imageMetaMatchesPatterns. Unlike its
// containerMetaMatchesPatterns twin above, these two gates are NOT
// equivalent: both feed anyRepoTagMatches, which loops over meta.repoTags and
// only calls matchesAnyPattern per iteration, so a resource with a nil or
// empty repoTags list never reaches matchesAnyPattern at all — its own
// "empty patterns always match" guard never gets a chance to run;
// anyRepoTagMatches instead returns false outright for an empty repoTags
// list, regardless of how many patterns are configured. With the real `> 0`
// gate, an empty pattern list skips the block entirely and the resource
// stays visible. A `>=` mutant enters the block anyway (0 >= 0),
// anyRepoTagMatches returns false, and the resource is wrongly hidden — this
// is observable with an ordinary non-nil, empty resourceMeta, no nil
// dereference required.
func TestImageMetaMatchesPatternsEmptyRepoTagsWithNoAxesStillVisible(t *testing.T) {
	t.Parallel()
	meta := &resourceMeta{}
	if !imageMetaMatchesPatterns(meta, &compiledPolicy{}) {
		t.Fatal("imageMetaMatchesPatterns() = false, want true when repoTags is empty and no pattern axis is configured")
	}
}

// TestImageMetaMatchesPatternsNameAndImage exercises the imageMetaMatchesPatterns
// branches: no tags → false when namePatterns require a match; matching tag → true.
func TestImageMetaMatchesPatternsNameAndImage(t *testing.T) {
	t.Parallel()

	namePatterns, err := compilePatterns([]string{"traefik*"})
	if err != nil {
		t.Fatalf("compilePatterns(name): %v", err)
	}
	imagePatterns, err := compilePatterns([]string{"ghcr.io/**"})
	if err != nil {
		t.Fatalf("compilePatterns(image): %v", err)
	}

	tests := []struct {
		name     string
		repoTags []string
		policy   *compiledPolicy
		want     bool
	}{
		{
			name:     "name pattern matches short name",
			repoTags: []string{"traefik:v2.10"},
			policy:   &compiledPolicy{namePatterns: namePatterns},
			want:     true,
		},
		{
			name:     "name pattern no match",
			repoTags: []string{"nginx:latest"},
			policy:   &compiledPolicy{namePatterns: namePatterns},
			want:     false,
		},
		{
			name:     "image pattern matches full ref",
			repoTags: []string{"ghcr.io/org/app:1.0"},
			policy:   &compiledPolicy{imagePatterns: imagePatterns},
			want:     true,
		},
		{
			name:     "image pattern no match",
			repoTags: []string{"docker.io/library/nginx:latest"},
			policy:   &compiledPolicy{imagePatterns: imagePatterns},
			want:     false,
		},
		{
			name:     "empty repoTags with name pattern returns false",
			repoTags: nil,
			policy:   &compiledPolicy{namePatterns: namePatterns},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &resourceMeta{repoTags: tt.repoTags}
			got := imageMetaMatchesPatterns(meta, tt.policy)
			if got != tt.want {
				t.Errorf("imageMetaMatchesPatterns() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnyRepoTagMatchesWithTransform covers the transform-applied path in anyRepoTagMatches.
func TestAnyRepoTagMatchesWithTransform(t *testing.T) {
	t.Parallel()

	shortNamePatterns, err := compilePatterns([]string{"traefik*"})
	if err != nil {
		t.Fatalf("compilePatterns: %v", err)
	}

	refs := []string{"ghcr.io/traefik/traefik:v2.10", "nginx:latest"}

	// With imageShortName transform: "ghcr.io/traefik/traefik:v2.10" → "traefik:v2.10"
	if !anyRepoTagMatches(refs, shortNamePatterns, imageShortName) {
		t.Error("anyRepoTagMatches with imageShortName transform should return true")
	}

	// Without transform: full refs don't match "traefik*"
	if anyRepoTagMatches(refs, shortNamePatterns, nil) {
		t.Error("anyRepoTagMatches without transform should return false for full refs")
	}
}

// TestResourceVisibleNotFound covers the !found → (true, nil) branch in resourceVisible.
func TestResourceVisibleNotFound(t *testing.T) {
	t.Parallel()

	deps := visibilityDeps{
		inspectResource: func(_ context.Context, _ dockerresource.Kind, _ string) (map[string]string, bool, error) {
			return nil, false, nil // not found
		},
	}
	selectors := []compiledSelector{{key: "env", value: "prod", hasValue: true}}

	visible, err := resourceVisible(context.Background(), deps, dockerresource.KindContainer, "missing-id", selectors)
	if err != nil {
		t.Fatalf("resourceVisible() error = %v, want nil", err)
	}
	if !visible {
		t.Error("resourceVisible() = false for not-found resource, want true (treat as visible)")
	}
}
