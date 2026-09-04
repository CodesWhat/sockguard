package visibility

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/proxy"
)

// conditionalRecordingTransport stands in for the Docker socket behind the
// reverse proxy and keeps the request headers that reached the wire.
type conditionalRecordingTransport struct {
	seen http.Header
	body string
}

func (t *conditionalRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.seen = req.Header.Clone()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

// TestVisibilityListRevalidationReachesDaemonAsFullFetch drives the composed
// shape — visibility middleware over the reverse proxy — because that is
// where the strip lives. A client revalidating a list it cached before the
// policy existed has to be answered with a filtered body, not a 304.
func TestVisibilityListRevalidationReachesDaemonAsFullFetch(t *testing.T) {
	t.Parallel()

	transport := &conditionalRecordingTransport{body: `[{"Names":["/visible-web"],"Image":"nginx"},{"Names":["/secret-db"],"Image":"postgres"}]`}
	upstream := proxy.NewWithTransport(transport, slog.New(slog.NewTextHandler(io.Discard, nil)), proxy.Options{})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req.Header.Set("If-None-Match", `"cached-before-the-policy"`)
	req.Header.Set("If-Modified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, name := range []string{"If-None-Match", "If-Modified-Since"} {
		if got := transport.seen.Get(name); got != "" {
			t.Errorf("daemon saw %s = %q, want it stripped so the list can be filtered", name, got)
		}
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "secret-db") {
		t.Fatalf("hidden container leaked into the revalidated list: %s", body)
	}
}

// TestVisibilityFiltersFailClosedOnNotModified is the backstop for an upstream
// that answers 304 anyway. The refusal carries its own reason code so an
// operator is not sent to read pattern axes that never ran.
func TestVisibilityFiltersFailClosedOnNotModified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		opts   Options
	}{
		{
			name:   "pattern-filtered container list",
			target: "/v1.53/containers/json",
			opts:   Options{NamePatterns: []string{"visible-*"}},
		},
		{
			name:   "pattern-filtered libpod container list",
			target: "/v5.8.1/libpod/containers/json",
			opts:   Options{NamePatterns: []string{"visible-*"}},
		},
		{
			name:   "pattern-filtered image list",
			target: "/v1.53/images/json",
			opts:   Options{ImagePatterns: []string{"nginx*"}},
		},
		{
			name:   "system data usage",
			target: "/v1.53/system/df",
			opts:   Options{VisibleResourceLabels: []string{"tier=prod"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"upstream"`)
				w.WriteHeader(http.StatusNotModified)
			})
			handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{})(upstream)

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeVisibilityNotModified {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityNotModified)
			}
			if got := rec.Header().Get("ETag"); got != "" {
				t.Fatalf("ETag = %q, want the upstream validator cleared off the refusal", got)
			}
		})
	}
}

// TestVisibilityNotModifiedRefusalIgnoresRolloutMode: the response-side
// controls in this package are not verdicts warn mode stages, and this one
// decides whether a stale body is confirmed at all.
func TestVisibilityNotModifiedRefusalIgnoresRolloutMode(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d under warn mode; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

// TestVisibilityNoContentStillPassesThrough is the control: 204 is not a
// revalidation, so it keeps the pass-through it always had.
func TestVisibilityNoContentStillPassesThrough(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}
