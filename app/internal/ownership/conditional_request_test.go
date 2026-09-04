package ownership

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

// TestSystemDataUsageRevalidationReachesDaemonAsFullFetch drives the composed
// shape — ownership middleware over the reverse proxy — because that is where
// the strip lives. A caller revalidating a host inventory it cached before
// isolation was configured has to be answered with the owner-filtered body.
func TestSystemDataUsageRevalidationReachesDaemonAsFullFetch(t *testing.T) {
	t.Parallel()

	transport := &conditionalRecordingTransport{body: modernSystemDFUpstream}
	upstream := proxy.NewWithTransport(transport, slog.New(slog.NewTextHandler(io.Discard, nil)), proxy.Options{})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	req.Header.Set("If-None-Match", `"cached-before-isolation"`)
	req.Header.Set("If-Modified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, name := range []string{"If-None-Match", "If-Modified-Since"} {
		if got := transport.seen.Get(name); got != "" {
			t.Errorf("daemon saw %s = %q, want it stripped so the inventory can be filtered", name, got)
		}
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "team-b") {
		t.Fatalf("other owner's resources leaked into the revalidated inventory: %s", body)
	}
}

// TestSystemDataUsageFailsClosedOnNotModified is the backstop for an upstream
// that answers 304 anyway: the host inventory the client cached is never
// confirmed, and the refusal carries its own reason code so it is not read as
// an ownership misconfiguration.
func TestSystemDataUsageFailsClosedOnNotModified(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if meta.ReasonCode != reasonCodeOwnerNotModified {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerNotModified)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want the upstream validator cleared off the refusal", got)
	}
}

// TestSystemDataUsageHeadFailsClosedOnNotModified is the HEAD twin of
// TestSystemDataUsageFailsClosedOnNotModified. HEAD reaches the same 304 check
// as GET rather than forwardHeadWithoutUpstreamRepresentation's usual
// metadata-stripped 200: forwarding a recorded 304 on HEAD would leave the
// fail-closed claim in docs/content/docs/security.mdx untrue for that method.
func TestSystemDataUsageHeadFailsClosedOnNotModified(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodHead, "/v1.53/system/df", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if meta.ReasonCode != reasonCodeOwnerNotModified {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerNotModified)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want the upstream validator cleared off the refusal", got)
	}
}

// TestSystemDataUsageNotModifiedRefusalIgnoresRolloutMode: every response-side
// control in this file is unconditional, and this one decides whether a full
// host inventory is confirmed at all.
func TestSystemDataUsageNotModifiedRefusalIgnoresRolloutMode(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: "warn"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d under warn mode; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

// TestSystemDataUsageNoContentStillPassesThrough is the control: 204 is not a
// revalidation, so it keeps the pass-through it always had.
func TestSystemDataUsageNoContentStillPassesThrough(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}
