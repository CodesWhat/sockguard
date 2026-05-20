package visibility

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

// makePatternPolicy builds a minimal compiledPolicy with name patterns for use
// in patternFilterWriter tests.
func makePatternPolicy(t *testing.T, nameGlobs ...string) *compiledPolicy {
	t.Helper()
	patterns, err := compilePatterns(nameGlobs)
	if err != nil {
		t.Fatalf("compilePatterns: %v", err)
	}
	return &compiledPolicy{namePatterns: patterns}
}

// TestFilterWriterFlushFilteredEmptyBodyOn304 asserts that a 304 Not Modified
// response is forwarded with no body (RFC 9110 §15.4.5). Any bytes written for
// a 304 would trigger Go's http.ResponseWriter to downgrade to 502.
func TestFilterWriterFlushFilteredEmptyBodyOn304(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)

	// Simulate upstream writing a 304 with stale buffered bytes.
	fw.WriteHeader(http.StatusNotModified)
	_, _ = fw.Write([]byte("stale-body-that-must-not-be-forwarded"))

	policy := makePatternPolicy(t, "mycontainer")
	if err := fw.flushFiltered("/containers/json", policy); err != nil {
		t.Fatalf("flushFiltered error: %v", err)
	}

	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("body = %q, want empty body for 304", body)
	}
}

// TestFilterWriterFlushFilteredEmptyBodyOn204 asserts that a 204 No Content
// response is forwarded with no body (RFC 9110 §15.3.5).
func TestFilterWriterFlushFilteredEmptyBodyOn204(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)

	fw.WriteHeader(http.StatusNoContent)
	_, _ = fw.Write([]byte("should-not-be-sent"))

	policy := makePatternPolicy(t, "*")
	if err := fw.flushFiltered("/containers/json", policy); err != nil {
		t.Fatalf("flushFiltered error: %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("body = %q, want empty body for 204", body)
	}
}

// TestFilterWriterFlushFilteredFiltersContainersByName verifies the happy-path
// pattern filtering: only containers matching the name glob survive.
func TestFilterWriterFlushFilteredFiltersContainersByName(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `[{"Names":["/mycontainer"],"Image":"alpine"},{"Names":["/other"],"Image":"nginx"}]`)
	})

	opts := Options{
		NamePatterns: []string{"mycontainer"},
	}
	handler := middlewareWithDeps(logger, opts, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mycontainer") {
		t.Fatalf("body missing mycontainer: %s", body)
	}
	if strings.Contains(body, "other") {
		t.Fatalf("body should not contain filtered container 'other': %s", body)
	}
}

// TestFilterWriterWriteCapsBufferAtLimit asserts patternFilterWriter.Write
// stops buffering once the body would exceed filter.MaxResponseBodyBytes, so a
// large upstream response cannot drive unbounded memory growth.
func TestFilterWriterWriteCapsBufferAtLimit(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)

	under := make([]byte, filter.MaxResponseBodyBytes-1)
	if _, err := fw.Write(under); err != nil {
		t.Fatalf("Write(under) error: %v", err)
	}
	if fw.overflow {
		t.Fatal("overflow set before exceeding the limit")
	}

	n, err := fw.Write([]byte("12"))
	if err != nil {
		t.Fatalf("Write(over) error: %v", err)
	}
	if n != 2 {
		t.Fatalf("Write(over) n = %d, want 2 (overflow bytes still reported written)", n)
	}
	if !fw.overflow {
		t.Fatal("overflow not set after exceeding the limit")
	}
	if fw.body.Len() != filter.MaxResponseBodyBytes-1 {
		t.Fatalf("buffer len = %d, want %d (capped, no oversized append)", fw.body.Len(), filter.MaxResponseBodyBytes-1)
	}
}

// TestFilterWriterCapsOversizedResponse drives the middleware end-to-end with a
// containers/json response larger than the 8 MiB cap and asserts the client
// gets a 502 rather than the proxy buffering the whole body (OOM DoS guard).
func TestFilterWriterCapsOversizedResponse(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	chunk := `{"Names":["/c"],"Image":"alpine"},`
	huge := "[" + strings.Repeat(chunk, (filter.MaxResponseBodyBytes/len(chunk))+5000) +
		`{"Names":["/c"],"Image":"alpine"}]`

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, huge)
	})

	opts := Options{NamePatterns: []string{"*"}}
	handler := middlewareWithDeps(logger, opts, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for oversized response; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("body = %q, want too-large message", rec.Body.String())
	}
}
