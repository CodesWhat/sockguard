package visibility

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
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

func TestFilterWriterMarksHeadersWrittenOnEveryCommittedPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "empty body status", status: http.StatusNoContent},
		{name: "non-success status", status: http.StatusBadGateway, body: `upstream error`},
		{name: "filtered array", status: http.StatusOK, body: `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			fw := newPatternFilterWriter(rec)
			t.Cleanup(fw.release)
			fw.WriteHeader(tt.status)
			_, _ = fw.Write([]byte(tt.body))
			if err := fw.flushFiltered("/containers/json", makePatternPolicy(t, "*")); err != nil {
				t.Fatalf("flushFiltered() error = %v", err)
			}
			if !fw.headerWritten {
				t.Fatal("flushFiltered() committed a response without recording headerWritten")
			}
		})
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

// TestFilterWriterWriteAtExactLimitDoesNotOverflow is the boundary regression
// for `int64(p.body.Len())+int64(len(b)) > filter.MaxResponseBodyBytes` in
// patternFilterWriter.Write: a write that lands EXACTLY on the limit must be
// buffered in full, not treated as oversized. A `>=` in place of `>` would
// flag it as overflow one write early.
func TestFilterWriterWriteAtExactLimitDoesNotOverflow(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)
	t.Cleanup(fw.release)

	exact := make([]byte, filter.MaxResponseBodyBytes)
	n, err := fw.Write(exact)
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if n != len(exact) {
		t.Fatalf("Write() n = %d, want %d", n, len(exact))
	}
	if fw.overflow {
		t.Fatal("overflow set for a write landing exactly on the limit")
	}
	if fw.body.Len() != filter.MaxResponseBodyBytes {
		t.Fatalf("buffer len = %d, want %d", fw.body.Len(), filter.MaxResponseBodyBytes)
	}
}

// TestFilterWriterCommitIfUnfilterablePassesThroughExactBoundaryStatus is the
// boundary regression for `p.statusCode >= http.StatusMultipleChoices` in
// commitIfUnfilterable: 300 itself is the first non-2xx status and must be
// passed through untouched. A `>` in place of `>=` would leave exactly 300
// inside the "filter as 2xx JSON" range instead.
func TestFilterWriterCommitIfUnfilterablePassesThroughExactBoundaryStatus(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)
	t.Cleanup(fw.release)

	const body = "not a json array"
	fw.WriteHeader(http.StatusMultipleChoices)
	_, _ = fw.Write([]byte(body))

	committed, err := fw.commitIfUnfilterable()
	if err != nil {
		t.Fatalf("commitIfUnfilterable() error = %v", err)
	}
	if !committed {
		t.Fatal("commitIfUnfilterable() = false, want true (300 must pass through unfiltered)")
	}
	if rec.Code != http.StatusMultipleChoices {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMultipleChoices)
	}
	if rec.Body.String() != body {
		t.Fatalf("body = %q, want %q unchanged", rec.Body.String(), body)
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

func TestGeneratedFilterErrorsReplaceUpstreamRepresentationOnWire(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body func() string
	}{
		{name: "oversized", body: func() string { return strings.Repeat("x", filter.MaxResponseBodyBytes+1) }},
		{name: "filter failure", body: func() string { return `[{"Names":` }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := middlewareWithDeps(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
				NamePatterns: []string{"*"},
			}, visibilityDeps{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", "99999999")
				w.Header().Set("Content-Range", "bytes 0-9/10")
				w.Header().Set("ETag", `"upstream"`)
				_, _ = io.WriteString(w, tt.body())
			}))
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)

			client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
			resp, err := client.Get(srv.URL + "/v1.53/containers/json")
			if err != nil {
				t.Fatalf("GET generated error: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read generated error: %v", err)
			}
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusBadGateway, body)
			}
			for _, name := range []string{"Content-Encoding", "Content-Range", "ETag"} {
				if got := resp.Header.Get(name); got != "" {
					t.Errorf("%s = %q, want empty", name, got)
				}
			}
			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode generated error JSON: %v; body: %q", err, body)
			}
			if payload["message"] == "" {
				t.Fatalf("generated error payload = %#v, want message", payload)
			}
		})
	}
}

// TestFilterWriterFlushFilteredRefusesNonArrayBody is the fail-closed
// regression for flushFiltered's decode guard. A 2xx list response that is not
// a JSON array used to be forwarded verbatim, so any body the pattern filter
// could not walk reached the client with none of its contents ever checked
// against the policy. Every shape below has to end in an error and an
// uncommitted response, which is what lets filterResponseThroughWriter answer
// 502 instead.
func TestFilterWriterFlushFilteredRefusesNonArrayBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "object", body: `{"Names":["/hidden"],"Image":"secret"}`},
		{name: "null", body: `null`},
		{name: "string", body: `"a string"`},
		{name: "number", body: `42`},
		{name: "bool", body: `true`},
		{name: "empty", body: ``},
		{name: "whitespace only", body: "  \n\t"},
		{name: "not json at all", body: `<html>daemon error page</html>`},
		{name: "array of arrays opened as object", body: `{"Containers":[{"Names":["/hidden"]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			fw := newPatternFilterWriter(rec)
			t.Cleanup(fw.release)
			fw.WriteHeader(http.StatusOK)
			_, _ = fw.Write([]byte(tt.body))

			err := fw.flushFiltered("/containers/json", makePatternPolicy(t, "*"))
			if err == nil {
				t.Fatalf("flushFiltered() = nil, want an error for a non-array body %q", tt.body)
			}
			if fw.headerWritten {
				t.Fatal("flushFiltered() committed a response for a body it refused")
			}
			if got := rec.Body.String(); got != "" {
				t.Fatalf("refused body reached the client: %q", got)
			}
		})
	}
}

// TestPatternListNonArrayResponseFailsClosed drives the same refusal through
// the whole middleware for both list endpoints the pattern filter covers, and
// pins the client-visible outcome: a 502 whose body carries none of the
// upstream bytes, audited under the shared response-filter reason code.
func TestPatternListNonArrayResponseFailsClosed(t *testing.T) {
	t.Parallel()
	const secret = "container-the-policy-never-checked"
	for _, path := range []string{"/v1.53/containers/json", "/v1.53/images/json", "/v5.8.1/libpod/containers/json", "/v5.8.1/libpod/images/json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"Names":["/`+secret+`"]}`)
			})
			handler := middlewareWithDeps(testVisibilityLogger(),
				Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("upstream body leaked into the refusal: %s", rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeVisibilityPolicyLookupFailed {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyLookupFailed)
			}
		})
	}
}

// TestPatternListWarnModeStillFailsClosedOnNonArrayBody pins that the refusal
// is not a policy verdict warn mode stages. Every other response-side control
// in this package applies regardless of rollout mode, and this one decides
// whether an unparseable body leaves the proxy at all.
func TestPatternListWarnModeStillFailsClosedOnNonArrayBody(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"not":"an array"}`)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	meta := &logging.RequestMeta{RolloutMode: "warn"}
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d under warn mode; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

// TestPatternListHeadRequestNotIntercepted is the counterpart of
// TestSystemDataUsageHeadRequestNotIntercepted: a HEAD carries no body, so the
// pattern response filter never runs on one. Without the GET gate the empty
// buffer would hit flushFiltered's decode guard and turn a legitimate HEAD
// into a 502.
func TestPatternListHeadRequestNotIntercepted(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodHead, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Length"); got != "4096" {
		t.Fatalf("Content-Length = %q, want the upstream's 4096 untouched", got)
	}
}
