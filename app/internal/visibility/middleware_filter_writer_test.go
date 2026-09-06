package visibility

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// TestFilterWriterFlushFilteredRefuses304 asserts that a 304 Not Modified is
// refused rather than forwarded. It used to be relayed as a bodiless 304,
// which confirmed whatever the client had cached — a list produced under an
// earlier policy, or none. flushFiltered must leave the response uncommitted
// so filterResponseThroughWriter can substitute the 502.
func TestFilterWriterFlushFilteredRefuses304(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	fw := newPatternFilterWriter(rec)

	// Simulate upstream writing a 304 with stale buffered bytes.
	fw.WriteHeader(http.StatusNotModified)
	_, _ = fw.Write([]byte("stale-body-that-must-not-be-forwarded"))

	policy := makePatternPolicy(t, "mycontainer")
	err := fw.flushFiltered("/containers/json", policy)
	if !errors.Is(err, errNotModifiedUnfilterable) {
		t.Fatalf("flushFiltered error = %v, want errNotModifiedUnfilterable", err)
	}
	if fw.headerWritten {
		t.Fatal("headerWritten = true, want false so the caller can write the 502")
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("body = %q, want nothing forwarded for a refused 304", body)
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

// TestPatternListHeadDropsUpstreamRepresentation is the counterpart of
// TestSystemDataUsageHeadStripsUpstreamRepresentation. The pattern response
// filter still never runs on a HEAD — an empty buffer would hit
// flushFiltered's decode guard and turn a legitimate HEAD into a 502 — but the
// HEAD is no longer forwarded untouched either: the daemon's Content-Length
// and ETag are computed over the unfiltered list, so the length counts the
// containers and images the policy hides and the ETag validates them. Every
// pattern-filtered list route is covered, not only /containers/json.
func TestPatternListHeadDropsUpstreamRepresentation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		opts   Options
	}{
		{name: "container list", target: "/v1.53/containers/json", opts: Options{NamePatterns: []string{"visible-*"}}},
		{name: "libpod container list", target: "/v5.8.1/libpod/containers/json", opts: Options{NamePatterns: []string{"visible-*"}}},
		{name: "image list", target: "/v1.53/images/json", opts: Options{ImagePatterns: []string{"nginx*"}}},
		{name: "libpod image list", target: "/v5.8.1/libpod/images/json", opts: Options{ImagePatterns: []string{"nginx*"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "4096")
				w.Header().Set("Content-Type", "application/json")
				setUpstreamRepresentationHeaders(w.Header())
				w.WriteHeader(http.StatusOK)
			})
			handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{})(upstream)

			req := httptest.NewRequest(http.MethodHead, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Length"); got != "" {
				t.Errorf("Content-Length = %q, want it cleared so the hidden items are not counted", got)
			}
			for _, name := range upstreamRepresentationHeaders {
				if got := rec.Header().Get(name); got != "" {
					t.Errorf("%s = %q, want it cleared on a HEAD the policy scopes", name, got)
				}
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want the media type kept", got)
			}
			if body := rec.Body.String(); body != "" {
				t.Errorf("body = %q, want nothing forwarded for a HEAD", body)
			}
		})
	}
}

// TestPatternListHeadWithoutPatternAxesIsUntouched is the control: with no
// pattern axis the response filter never runs, the label selectors go upstream
// on the request, and the daemon's length already describes the scoped list.
// There is nothing to hide, so the HEAD is forwarded as it always was.
func TestPatternListHeadWithoutPatternAxesIsUntouched(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(upstream)

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

// upstreamRepresentationHeaders is the set every rewriting path has to strip.
// It mirrors responsefilter.ClearUpstreamRepresentationHeaders, spelled out
// here so a header quietly dropped from that list fails a test rather than
// silently stops being checked.
var upstreamRepresentationHeaders = []string{
	"Accept-Ranges",
	"Content-Digest",
	"Content-Encoding",
	"Content-Language",
	"Content-Location",
	"Content-MD5",
	"Content-Range",
	"Digest",
	"ETag",
	"Last-Modified",
	"Repr-Digest",
	"Trailer",
	"Transfer-Encoding",
}

// setUpstreamRepresentationHeaders makes an upstream response announce every
// representation header a rewrite has to invalidate.
func setUpstreamRepresentationHeaders(h http.Header) {
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Digest", "sha-256=:upstream:")
	h.Set("Content-Encoding", "identity")
	h.Set("Content-Language", "en")
	h.Set("Content-Location", "/v1.53/containers/json")
	h.Set("Content-MD5", "upstream-md5")
	h.Set("Content-Range", "bytes 0-99/100")
	h.Set("Digest", "sha-256=upstream")
	h.Set("ETag", `"upstream-etag"`)
	h.Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
	h.Set("Repr-Digest", "sha-256=:upstream:")
	h.Set("Trailer", "X-Upstream-Trailer")
	h.Set("Content-Length", "4096")
}

// TestPatternListRewriteClearsUpstreamRepresentationHeaders pins that a
// rewritten list body does not ship the daemon's metadata for the body it
// replaced. Content-Length was already corrected; ETag, Content-Encoding,
// Content-Range and the rest were not, so the client received a validator and
// an encoding describing bytes it never got. A caching client keyed on that
// ETag can serve the unfiltered list back later, and the ETag by itself
// fingerprints the resources the policy hid.
func TestPatternListRewriteClearsUpstreamRepresentationHeaders(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		setUpstreamRepresentationHeaders(w.Header())
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `[{"Names":["/visible-web"],"Image":"alpine"},{"Names":["/hidden-db"],"Image":"nginx"}]`)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hidden-db") {
		t.Fatalf("hidden container survived the filter: %s", rec.Body.String())
	}
	for _, name := range upstreamRepresentationHeaders {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q after a body rewrite, want cleared", name, got)
		}
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Fatalf("Content-Length = %q, want %q (the rewritten body's own length)", got, want)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want the upstream's application/json kept", got)
	}
}

// TestSystemDataUsageRewriteClearsUpstreamRepresentationHeaders is the same
// assertion for the other flush that reaches commitFilteredBody.
func TestSystemDataUsageRewriteClearsUpstreamRepresentationHeaders(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		setUpstreamRepresentationHeaders(w.Header())
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, modernSystemDFForTest)
	})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{VisibleResourceLabels: []string{"tier=prod"}}, visibilityDeps{})(upstream)

	rec := getSystemDFForTest(t, handler)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	for _, name := range upstreamRepresentationHeaders {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q after a body rewrite, want cleared", name, got)
		}
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Fatalf("Content-Length = %q, want %q (the rewritten body's own length)", got, want)
	}
}

// TestPatternListHeadOverRealServerSendsNoContentLength proves the claim the
// header clear rests on: with Content-Length deleted and no bytes written, Go
// does not synthesize one for a HEAD, so the client sees no length rather than
// a length of 0. httptest.NewRecorder never serializes headers, so this needs
// a real server and a real client.
func TestPatternListHeadOverRealServerSendsNoContentLength(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream))
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodHead, server.URL+"/v1.53/containers/json", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, ok := resp.Header["Content-Length"]; ok {
		t.Errorf("Content-Length = %v, want the header absent entirely", got)
	}
	if resp.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1 (unknown)", resp.ContentLength)
	}
	if got := resp.Header.Get("ETag"); got != "" {
		t.Errorf("ETag = %q, want it cleared", got)
	}
}

// TestPatternListHeadOverRealServerRefusesNotModified is the wire-level
// counterpart of TestVisibilityFiltersFailClosedOnNotModified's HEAD cases: it
// proves that when the upstream answers a HEAD with a recorded 304, the 502
// refusal body httpjson.Write produces never actually reaches the client, not
// just that the ResponseRecorder-based test never inspected it. Go's HEAD
// handling eats a handler's body writes on the wire; this pins that the
// refusal's JSON error body is exactly the write being eaten, over a real
// server and a real client.
func TestPatternListHeadOverRealServerRefusesNotModified(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusNotModified)
	})
	server := httptest.NewServer(middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream))
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodHead, server.URL+"/v1.53/containers/json", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("ETag"); got != "" {
		t.Errorf("ETag = %q, want the upstream validator cleared off the refusal", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want nothing forwarded for a HEAD refusal", body)
	}
}
