package visibility_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/ownership"
	"github.com/codeswhat/sockguard/app/internal/visibility"
)

// nestedSystemDFUpstream is a /system/df report whose three containers differ
// on exactly one axis each: the first passes both layers, the second is
// another owner's, the third is this owner's but outside the visibility
// selector.
const nestedSystemDFUpstream = `{"ContainerUsage":{"ActiveCount":3,"TotalCount":3,"Items":[
  {"Id":"keep-me","Names":["/keep-me"],"Image":"nginx","Labels":{"` + ownership.DefaultLabelKey + `":"team-a","tier":"prod"}},
  {"Id":"other-owner","Names":["/other-owner"],"Image":"nginx","Labels":{"` + ownership.DefaultLabelKey + `":"team-b","tier":"prod"}},
  {"Id":"other-tier","Names":["/other-tier"],"Image":"nginx","Labels":{"` + ownership.DefaultLabelKey + `":"team-a","tier":"dev"}}
]}}`

// failingRoundTripper stands in for the inspector transport neither layer
// should reach on /system/df. A resource inspect here would be a bug in the
// route dispatch rather than in the decode, so it fails loudly.
type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no resource inspect should reach the upstream on /system/df")
}

func gzipForNestedTest(t *testing.T, body string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// nestedHandler composes the two layers the way internal/cmd's chain does:
// visibility wraps ownership, so a response passes through the owner filter
// first and the visibility filter second.
func nestedHandler(t *testing.T, upstream http.Handler) http.Handler {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	owner := ownership.MiddlewareWithRoundTripper(failingRoundTripper{}, logger, ownership.Options{Owner: "team-a"})
	visible := visibility.MiddlewareWithRoundTripper(failingRoundTripper{}, logger, visibility.Options{
		VisibleResourceLabels: []string{"tier=prod"},
	})
	return visible(owner(upstream))
}

// TestNestedFiltersDecodeAGzippedSystemDataUsageOnce is the composition both
// layers ship in. They share one header map, so the owner filter's decode and
// header clear have to leave the visibility filter looking at identity bytes:
// a second decode attempt over the plaintext the first one produced would fail
// on the missing gzip magic and turn a correct 200 into a 502.
func TestNestedFiltersDecodeAGzippedSystemDataUsageOnce(t *testing.T) {
	t.Parallel()

	raw := gzipForNestedTest(t, nestedSystemDFUpstream)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"upstream"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	rec := httptest.NewRecorder()
	nestedHandler(t, upstream).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "keep-me") {
		t.Errorf("the container both layers allow is missing: %s", body)
	}
	for _, hidden := range []string{"other-owner", "other-tier"} {
		if strings.Contains(body, hidden) {
			t.Errorf("%q survived the nested filters: %s", hidden, body)
		}
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want it dropped with the compressed body", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d for the rewritten body", got, len(body))
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Errorf("ETag = %q, want the upstream validator cleared off the rewritten body", got)
	}
}

// TestNestedFiltersFailClosedOnAnUndecodableSystemDataUsage pins that the
// inner layer's refusal reaches the client intact. The owner filter answers
// the 502 into the visibility filter's buffer, which forwards a non-2xx
// verbatim, so the status and the reason the inner layer recorded are what
// goes out.
func TestNestedFiltersFailClosedOnAnUndecodableSystemDataUsage(t *testing.T) {
	t.Parallel()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("brotli bytes neither layer can read"))
	})

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	nestedHandler(t, upstream).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want it cleared off the refusal", got)
	}
	if strings.Contains(rec.Body.String(), "brotli bytes") {
		t.Fatalf("the undecodable upstream body reached the client: %s", rec.Body.String())
	}
	if meta.ReasonCode == "" {
		t.Fatalf("meta.ReasonCode is empty, want the refusal recorded")
	}
}
