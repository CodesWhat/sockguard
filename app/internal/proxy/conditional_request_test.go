package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// conditionalRecordingTransport stands in for the Docker socket and keeps the
// request headers the proxy actually put on the wire.
type conditionalRecordingTransport struct {
	seen http.Header
}

func (t *conditionalRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.seen = req.Header.Clone()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`[]`)),
		Request:    req,
	}, nil
}

// TestProxyStripsConditionalRequestHeaders pins the single strip point. Every
// request the read-side filters act on reaches the daemon through this
// Rewrite, so this is where a client's revalidation is turned back into a
// full fetch the filters can inspect.
func TestProxyStripsConditionalRequestHeaders(t *testing.T) {
	t.Parallel()

	transport := &conditionalRecordingTransport{}
	rp := NewWithTransport(transport, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req.Header.Set("If-None-Match", `"upstream-etag"`)
	req.Header.Set("If-Modified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	req.Header.Set("If-Match", `"upstream-etag"`)
	req.Header.Set("If-Unmodified-Since", "Wed, 03 Sep 2026 10:00:00 GMT")
	req.Header.Set("If-Range", `"upstream-etag"`)
	req.Header.Set("X-Registry-Auth", "keep-me")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range"} {
		if got := transport.seen.Get(name); got != "" {
			t.Errorf("upstream saw %s = %q, want it stripped", name, got)
		}
	}
	if got := transport.seen.Get("X-Registry-Auth"); got != "keep-me" {
		t.Errorf("upstream saw X-Registry-Auth = %q, want the unrelated header forwarded", got)
	}
	// The strip happens on ReverseProxy's outbound clone. The inbound request
	// is what the access and audit logs describe, so it has to still say what
	// the client actually sent.
	if got := req.Header.Get("If-None-Match"); got != `"upstream-etag"` {
		t.Errorf("inbound If-None-Match = %q, want the client's request left intact for the logs", got)
	}
}
