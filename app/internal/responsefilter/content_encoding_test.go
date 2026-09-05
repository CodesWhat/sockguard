package responsefilter

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	requestfilter "github.com/codeswhat/sockguard/app/internal/filter"
)

// gzipBytesForTest compresses body the way an upstream that ignores
// Accept-Encoding: identity would.
func gzipBytesForTest(t *testing.T, body string) []byte {
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

// newEncodedResponseForTest builds an upstream response whose body carries the
// given raw bytes under the given Content-Encoding, with the Content-Length
// the daemon would have announced for them.
func newEncodedResponseForTest(t *testing.T, method, path, coding string, raw []byte) *http.Response {
	t.Helper()

	resp := newResponseForTest(t, method, path, "")
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
	if coding != "" {
		resp.Header.Set("Content-Encoding", coding)
	}
	return resp
}

// TestModifyResponse_DecodesGzipOnRedactedInspectRoute is the whole-body
// decode path: an upstream that compressed anyway used to reach the JSON
// decoder as gzip magic bytes and fail the read closed.
func TestModifyResponse_DecodesGzipOnRedactedInspectRoute(t *testing.T) {
	t.Parallel()

	const upstream = `{"Id":"abc123","Config":{"Env":["SECRET=shh"]}}`
	raw := gzipBytesForTest(t, upstream)
	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "gzip", raw)

	filter := New(Options{RedactContainerEnv: true})
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if strings.Contains(string(body), "SECRET=shh") {
		t.Fatalf("body = %s, want the env redacted", body)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want it dropped with the compressed body", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length = %q, want %d for the uncompressed body", got, len(body))
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("resp.ContentLength = %d, want %d", resp.ContentLength, len(body))
	}
}

// TestModifyResponse_DecodesGzipOnRedactedListRoute covers the other body
// reader. streamArrayResponse consumes resp.Body through its own decoder
// rather than withResponseBody, so it needs its own decode.
func TestModifyResponse_DecodesGzipOnRedactedListRoute(t *testing.T) {
	t.Parallel()

	const upstream = `[{"Id":"abc123","Mounts":[{"Source":"/srv/host-secret"}]}]`
	raw := gzipBytesForTest(t, upstream)
	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/json", "gzip", raw)

	filter := New(Options{RedactMountPaths: true})
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if strings.Contains(string(body), "/srv/host-secret") {
		t.Fatalf("body = %s, want the mount source redacted", body)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want it dropped with the compressed body", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length = %q, want %d for the uncompressed body", got, len(body))
	}
}

// TestModifyResponse_LeavesGzipUntouchedOnUnfilteredRoute pins that the
// decode is scoped to what the filter rewrites. A route no handler claims
// keeps the daemon's compressed bytes and its Content-Encoding, because
// nothing here needs to read them.
func TestModifyResponse_LeavesGzipUntouchedOnUnfilteredRoute(t *testing.T) {
	t.Parallel()

	raw := gzipBytesForTest(t, `[{"Id":"sha256:aa"}]`)
	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/images/json", "gzip", raw)

	filter := New(Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
		RedactHostTopology:    true,
	})
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(body, raw) {
		t.Fatalf("body was rewritten, want the compressed bytes passed through untouched")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip preserved alongside the untouched body", got)
	}
}

// TestModifyResponse_LeavesGzipUntouchedWhenRouteOptionDisabled is the same
// property one layer in: the route has a handler, but no enabled option can
// rewrite it, so the handler returns before reading and the compressed body
// survives.
func TestModifyResponse_LeavesGzipUntouchedWhenRouteOptionDisabled(t *testing.T) {
	t.Parallel()

	raw := gzipBytesForTest(t, `{"Volumes":[{"Name":"data","Mountpoint":"/var/lib/docker/volumes/data/_data"}]}`)
	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/volumes", "gzip", raw)

	filter := New(Options{RedactNetworkTopology: true})
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(body, raw) {
		t.Fatalf("body was rewritten, want the compressed bytes passed through untouched")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip preserved alongside the untouched body", got)
	}
}

// TestModifyResponse_IdentityContentEncodingUnchanged pins that an explicit
// identity header reads exactly as an absent one does.
func TestModifyResponse_IdentityContentEncodingUnchanged(t *testing.T) {
	t.Parallel()

	const upstream = `{"Id":"abc123","Config":{"Env":["SECRET=shh"]}}`
	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "identity", []byte(upstream))

	filter := New(Options{RedactContainerEnv: true})
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatalf("ModifyResponse() error = %v, want nil", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if strings.Contains(string(body), "SECRET=shh") {
		t.Fatalf("body = %s, want the env redacted", body)
	}
}

// TestModifyResponse_RejectsUnsupportedContentEncoding keeps the fail-closed
// direction for the codings this package cannot decode. Forwarding them
// unread would redact nothing on a route policy says must be redacted.
func TestModifyResponse_RejectsUnsupportedContentEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		coding []string
	}{
		{name: "brotli", coding: []string{"br"}},
		{name: "zstd", coding: []string{"zstd"}},
		{name: "double gzip in one value", coding: []string{"gzip, gzip"}},
		{name: "double gzip in two header lines", coding: []string{"gzip", "gzip"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "", []byte("whatever"))
			for _, coding := range tt.coding {
				resp.Header.Add("Content-Encoding", coding)
			}

			filter := New(Options{RedactContainerEnv: true})
			err := filter.ModifyResponse(resp)
			if !errors.Is(err, ErrResponseRejected) {
				t.Fatalf("ModifyResponse() error = %v, want ErrResponseRejected", err)
			}
			if !strings.Contains(err.Error(), "Content-Encoding") {
				t.Fatalf("error = %v, want it to name the coding it refused", err)
			}
		})
	}
}

// TestModifyResponse_RejectsMalformedGzipBody covers the header that claims
// gzip over bytes that are not.
func TestModifyResponse_RejectsMalformedGzipBody(t *testing.T) {
	t.Parallel()

	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "gzip", []byte(`{"Id":"abc123"}`))

	filter := New(Options{RedactContainerEnv: true})
	if err := filter.ModifyResponse(resp); !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want ErrResponseRejected", err)
	}
}

// TestModifyResponse_GzipBodyRespectsDecompressedSizeLimit pins the cap on
// the side that matters once a body can be compressed: MaxResponseBodyBytes
// counts decoded bytes, so a small archive that expands past the limit is
// refused rather than buffered whole.
func TestModifyResponse_GzipBodyRespectsDecompressedSizeLimit(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	buf.WriteString(`{"Id":"`)
	buf.Write(bytes.Repeat([]byte("a"), requestfilter.MaxResponseBodyBytes))
	buf.WriteString(`"}`)
	raw := gzipBytesForTest(t, buf.String())
	if int64(len(raw)) > requestfilter.MaxResponseBodyBytes {
		t.Fatalf("compressed payload is %d bytes, want it under the cap so only the decoded size can trip it", len(raw))
	}

	resp := newEncodedResponseForTest(t, http.MethodGet, "/v1.53/containers/abc123/json", "gzip", raw)

	filter := New(Options{RedactContainerEnv: true})
	err := filter.ModifyResponse(resp)
	if !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("ModifyResponse() error = %v, want ErrResponseRejected", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want the size-limit rejection", err)
	}
}

// TestPinIdentityAcceptEncoding covers the header write on its own. The
// end-to-end assertion that the daemon sees it lives in internal/proxy.
func TestPinIdentityAcceptEncoding(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set("Accept-Encoding", "gzip, br;q=0.9")
	PinIdentityAcceptEncoding(header)

	if got := header.Values("Accept-Encoding"); len(got) != 1 || got[0] != "identity" {
		t.Fatalf("Accept-Encoding = %#v, want exactly [identity]", got)
	}
}
