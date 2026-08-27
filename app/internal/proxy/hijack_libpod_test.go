package proxy

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

// TestIsHijackEndpointLibpod covers #148's libpod routes:
// /libpod/containers/{id}/attach and
// /libpod/exec/{id}/start must upgrade exactly like their Docker-compat
// counterparts, including through a three-part Podman semver version prefix.
func TestIsHijackEndpointLibpod(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		// Positive cases.
		{"POST", "/libpod/containers/abc123/attach", true},
		{"POST", "/libpod/exec/abc123/start", true},
		// With a Docker-style two-part version prefix.
		{"POST", "/v1.45/libpod/containers/abc123/attach", true},
		{"POST", "/v1.45/libpod/exec/abc123/start", true},
		// With Podman's three-part semver version prefix (#148).
		{"POST", "/v5.0.0/libpod/containers/abc123/attach", true},
		{"POST", "/v4.9.3/libpod/exec/abc123/start", true},
		// Negative: wrong method.
		{"GET", "/libpod/containers/abc123/attach", false},
		{"PUT", "/libpod/exec/abc123/start", false},
		// Negative: wrong path within the libpod namespace.
		{"POST", "/libpod/containers/abc123/start", false},
		{"POST", "/libpod/exec/abc123/resize", false},
		{"POST", "/libpod/containers/attach", false},
		{"POST", "/libpod/exec/start", false},
		// Negative: not actually the libpod namespace.
		{"POST", "/libpodxyz/containers/abc123/attach", false},
		{"POST", "/LIBPOD/containers/abc123/attach", false},
		// Negative: other libpod endpoints.
		{"POST", "/libpod/containers/create", false},
		{"POST", "/libpod/pods/create", false},
		{"POST", "/libpod/play/kube", false},
		{"GET", "/libpod/info", false},
	}

	for _, tt := range tests {
		name := tt.method + " " + tt.path
		t.Run(name, func(t *testing.T) {
			got := isHijackEndpoint(tt.method, tt.path)
			if got != tt.want {
				t.Errorf("isHijackEndpoint(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHijackEndpointLibpodDoesNotAllocate(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "libpod_attach", method: http.MethodPost, path: "/libpod/containers/abc123/attach"},
		{name: "libpod_versioned_exec_start", method: http.MethodPost, path: "/v5.0.0/libpod/exec/abc123/start"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !isHijackEndpoint(tt.method, tt.path) {
				t.Fatalf("isHijackEndpoint(%q, %q) = false, want true", tt.method, tt.path)
			}

			allocs := testing.AllocsPerRun(1000, func() {
				isHijackEndpoint(tt.method, tt.path)
			})

			if allocs > 0 {
				t.Fatalf("isHijackEndpoint(%q, %q) allocated %.0f times, want 0", tt.method, tt.path, allocs)
			}
		})
	}
}

// TestHijackFilterParity pins the normalization boundary between proxy and
// filter. The proxy must normalize versioned paths before calling the shared
// filter predicate.
func TestHijackFilterParity(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		// Docker-compat hijack endpoints.
		{"POST", "/containers/abc123/attach"},
		{"POST", "/exec/abc123/start"},
		{"POST", "/v1.45/containers/abc123/attach"},
		{"POST", "/v1.45/exec/abc123/start"},
		// libpod hijack endpoints (#148).
		{"POST", "/libpod/containers/abc123/attach"},
		{"POST", "/libpod/exec/abc123/start"},
		{"POST", "/v5.0.0/libpod/containers/abc123/attach"},
		{"POST", "/v5.0.0/libpod/exec/abc123/start"},
		// Paths that must NOT be hijack candidates on either side.
		{"GET", "/containers/abc123/attach"},
		{"POST", "/containers/abc123/exec"},
		{"POST", "/containers/create"},
		{"POST", "/libpod/containers/abc123/exec"},
		{"POST", "/libpod/containers/create"},
		{"POST", "/libpod/pods/create"},
		{"POST", "/libpod/play/kube"},
		{"GET", "/libpod/exec/abc123/start"},
		{"POST", "/containers/abc123/start"},
		{"POST", "/exec/abc123/resize"},
	}

	for _, tt := range tests {
		name := tt.method + " " + tt.path
		t.Run(name, func(t *testing.T) {
			normalized := filter.NormalizePath(tt.path)
			hijackWant := isHijackEndpoint(tt.method, tt.path)
			filterWant := filter.IsHijackCandidatePath(tt.method, normalized)
			if hijackWant != filterWant {
				t.Fatalf("parity mismatch for %s %s (normalized %q): hijack layer = %v, filter layer = %v",
					tt.method, tt.path, normalized, hijackWant, filterWant)
			}
		})
	}
}

// TestHandleHijack_LibpodExecStartPreservesVersionPrefix is the #194
// regression test. Real Podman requires a version prefix
// (/v5.x.y/libpod/...) on every route except the bare _ping — unlike
// dockerd, which accepts unversioned paths. The hijack layer strips that
// prefix internally for endpoint matching and
// rule evaluation, but it must NOT forward the stripped path upstream: doing
// so reaches Podman without its version prefix and 404s, breaking libpod
// exec-start (interactive/attached exec) even when policy allows it. The
// non-hijack reverse-proxy path (proxy.go's Rewrite) never had this bug — it
// only touches Scheme/Host and forwards the client's original URL verbatim.
// This test pins the hijack path to the same behavior, table-driven so a
// future Podman version-path shape is a local case addition. The last case
// also covers the RawPath/%2F regression (see hijack_test.go's
// TestNewUpstreamHijackRequest_PreservesRawPathForEncodedSegments for the
// unit-level half): an encoded exec ID segment must survive onto the wire
// unchanged, not just the version prefix.
func TestHandleHijack_LibpodExecStartPreservesVersionPrefix(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		wantPath    string
		wantQuery   string
		wantReqLine string
	}{
		{
			name:        "three-part Podman semver prefix",
			target:      "http://client.example/v5.0.0/libpod/exec/abc123/start?detach=0",
			wantPath:    "/v5.0.0/libpod/exec/abc123/start",
			wantQuery:   "detach=0",
			wantReqLine: "POST /v5.0.0/libpod/exec/abc123/start?detach=0 HTTP/1.1",
		},
		{
			name:        "two-part Docker-style prefix on the libpod route",
			target:      "http://client.example/v1.45/libpod/exec/abc123/start?detach=0",
			wantPath:    "/v1.45/libpod/exec/abc123/start",
			wantQuery:   "detach=0",
			wantReqLine: "POST /v1.45/libpod/exec/abc123/start?detach=0 HTTP/1.1",
		},
		{
			name:        "encoded exec ID segment stays encoded on the wire",
			target:      "http://client.example/v5.0.0/libpod/exec/abc%2F123/start?detach=0",
			wantPath:    "/v5.0.0/libpod/exec/abc/123/start", // decoded form, as parsed off the wire
			wantQuery:   "detach=0",
			wantReqLine: "POST /v5.0.0/libpod/exec/abc%2F123/start?detach=0 HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreHijackHooks(t)

			var rawRequest bytes.Buffer
			dialUpstreamHook = func(network, address string) (net.Conn, error) {
				return &funcConn{
					writeFn: func(p []byte) (int, error) {
						return rawRequest.Write(p)
					},
				}, nil
			}
			readResponseHook = func(*bufio.Reader, *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"message":"bad request"}`)),
				}, nil
			}

			req := httptest.NewRequest(http.MethodPost, tt.target, nil)
			req.Host = "client.example"

			rec := httptest.NewRecorder()
			handleHijack(rec, req, "/unused.sock", slog.New(slog.NewTextHandler(io.Discard, nil)))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			gotReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawRequest.Bytes())))
			if err != nil {
				t.Fatalf("read forwarded request: %v", err)
			}
			defer gotReq.Body.Close()

			if gotReq.Host != "docker" {
				t.Fatalf("Host = %q, want %q", gotReq.Host, "docker")
			}
			// The bug: the hijack layer forwarded filter.NormalizePath's
			// version-stripped path instead of the client's original,
			// versioned path. Podman needs the version prefix.
			if gotReq.URL.Path != tt.wantPath {
				t.Fatalf("URL.Path = %q, want %q (version prefix must survive the hijack upstream leg)", gotReq.URL.Path, tt.wantPath)
			}
			if gotReq.URL.RawQuery != tt.wantQuery {
				t.Fatalf("URL.RawQuery = %q, want %q", gotReq.URL.RawQuery, tt.wantQuery)
			}

			rawForwarded := rawRequest.String()
			if !strings.Contains(rawForwarded, tt.wantReqLine) {
				t.Fatalf("forwarded request target = %q, want it to contain %q:\n%s", rawForwarded, tt.wantReqLine, rawForwarded)
			}
		})
	}
}
