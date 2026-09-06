package ownership

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/proxy"
)

// gzipForTest compresses body the way an intermediary that ignores
// Accept-Encoding: identity would.
func gzipForTest(t *testing.T, body string) []byte {
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

// capturingOwnershipLogger returns a logger and the buffer it writes to, so a
// test can assert on the record the middleware emits rather than only on the
// status it returns.
func capturingOwnershipLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// encodedUpstream answers with a fixed Content-Encoding whatever the request
// asked for, which is the intermediary this decode exists for.
func encodedUpstream(status int, coding string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if coding != "" {
			w.Header().Set("Content-Encoding", coding)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// gzipRecordingTransport stands in for the Docker socket behind the reverse
// proxy, keeps the request headers that reached the wire, and compresses the
// response regardless of what they asked for.
type gzipRecordingTransport struct {
	seen http.Header
	body []byte
}

func (t *gzipRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.seen = req.Header.Clone()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{"gzip"},
			"ETag":             []string{`"upstream"`},
		},
		Body:    io.NopCloser(bytes.NewReader(t.body)),
		Request: req,
	}, nil
}

// TestSystemDataUsageFiltersGzippedUpstreamBody drives the composed shape —
// ownership middleware over the reverse proxy — so the identity pin is in the
// picture and the upstream ignores it anyway. Before this the compressed bytes
// went straight into the owner classifier and the read became a 502, which is
// fail-closed but also means the one host-inventory endpoint owner isolation
// can scope is unusable behind anything that compresses.
func TestSystemDataUsageFiltersGzippedUpstreamBody(t *testing.T) {
	t.Parallel()

	transport := &gzipRecordingTransport{body: gzipForTest(t, modernSystemDFUpstream)}
	upstream := proxy.NewWithTransport(transport, testLogger(), proxy.Options{})
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
		fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := transport.seen.Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("daemon saw Accept-Encoding = %q, want identity", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "team-b") {
		t.Fatalf("another owner's resources leaked out of the compressed inventory: %s", body)
	}
	if !strings.Contains(body, "c-a") {
		t.Fatalf("this owner's container missing from the filtered inventory: %s", body)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want it dropped with the compressed body", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length = %q, want %d for the rewritten body", got, len(body))
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want the upstream validator cleared off the rewritten body", got)
	}
}

// TestSystemDataUsageDecodesBothUpstreamShapes covers the decode against both
// /system/df bodies the engines produce, so the fix is not pinned to whichever
// one the first test happened to use.
func TestSystemDataUsageDecodesBothUpstreamShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		coding string
		body   string
	}{
		{name: "modern shape", body: modernSystemDFUpstream},
		{name: "legacy shape", body: legacySystemDFUpstream},
		{name: "x-gzip spelling", coding: "x-gzip", body: modernSystemDFUpstream},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coding := tt.coding
			if coding == "" {
				coding = "gzip"
			}
			upstream := encodedUpstream(http.StatusOK, coding, gzipForTest(t, tt.body))
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

			req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "team-b") {
				t.Errorf("another owner's resources leaked out of the compressed inventory: %s", body)
			}
			if !strings.Contains(body, "c-a") {
				t.Errorf("this owner's container missing from the filtered inventory: %s", body)
			}
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("Content-Encoding = %q, want it dropped with the compressed body", got)
			}
			if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
				t.Errorf("Content-Length = %q, want %d for the rewritten body", got, len(body))
			}
		})
	}
}

// TestSystemDataUsageFailsClosedOnUndecodableBody keeps the fail-closed
// direction for everything the decode cannot turn into bytes the owner
// classifier reads. A coding this build does not implement is refused rather
// than forwarded unread, and the log names it so an operator can see what the
// upstream actually sent.
func TestSystemDataUsageFailsClosedOnUndecodableBody(t *testing.T) {
	t.Parallel()

	full := gzipForTest(t, modernSystemDFUpstream)
	tests := []struct {
		name       string
		coding     string
		body       []byte
		wantLogged string
	}{
		// The text handler escapes the quotes the error puts around the
		// coding, so the expectation carries them escaped too.
		{name: "brotli", coding: "br", body: []byte("whatever"), wantLogged: `Content-Encoding \"br\"`},
		{name: "zstd", coding: "zstd", body: []byte("whatever"), wantLogged: `Content-Encoding \"zstd\"`},
		{name: "truncated gzip stream", coding: "gzip", body: full[:len(full)-4], wantLogged: "gzip"},
		{name: "gzip header only", coding: "gzip", body: full[:6], wantLogged: "gzip"},
		{name: "empty body under a gzip claim", coding: "gzip", body: nil, wantLogged: "gzip"},
		{name: "claims gzip, is not", coding: "gzip", body: []byte(`{"LayersSize":0}`), wantLogged: "gzip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, logs := capturingOwnershipLogger()
			upstream := encodedUpstream(http.StatusOK, tt.coding, tt.body)
			handler := middlewareWithDeps(logger, Options{Owner: "team-a"},
				fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeOwnerResponseFilterFail {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerResponseFilterFail)
			}
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want it cleared off the refusal", got)
			}
			if !strings.Contains(logs.String(), tt.wantLogged) {
				t.Fatalf("log = %s, want it to name the coding %s", logs.String(), tt.wantLogged)
			}
		})
	}
}

// TestSystemDataUsageRefusesAnExpandingGzipBody is the gzip-bomb guard on the
// side that matters once a body can be compressed: the buffered cap counts the
// bytes that arrived, so a small archive that expands past the limit has to be
// caught by the decoded size instead. It carries the response-too-large reason
// code rather than the filter-failure one, because it is the same verdict the
// raw-size branch returns, reached one step later.
func TestSystemDataUsageRefusesAnExpandingGzipBody(t *testing.T) {
	t.Parallel()

	raw := gzipForTest(t, strings.Repeat("a", filter.MaxResponseBodyBytes+1))
	if int64(len(raw)) > filter.MaxResponseBodyBytes {
		t.Fatalf("compressed payload is %d bytes, want it under the cap so only the decoded size can trip it", len(raw))
	}

	upstream := encodedUpstream(http.StatusOK, "gzip", raw)
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
	if meta.ReasonCode != reasonCodeOwnerResponseTooLarge {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerResponseTooLarge)
	}
	if got := rec.Body.String(); !strings.Contains(got, ownerResponseTooLargeMessage) {
		t.Fatalf("body = %s, want the size refusal", got)
	}
}

// TestSystemDataUsageCompressedResponsesNotRewrittenAreUntouched pins the
// branches that commit before the decode runs. A HEAD has no body to decode, a
// 304 is refused whatever it is encoded with, and a non-2xx is forwarded as it
// arrived — so its Content-Encoding still describes the bytes the client gets.
func TestSystemDataUsageCompressedResponsesNotRewrittenAreUntouched(t *testing.T) {
	t.Parallel()

	t.Run("HEAD drops the compressed body and the daemon's metadata", func(t *testing.T) {
		t.Parallel()

		gzipped := gzipForTest(t, modernSystemDFUpstream)
		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("ETag", `"upstream"`)
			w.Header().Set("Content-Length", strconv.Itoa(len(gzipped)))
			w.WriteHeader(http.StatusOK)
		})
		handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
			fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

		req := httptest.NewRequest(http.MethodHead, "/v1.53/system/df", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("body = %q, want nothing relayed on a HEAD", rec.Body.String())
		}
		for _, name := range []string{"Content-Encoding", "Content-Length", "ETag"} {
			if got := rec.Header().Get(name); got != "" {
				t.Errorf("%s = %q, want the upstream representation metadata cleared", name, got)
			}
		}
	})

	t.Run("304 is still refused when it is compressed", func(t *testing.T) {
		t.Parallel()

		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
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
	})

	t.Run("a compressed error body is forwarded with its coding", func(t *testing.T) {
		t.Parallel()

		errorBody := gzipForTest(t, `{"message":"daemon is unwell"}`)
		upstream := encodedUpstream(http.StatusInternalServerError, "gzip", errorBody)
		handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"},
			fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

		req := httptest.NewRequest(http.MethodGet, "/v1.53/system/df", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d; body: %q", rec.Code, http.StatusInternalServerError, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), errorBody) {
			t.Fatalf("body was rewritten, want the compressed error forwarded untouched")
		}
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip preserved alongside the untouched body", got)
		}
	})
}
