package visibility

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

// capturingVisibilityLogger returns a logger and the buffer it writes to, so a
// test can assert on the record the middleware emits rather than only on the
// status it returns.
func capturingVisibilityLogger() (*slog.Logger, *bytes.Buffer) {
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

// TestVisibilityListFiltersGzippedUpstreamBody drives the composed shape —
// visibility middleware over the reverse proxy — so the identity pin is in the
// picture and the upstream ignores it anyway. Before this the compressed bytes
// went straight into the list decoder and the read became a 502, which is
// fail-closed but also means a policy-scoped list endpoint is unusable behind
// anything that compresses.
func TestVisibilityListFiltersGzippedUpstreamBody(t *testing.T) {
	t.Parallel()

	transport := &gzipRecordingTransport{
		body: gzipForTest(t, `[{"Names":["/visible-web"],"Image":"nginx"},{"Names":["/secret-db"],"Image":"postgres"}]`),
	}
	upstream := proxy.NewWithTransport(transport, testVisibilityLogger(), proxy.Options{})
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
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
	if strings.Contains(body, "secret-db") {
		t.Fatalf("hidden container leaked out of the compressed list: %s", body)
	}
	if !strings.Contains(body, "visible-web") {
		t.Fatalf("visible container missing from the filtered list: %s", body)
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

// TestVisibilityFiltersDecodeGzippedUpstreamBody covers the same decode on
// every route this package rewrites a body on, including the /system/df
// report, which reaches it through a different flush step.
func TestVisibilityFiltersDecodeGzippedUpstreamBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		coding  string
		body    string
		opts    Options
		want    []string
		notWant []string
	}{
		{
			name:    "container list",
			target:  "/v1.53/containers/json",
			body:    `[{"Names":["/visible-web"],"Image":"nginx"},{"Names":["/secret-db"],"Image":"postgres"}]`,
			opts:    Options{NamePatterns: []string{"visible-*"}},
			want:    []string{"visible-web"},
			notWant: []string{"secret-db"},
		},
		{
			name:    "libpod container list",
			target:  "/v5.8.1/libpod/containers/json",
			body:    `[{"Names":["/visible-web"],"Image":"nginx"},{"Names":["/secret-db"],"Image":"postgres"}]`,
			opts:    Options{NamePatterns: []string{"visible-*"}},
			want:    []string{"visible-web"},
			notWant: []string{"secret-db"},
		},
		{
			name:    "image list",
			target:  "/v1.53/images/json",
			body:    `[{"RepoTags":["nginx:1"]},{"RepoTags":["postgres:16"]}]`,
			opts:    Options{ImagePatterns: []string{"nginx*"}},
			want:    []string{"nginx:1"},
			notWant: []string{"postgres:16"},
		},
		{
			name:    "libpod image list",
			target:  "/v5.8.1/libpod/images/json",
			body:    `[{"RepoTags":["nginx:1"]},{"RepoTags":["postgres:16"]}]`,
			opts:    Options{ImagePatterns: []string{"nginx*"}},
			want:    []string{"nginx:1"},
			notWant: []string{"postgres:16"},
		},
		{
			name:   "system data usage",
			target: "/v1.53/system/df",
			body: `{"ContainerUsage":{"Items":[` +
				`{"Id":"c-a","Names":["/web"],"Image":"nginx","Labels":{"tier":"prod"}},` +
				`{"Id":"c-b","Names":["/db"],"Image":"postgres","Labels":{"tier":"dev"}}]}}`,
			opts:    Options{VisibleResourceLabels: []string{"tier=prod"}},
			want:    []string{"c-a"},
			notWant: []string{"c-b"},
		},
		{
			name:    "x-gzip spelling",
			target:  "/v1.53/containers/json",
			coding:  "x-gzip",
			body:    `[{"Names":["/visible-web"],"Image":"nginx"},{"Names":["/secret-db"],"Image":"postgres"}]`,
			opts:    Options{NamePatterns: []string{"visible-*"}},
			want:    []string{"visible-web"},
			notWant: []string{"secret-db"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coding := tt.coding
			if coding == "" {
				coding = "gzip"
			}
			upstream := encodedUpstream(http.StatusOK, coding, gzipForTest(t, tt.body))
			handler := middlewareWithDeps(testVisibilityLogger(), tt.opts, visibilityDeps{})(upstream)

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Errorf("%q missing from the decoded body: %s", want, body)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(body, notWant) {
					t.Errorf("%q leaked out of the compressed body: %s", notWant, body)
				}
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

// TestVisibilityFiltersFailClosedOnUndecodableBody keeps the fail-closed
// direction for everything the decode cannot turn into bytes the policy walks.
// A coding this build does not implement is refused rather than forwarded
// unread, because forwarding it would mean applying no policy on a route that
// exists to apply one, and the log names the coding so an operator can see
// what the upstream actually sent.
func TestVisibilityFiltersFailClosedOnUndecodableBody(t *testing.T) {
	t.Parallel()

	full := gzipForTest(t, `[{"Names":["/visible-web"],"Image":"nginx"}]`)
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
		{name: "claims gzip, is not", coding: "gzip", body: []byte(`[{"Names":["/web"]}]`), wantLogged: "gzip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, logs := capturingVisibilityLogger()
			upstream := encodedUpstream(http.StatusOK, tt.coding, tt.body)
			handler := middlewareWithDeps(logger,
				Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

			meta := &logging.RequestMeta{}
			req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeVisibilityPolicyLookupFailed {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityPolicyLookupFailed)
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

// TestVisibilityFiltersRefuseAnExpandingGzipBody is the gzip-bomb guard on the
// side that matters once a body can be compressed: the buffered cap counts the
// bytes that arrived, so a small archive that expands past the limit has to be
// caught by the decoded size instead. It carries the response-too-large reason
// code rather than the filter-failure one, because it is the same verdict the
// raw-size branch returns, reached one step later.
func TestVisibilityFiltersRefuseAnExpandingGzipBody(t *testing.T) {
	t.Parallel()

	raw := gzipForTest(t, strings.Repeat("a", filter.MaxResponseBodyBytes+1))
	if int64(len(raw)) > filter.MaxResponseBodyBytes {
		t.Fatalf("compressed payload is %d bytes, want it under the cap so only the decoded size can trip it", len(raw))
	}

	upstream := encodedUpstream(http.StatusOK, "gzip", raw)
	handler := middlewareWithDeps(testVisibilityLogger(),
		Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
	if meta.ReasonCode != reasonCodeVisibilityResponseTooLarge {
		t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityResponseTooLarge)
	}
	if got := rec.Body.String(); !strings.Contains(got, responseTooLargeMessage) {
		t.Fatalf("body = %s, want the size refusal", got)
	}
}

// TestVisibilityCompressedResponsesNotRewrittenAreUntouched pins the branches
// that commit before the decode runs. A HEAD has no body to decode, a 304 is
// refused whatever it is encoded with, and a non-2xx is forwarded as it
// arrived — so its Content-Encoding still describes the bytes the client gets.
func TestVisibilityCompressedResponsesNotRewrittenAreUntouched(t *testing.T) {
	t.Parallel()

	gzipped := gzipForTest(t, `[{"Names":["/visible-web"],"Image":"nginx"}]`)

	t.Run("HEAD drops the compressed body and the daemon's metadata", func(t *testing.T) {
		t.Parallel()

		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("ETag", `"upstream"`)
			w.Header().Set("Content-Length", strconv.Itoa(len(gzipped)))
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
		handler := middlewareWithDeps(testVisibilityLogger(),
			Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

		meta := &logging.RequestMeta{}
		req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
		req = req.WithContext(logging.WithMeta(req.Context(), meta))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
		}
		if meta.ReasonCode != reasonCodeVisibilityNotModified {
			t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeVisibilityNotModified)
		}
	})

	t.Run("a compressed error body is forwarded with its coding", func(t *testing.T) {
		t.Parallel()

		errorBody := gzipForTest(t, `{"message":"no such container"}`)
		upstream := encodedUpstream(http.StatusInternalServerError, "gzip", errorBody)
		handler := middlewareWithDeps(testVisibilityLogger(),
			Options{NamePatterns: []string{"visible-*"}}, visibilityDeps{})(upstream)

		req := httptest.NewRequest(http.MethodGet, "/v1.53/containers/json", nil)
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
