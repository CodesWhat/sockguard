package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
)

const maxFuzzBodyBytes = 4096

type fuzzEchoResponse struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	BodyLen     int    `json:"body_len"`
	BodySHA256  string `json:"body_sha256"`
}

func FuzzProxyHeadersAndBody(f *testing.F) {
	socketPath := startFuzzEchoUpstream(f)
	handler := New(socketPath, testLogger())

	f.Add("trace", "alpha", []byte("hello"))
	f.Add("contenttype", "application/json", []byte(`{"name":"demo"}`))
	f.Add("docker", "api-version=1.47", []byte{})
	f.Add("multi-word", "value with spaces", []byte("line1\nline2"))

	f.Fuzz(func(t *testing.T, headerSuffix, headerValue string, body []byte) {
		body = truncateFuzzBody(body)
		headerName := fuzzHeaderName(headerSuffix)
		headerValue = sanitizeHeaderValue(headerValue)

		req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(body))
		req.Header.Set(headerName, headerValue)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}

		assertFuzzEchoResponse(t, rec, http.MethodPost, "/containers/create", headerName, expectedForwardedHeaderValue(headerValue), body)
	})
}

func FuzzHijackHeadersAndBody(f *testing.F) {
	socketPath := startFuzzEchoUpstream(f)

	f.Add("trace", "alpha", []byte("stdin"))
	f.Add("stream", "1", []byte(`{"stdin":true,"stdout":true}`))
	f.Add("exec", "start", []byte{})
	f.Add("body", "tabs\tallowed", []byte("binary\x00payload"))

	f.Fuzz(func(t *testing.T, headerSuffix, headerValue string, body []byte) {
		handler := HijackHandler(socketPath, testLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("next handler should not be called for hijack endpoints")
		}))

		body = truncateFuzzBody(body)
		headerName := fuzzHeaderName(headerSuffix)
		headerValue = sanitizeHeaderValue(headerValue)

		req := httptest.NewRequest(http.MethodPost, "/containers/abc/attach", bytes.NewReader(body))
		req.Header.Set(headerName, headerValue)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}

		assertFuzzEchoResponse(t, rec, http.MethodPost, "/containers/abc/attach", headerName, expectedForwardedHeaderValue(headerValue), body)
	})
}

func startFuzzEchoUpstream(f *testing.F) string {
	f.Helper()

	socketPath := "/tmp/sockguard-fuzz-" + time.Now().Format("20060102150405.000000000") + ".sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		f.Fatalf("listen unix socket: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			body, err := io.ReadAll(io.LimitReader(r.Body, maxFuzzBodyBytes))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			headerName, headerValue := firstFuzzHeader(r.Header)
			if err := httpjson.Write(w, http.StatusOK, fuzzEchoResponse{
				Method:      r.Method,
				Path:        r.URL.Path,
				HeaderName:  headerName,
				HeaderValue: headerValue,
				BodyLen:     len(body),
				BodySHA256:  sha256Hex(body),
			}); err != nil {
				panic("encode upstream response: " + err.Error())
			}
		}),
	}

	go func() {
		_ = server.Serve(ln)
	}()

	f.Cleanup(func() {
		_ = server.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	return socketPath
}

func assertFuzzEchoResponse(t *testing.T, rec *httptest.ResponseRecorder, wantMethod, wantPath, wantHeaderName, wantHeaderValue string, wantBody []byte) {
	t.Helper()

	var body fuzzEchoResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Method != wantMethod {
		t.Fatalf("method = %q, want %q", body.Method, wantMethod)
	}
	if body.Path != wantPath {
		t.Fatalf("path = %q, want %q", body.Path, wantPath)
	}
	if body.HeaderName != textproto.CanonicalMIMEHeaderKey(wantHeaderName) {
		t.Fatalf("header name = %q, want %q", body.HeaderName, textproto.CanonicalMIMEHeaderKey(wantHeaderName))
	}
	if body.HeaderValue != wantHeaderValue {
		t.Fatalf("header value = %q, want %q", body.HeaderValue, wantHeaderValue)
	}
	if body.BodyLen != len(wantBody) {
		t.Fatalf("body len = %d, want %d", body.BodyLen, len(wantBody))
	}
	if body.BodySHA256 != sha256Hex(wantBody) {
		t.Fatalf("body sha256 = %q, want %q", body.BodySHA256, sha256Hex(wantBody))
	}
}

func truncateFuzzBody(body []byte) []byte {
	if len(body) > maxFuzzBodyBytes {
		return body[:maxFuzzBodyBytes]
	}
	return body
}

func fuzzHeaderName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		b.WriteString("Value")
	}
	return "X-Fuzz-" + b.String()
}

func sanitizeHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == ' ':
			b.WriteRune(r)
		case r >= 0x21 && r <= 0x7e:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func expectedForwardedHeaderValue(s string) string {
	return textproto.TrimString(s)
}

func firstFuzzHeader(header http.Header) (string, string) {
	for name, values := range header {
		if strings.HasPrefix(name, "X-Fuzz-") {
			if len(values) == 0 {
				return name, ""
			}
			return name, values[0]
		}
	}
	return "", ""
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
