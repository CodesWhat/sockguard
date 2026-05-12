package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/httpjson"
)

const maxFuzzBodyBytes = 4096
const maxFuzzHeaderNameSuffixBytes = 64
const maxFuzzHeaderValueBytes = 512
const maxFuzzStreamBytes = (2 * hijackBufSize) + 1024

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
		startFuzzForensicsSampler(t, "FuzzHijackHeadersAndBody")

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

func FuzzHijackBidirectionalStream(f *testing.F) {
	f.Add([]byte("stdin"), []byte("stdout"))
	f.Add(bytes.Repeat([]byte("a"), hijackBufSize-1), bytes.Repeat([]byte("b"), hijackBufSize+1))
	f.Add(bytes.Repeat([]byte("c"), hijackBufSize+257), bytes.Repeat([]byte("d"), hijackBufSize*2))
	f.Add([]byte{}, bytes.Repeat([]byte("e"), hijackBufSize+17))

	f.Fuzz(func(t *testing.T, clientPayload, upstreamPayload []byte) {
		clientPayload = truncateFuzzBytes(clientPayload, maxFuzzStreamBytes)
		upstreamPayload = truncateFuzzBytes(upstreamPayload, maxFuzzStreamBytes)

		socketPath := fmt.Sprintf("/tmp/sockguard-fuzz-hijack-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen unix socket: %v", err)
		}
		t.Cleanup(func() {
			_ = ln.Close()
			_ = os.Remove(socketPath)
		})

		serverErrs := make(chan error, 4)
		clientBytesRead := make(chan int64, 1)

		var upstreamWg sync.WaitGroup
		upstreamWg.Add(1)
		go func() {
			defer upstreamWg.Done()

			conn, err := ln.Accept()
			if err != nil {
				serverErrs <- fmt.Errorf("accept upstream connection: %w", err)
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			req, err := http.ReadRequest(reader)
			if err != nil {
				serverErrs <- fmt.Errorf("read upstream request: %w", err)
				return
			}
			if req.Body != nil {
				_ = req.Body.Close()
			}

			resp := &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
			}
			resp.Header.Set("Connection", "Upgrade")
			resp.Header.Set("Upgrade", "tcp")
			if err := resp.Write(conn); err != nil {
				serverErrs <- fmt.Errorf("write upgrade response: %w", err)
				return
			}

			var ioWg sync.WaitGroup
			ioWg.Add(2)

			go func() {
				defer ioWg.Done()
				if len(upstreamPayload) > 0 {
					if _, err := conn.Write(upstreamPayload); err != nil {
						serverErrs <- fmt.Errorf("write upstream payload: %w", err)
						return
					}
				}
				closeWrite(conn)
			}()

			go func() {
				defer ioWg.Done()
				n, err := io.Copy(io.Discard, reader)
				if err != nil {
					serverErrs <- fmt.Errorf("read client payload: %w", err)
					return
				}
				clientBytesRead <- n
			}()

			ioWg.Wait()
		}()

		handler := HijackHandler(socketPath, testLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("next handler should not be called for hijack endpoints")
		}))

		// Client↔proxy leg uses a unix socket rather than a loopback TCP
		// listener so the 5 s pre-push smoke run doesn't exhaust macOS
		// ephemeral ports by cycling through hundreds of dial/close
		// pairs per second. Bidirectional hijack semantics are identical
		// across the two transports for what this fuzz exercises.
		clientSocketPath := fmt.Sprintf("/tmp/sockguard-fuzz-hijack-client-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
		clientLn, err := net.Listen("unix", clientSocketPath)
		if err != nil {
			t.Fatalf("listen client unix socket: %v", err)
		}
		t.Cleanup(func() {
			_ = clientLn.Close()
			_ = os.Remove(clientSocketPath)
		})

		srv := &http.Server{Handler: handler}
		go func() {
			_ = srv.Serve(clientLn)
		}()
		t.Cleanup(func() {
			_ = srv.Close()
		})

		clientConn, err := net.Dial("unix", clientSocketPath)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		t.Cleanup(func() {
			_ = clientConn.Close()
		})

		reqStr := "POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
		if _, err := clientConn.Write([]byte(reqStr)); err != nil {
			t.Fatalf("write hijack request: %v", err)
		}

		clientBuf := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(clientBuf, nil)
		if err != nil {
			t.Fatalf("read hijack response: %v", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
		}

		writeErr := make(chan error, 1)
		go func() {
			if len(clientPayload) > 0 {
				if _, err := clientConn.Write(clientPayload); err != nil {
					writeErr <- fmt.Errorf("write client payload: %w", err)
					return
				}
			}
			if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
				if err := cw.CloseWrite(); err != nil {
					writeErr <- fmt.Errorf("close client write side: %w", err)
					return
				}
			}
			writeErr <- nil
		}()

		gotUpstreamPayload, err := io.ReadAll(clientBuf)
		if err != nil {
			t.Fatalf("read upstream payload: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotUpstreamPayload, upstreamPayload) {
			t.Fatalf("upstream payload len = %d, want %d", len(gotUpstreamPayload), len(upstreamPayload))
		}

		upstreamWg.Wait()

		select {
		case n := <-clientBytesRead:
			if n != int64(len(clientPayload)) {
				t.Fatalf("client payload bytes read = %d, want %d", n, len(clientPayload))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for upstream client payload read")
		}

		select {
		case err := <-serverErrs:
			if err != nil {
				t.Fatal(err)
			}
		default:
		}
	})
}

func TestFuzzHeaderNameIsBounded(t *testing.T) {
	got := fuzzHeaderName(strings.Repeat("z", maxFuzzHeaderNameSuffixBytes*4))
	if len(got) > len("X-Fuzz-")+maxFuzzHeaderNameSuffixBytes {
		t.Fatalf("header name len = %d, want <= %d", len(got), len("X-Fuzz-")+maxFuzzHeaderNameSuffixBytes)
	}
	if got != "X-Fuzz-"+strings.Repeat("Z", maxFuzzHeaderNameSuffixBytes) {
		t.Fatalf("header name = %q", got)
	}
}

func TestSanitizeHeaderValueIsBounded(t *testing.T) {
	got := sanitizeHeaderValue(strings.Repeat("Z", maxFuzzHeaderValueBytes*4))
	if len(got) > maxFuzzHeaderValueBytes {
		t.Fatalf("header value len = %d, want <= %d", len(got), maxFuzzHeaderValueBytes)
	}
	if got != strings.Repeat("Z", maxFuzzHeaderValueBytes) {
		t.Fatalf("header value = %q", got)
	}
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
	return truncateFuzzBytes(body, maxFuzzBodyBytes)
}

func truncateFuzzBytes(data []byte, max int) []byte {
	if len(data) > max {
		return data[:max]
	}
	return data
}

func fuzzHeaderName(s string) string {
	var b strings.Builder
	b.Grow(maxFuzzHeaderNameSuffixBytes)
	for _, r := range s {
		if b.Len() >= maxFuzzHeaderNameSuffixBytes {
			break
		}
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
	b.Grow(maxFuzzHeaderValueBytes)
	for _, r := range s {
		if b.Len() >= maxFuzzHeaderValueBytes {
			break
		}
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
