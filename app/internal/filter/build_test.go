package filter

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareDeniesRemoteBuildContextByDefault(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected remote build context to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/build?remote=https%3A%2F%2Fgithub.com%2Facme%2Fapp.git", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "remote") {
		t.Fatalf("reason = %q, want remote-context denial", body.Reason)
	}
}

func TestMiddlewareDeniesBuildWithHostNetworkByDefault(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected host-network build to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/build?networkmode=host", bytes.NewReader(mustBuildContextTar(t, "Dockerfile", "FROM busybox\nCOPY . /app\n")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "host network") {
		t.Fatalf("reason = %q, want host-network denial", body.Reason)
	}
}

func TestMiddlewareDeniesBuildWithRunInstructionByDefault(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected build to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(mustBuildContextTar(t, "Dockerfile", "FROM busybox\nRUN id\n")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "RUN") {
		t.Fatalf("reason = %q, want RUN denial", body.Reason)
	}
}

func TestMiddlewareAllowsBuildWithoutRunInstructionsAndPreservesBody(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := mustBuildContextTar(t, "Dockerfile", "FROM busybox\nCOPY . /app\n")
	wantDigest := sha256.Sum256(payload)

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
			t.Fatalf("body sha256 = %s, want %s", hex.EncodeToString(gotDigest[:]), hex.EncodeToString(wantDigest[:]))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestBuildContextStreaming(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := mustBuildContextTar(t, "Dockerfile", "FROM busybox\nCOPY . /app\n")
	wantDigest := sha256.Sum256(payload)
	downstreamResult := make(chan error, 1)

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			downstreamResult <- fmt.Errorf("read body: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if gotDigest := sha256.Sum256(body); gotDigest != wantDigest {
			downstreamResult <- fmt.Errorf(
				"body sha256 = %s, want %s",
				hex.EncodeToString(gotDigest[:]),
				hex.EncodeToString(wantDigest[:]),
			)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.ContentLength != int64(len(payload)) {
			downstreamResult <- fmt.Errorf("content length = %d, want %d", r.ContentLength, len(payload))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		downstreamResult <- nil
		w.WriteHeader(http.StatusNoContent)
	}))

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := fmt.Fprintf(
		conn,
		"POST /build HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-tar\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(server.URL, "http://"),
	); err != nil {
		t.Fatalf("write request headers: %v", err)
	}

	const chunkSize = 37
	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]
		if _, err := fmt.Fprintf(conn, "%x\r\n", len(chunk)); err != nil {
			t.Fatalf("write chunk size: %v", err)
		}
		if _, err := conn.Write(chunk); err != nil {
			t.Fatalf("write chunk body: %v", err)
		}
		if _, err := io.WriteString(conn, "\r\n"); err != nil {
			t.Fatalf("write chunk trailer: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := io.WriteString(conn, "0\r\n\r\n"); err != nil {
		t.Fatalf("write terminal chunk: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusNoContent, body)
	}

	select {
	case err := <-downstreamResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for downstream build handler")
	}
}

func TestMiddlewareAllowsRunInstructionsWhenConfigured(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			DenyResponseVerbosity: DenyResponseVerbosityVerbose,
			Build: BuildOptions{
				AllowRunInstructions: true,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(mustBuildContextTar(t, "Dockerfile", "FROM busybox\nRUN id\n")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestBuildGzipTruncationDenial(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	payload := mustBuildContextGzipTarSeed(t, "Dockerfile", "FROM busybox\nCOPY . /app\n")
	truncated := payload[:len(payload)-8]

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected truncated gzip build context to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(truncated))
	req.Header.Set("Content-Type", "application/gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "unable to inspect build request" {
		t.Fatalf("reason = %q, want %q", body.Reason, "unable to inspect build request")
	}
}

func TestMiddlewareDeniesOversizedBuildContext(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := verboseMiddleware(rules, testLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected oversized build context to be denied")
	}))

	req := httptest.NewRequest(http.MethodPost, "/build", nil)
	req.Body = io.NopCloser(&repeatingByteReader{remaining: maxBuildContextBytes + 1, value: 'A'})
	req.ContentLength = maxBuildContextBytes + 1
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "exceeds") {
		t.Fatalf("reason = %q, want body-limit denial", body.Reason)
	}
}

func TestSpoolRequestBodyToTempFileWrapsCopyError(t *testing.T) {
	sentinel := errors.New("close failed")
	req := httptest.NewRequest(http.MethodPost, "/build", nil)
	req.Body = &erroringReadCloser{
		Reader:   strings.NewReader("FROM busybox\n"),
		closeErr: sentinel,
	}

	spool, size, err := spoolRequestBodyToTempFile(req, "sockguard-build-test-", 1024)
	if err == nil {
		t.Fatal("expected spoolRequestBodyToTempFile() to fail")
	}
	if spool != nil {
		t.Fatalf("spool = %#v, want nil", spool)
	}
	if size != 0 {
		t.Fatalf("size = %d, want 0", size)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is(err, sentinel) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "spool build body") {
		t.Fatalf("err = %q, want wrapped spool context", err)
	}
}

func TestExtractBuildDockerfileWrapsTooLargeError(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		payload     []byte
	}{
		{
			name:        "raw dockerfile",
			contentType: "text/plain",
			payload:     bytes.Repeat([]byte("A"), maxBuildDockerfileBytes+1),
		},
		{
			name:        "tar dockerfile",
			contentType: "application/x-tar",
			payload:     mustBuildContextTar(t, "Dockerfile", strings.Repeat("A", maxBuildDockerfileBytes+1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.CreateTemp("", "sockguard-build-dockerfile-*")
			if err != nil {
				t.Fatalf("CreateTemp: %v", err)
			}
			t.Cleanup(func() {
				_ = file.Close()
				_ = os.Remove(file.Name())
			})

			if _, err := file.Write(tt.payload); err != nil {
				t.Fatalf("Write: %v", err)
			}

			_, _, err = extractBuildDockerfile(file, tt.contentType, "Dockerfile")
			if err == nil {
				t.Fatal("expected extractBuildDockerfile() to fail")
			}
			if !errors.Is(err, errBuildDockerfileTooLarge) {
				t.Fatalf("errors.Is(err, errBuildDockerfileTooLarge) = false, err = %v", err)
			}
			if !strings.Contains(err.Error(), "dockerfile exceeds") {
				t.Fatalf("err = %q, want dockerfile limit context", err)
			}
		})
	}
}

func mustBuildContextTar(t *testing.T, dockerfilePath string, dockerfile string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, file := range []struct {
		name string
		body string
	}{
		{name: dockerfilePath, body: dockerfile},
		{name: "app.txt", body: "hello"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: 0o644,
			Size: int64(len(file.body)),
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

type repeatingByteReader struct {
	remaining int64
	value     byte
}

func (r *repeatingByteReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.value
	}
	r.remaining -= int64(len(p))
	return len(p), nil
}
