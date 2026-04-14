package filter

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestMiddlewareAllowsRunInstructionsWhenConfigured(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/build", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	handler := MiddlewareWithOptions(rules, testLogger(), Options{
		DenyResponseVerbosity: DenyResponseVerbosityVerbose,
		Build: BuildOptions{
			AllowRunInstructions: true,
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
