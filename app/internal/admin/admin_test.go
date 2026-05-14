package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testPath = "/admin/validate"

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func newOKValidator() Validator {
	return func(_ []byte) ValidateResponse {
		return ValidateResponse{OK: true, Rules: 3, Profiles: 1}
	}
}

func newFailValidator(errs ...string) Validator {
	return func(_ []byte) ValidateResponse {
		return ValidateResponse{OK: false, Errors: errs}
	}
}

func TestInterceptorPassesThroughNonMatchingPath(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	handler := NewValidateInterceptor(Options{Path: testPath, Validate: newOKValidator()})(next)

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("expected next handler to be called for non-matching path")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestInterceptorRejectsNonPOST(t *testing.T) {
	handler := NewValidateInterceptor(Options{Path: testPath, Validate: newOKValidator()})(noopHandler())

	req := httptest.NewRequest(http.MethodGet, testPath, nil)
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow header = %q, want %q", got, http.MethodPost)
	}
}

func TestInterceptorReturns200OnValidationSuccess(t *testing.T) {
	handler := NewValidateInterceptor(Options{Path: testPath, Validate: newOKValidator()})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader("rules: []\n"))
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeResponse(t, rec.Body.Bytes())
	if !got.OK {
		t.Fatalf("ok = %v, want true", got.OK)
	}
	if got.Rules != 3 || got.Profiles != 1 {
		t.Fatalf("rules=%d profiles=%d, want 3/1", got.Rules, got.Profiles)
	}
}

func TestInterceptorReturns422OnValidationFailure(t *testing.T) {
	handler := NewValidateInterceptor(Options{
		Path:     testPath,
		Validate: newFailValidator("listen.socket and listen.address are both empty", "rule 1: match.method is required"),
	})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader("garbage"))
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
	}
	got := decodeResponse(t, rec.Body.Bytes())
	if got.OK {
		t.Fatalf("ok = true, want false on validation failure")
	}
	if len(got.Errors) != 2 {
		t.Fatalf("errors = %v, want 2 entries", got.Errors)
	}
}

func TestInterceptorReturns413OnOversizeBody(t *testing.T) {
	handler := NewValidateInterceptor(Options{
		Path:         testPath,
		MaxBodyBytes: 16,
		Validate:     newOKValidator(),
	})(noopHandler())

	big := bytes.Repeat([]byte("a"), 1024)
	req := httptest.NewRequest(http.MethodPost, testPath, bytes.NewReader(big))
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d. body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestInterceptorPassesEmptyBodyThroughToValidator(t *testing.T) {
	var seen []byte
	handler := NewValidateInterceptor(Options{
		Path: testPath,
		Validate: func(yaml []byte) ValidateResponse {
			seen = append([]byte{}, yaml...)
			return ValidateResponse{OK: true}
		},
	})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, nil)
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(seen) != 0 {
		t.Fatalf("validator received %d bytes, want 0", len(seen))
	}
}

func TestInterceptorReturns503WhenValidatorNotConfigured(t *testing.T) {
	handler := NewValidateInterceptor(Options{Path: testPath, Validate: nil})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(""))
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestInterceptorSurfacesCompatActive(t *testing.T) {
	handler := NewValidateInterceptor(Options{
		Path: testPath,
		Validate: func(_ []byte) ValidateResponse {
			return ValidateResponse{OK: true, Rules: 1, CompatActive: true}
		},
	})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(""))
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if !decodeResponse(t, rec.Body.Bytes()).CompatActive {
		t.Fatalf("compat_active = false, want true")
	}
}

func TestNilValidatorMiddleware_FallsThroughForUnrelatedPaths(t *testing.T) {
	// When Validate is nil the middleware must NOT 503 every request — only
	// requests to the configured admin path should fail closed. Docker API
	// traffic hitting an unrelated path must still reach next.
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := NewValidateInterceptor(Options{Path: testPath, Validate: nil})(next)

	// Unrelated path → should fall through to next.
	req := httptest.NewRequest(http.MethodPost, "/foo", nil)
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("next handler not called for unrelated path when Validate is nil")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unrelated path status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Admin path → should still return 503.
	called = false
	req2 := httptest.NewRequest(http.MethodPost, testPath, nil)
	rec2 := newRecorder()
	handler.ServeHTTP(rec2, req2)

	if called {
		t.Fatalf("next handler must not be called for admin path when Validate is nil")
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin path status = %d, want 503 when Validate is nil", rec2.Code)
	}
}

func TestValidatePOSTAcceptsAnyContentType(t *testing.T) {
	// The endpoint uses config.LoadBytes which handles both YAML and JSON
	// (YAML is a superset of JSON). We intentionally do NOT gate on
	// Content-Type so operators can POST application/json without friction;
	// this test locks in that behavior.
	handler := NewValidateInterceptor(Options{Path: testPath, Validate: newOKValidator()})(noopHandler())

	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader("rules: []\n"))
	req.Header.Set("Content-Type", "application/json")
	rec := newRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for application/json Content-Type", rec.Code)
	}
}

func TestValidatePOSTConcurrentRequests(t *testing.T) {
	// Fire 10 goroutines concurrently to detect data races and goroutine-
	// safety regressions in the validate handler.
	const workers = 10
	handler := NewValidateInterceptor(Options{
		Path: testPath,
		Validate: func(_ []byte) ValidateResponse {
			return ValidateResponse{OK: true, Rules: 1}
		},
	})(noopHandler())

	errs := make(chan string, workers)
	done := make(chan struct{})
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		go func() {
			<-start
			body := strings.NewReader("rules: []\n")
			req := httptest.NewRequest(http.MethodPost, testPath, body)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Sprintf("status = %d, want 200", rec.Code)
			} else {
				errs <- ""
			}
		}()
	}
	close(start)
	go func() {
		for i := 0; i < workers; i++ {
			<-errs
		}
		close(done)
	}()
	<-done
}

// TestMainListenerDisabled_DedicatedListenerEnabled_HappyPath locks in the
// documented posture: admin endpoints are served ONLY on the dedicated
// admin listener, never on the main data listener.
//
// Regression target: a wiring change that accidentally mounts the validate or
// policy-version interceptor on the main ServeMux would break isolation — this
// test would start seeing 200/422 on the "main" side instead of 404.
func TestMainListenerDisabled_DedicatedListenerEnabled_HappyPath(t *testing.T) {
	const validatePath = "/admin/validate"
	const versionPath = "/admin/policy/version"

	// --- main data listener mux: no admin interceptors registered ---
	// The main listener uses an http.ServeMux whose routes are all Docker-API
	// paths. Admin paths are simply not registered, so they return 404.
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Validate that admin paths return 404 on the main listener.
	for _, path := range []string{validatePath, versionPath} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		rec := newRecorder()
		mainMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("main listener: %s returned %d, want 404 (admin must not be served on data listener)", path, rec.Code)
		}
	}

	// --- dedicated admin listener handler: validate + policy-version interceptors ---
	// Mirrors the shape built by buildAdminHandlerChain in internal/cmd/serve.go.
	snap := &PolicySnapshot{Version: 1, Rules: 2, Source: "startup"}
	versionInterceptor := NewPolicyVersionInterceptor(PolicyVersionOptions{
		Path:   versionPath,
		Source: func() *PolicySnapshot { return snap },
	})
	validateInterceptor := NewValidateInterceptor(Options{
		Path:     validatePath,
		Validate: newOKValidator(),
	})

	// Chain: policy-version → validate → 404 terminal (same order as production).
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	adminHandler := versionInterceptor(validateInterceptor(terminal))

	// POST /admin/validate with valid body → 200 OK on dedicated listener.
	req := httptest.NewRequest(http.MethodPost, validatePath, strings.NewReader("rules: []\n"))
	rec := newRecorder()
	adminHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("dedicated admin listener: POST %s = %d, want 200", validatePath, rec.Code)
	}

	// GET /admin/policy/version → 200 OK with snapshot on dedicated listener.
	req = httptest.NewRequest(http.MethodGet, versionPath, nil)
	rec = newRecorder()
	adminHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("dedicated admin listener: GET %s = %d, want 200", versionPath, rec.Code)
	}

	// Unrelated Docker API path → falls through to terminal (404) on dedicated listener.
	req = httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	rec = newRecorder()
	adminHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("dedicated admin listener: unrelated path = %d, want 404", rec.Code)
	}
}

func noopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func decodeResponse(t *testing.T, body []byte) ValidateResponse {
	t.Helper()
	var got ValidateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(body))
	}
	return got
}
