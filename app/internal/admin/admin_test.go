package admin

import (
	"bytes"
	"encoding/json"
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
