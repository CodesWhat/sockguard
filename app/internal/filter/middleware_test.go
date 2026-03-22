package filter

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type devNull struct{}

func (devNull) Write(b []byte) (int, error) { return len(b), nil }

var errWriteFailed = errors.New("write failed")

type failingResponseWriter struct {
	header http.Header
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}

func TestMiddlewareAllowed(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareDenied(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})
	rules := []*CompiledRule{r1, r2}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("expected request to NOT reach inner handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Message != "request denied by sockguard policy" {
		t.Errorf("message = %q, want 'request denied by sockguard policy'", body.Message)
	}
	if body.Method != "POST" {
		t.Errorf("method = %q, want POST", body.Method)
	}
	if body.Path != "/containers/create" {
		t.Errorf("path = %q, want /containers/create", body.Path)
	}
	if body.Reason != "deny all" {
		t.Errorf("reason = %q, want 'deny all'", body.Reason)
	}
}

func TestMiddlewareWritesMeta(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := logging.Meta(r.Context())
		if m == nil {
			t.Fatal("expected meta in context")
		}
		if m.Decision != "allow" {
			t.Errorf("Decision = %q, want allow", m.Decision)
		}
		if m.Rule != 0 {
			t.Errorf("Rule = %d, want 0", m.Rule)
		}
		if m.NormPath != "/_ping" {
			t.Errorf("NormPath = %q, want /_ping", m.NormPath)
		}
	})

	handler := Middleware(rules, testLogger())(inner)

	// Simulate access log middleware by injecting meta
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest("GET", "/_ping", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Also verify meta was written (accessible from outer middleware)
	if meta.Decision != "allow" {
		t.Errorf("meta.Decision = %q, want allow", meta.Decision)
	}
}

func TestMiddlewareVersionPrefixInDenial(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach inner handler")
	})

	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest("POST", "/v1.45/containers/create", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Original path should be preserved in denial response
	if body.Path != "/v1.45/containers/create" {
		t.Errorf("path = %q, want /v1.45/containers/create", body.Path)
	}
}

func TestMiddlewareEmptyRulesDeny(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	handler := Middleware(nil, testLogger())(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("expected request to NOT reach inner handler with empty rules")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Reason != "no matching allow rule" {
		t.Errorf("reason = %q, want %q", body.Reason, "no matching allow rule")
	}
}

func TestMiddlewareNilMetaInContext(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"GET"}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{r1}

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(rules, testLogger())(inner)
	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Error("expected request to reach inner handler with nil meta in context")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareLogsEncodeError(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	rules := []*CompiledRule{r1}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach inner handler")
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	handler := Middleware(rules, logger)(inner)
	req := httptest.NewRequest("POST", "/containers/create", nil)
	rec := &failingResponseWriter{}
	handler.ServeHTTP(rec, req)

	if rec.status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.status, http.StatusForbidden)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "failed to encode denial response") {
		t.Errorf("expected encode error log, got %q", logOutput)
	}
	if !strings.Contains(logOutput, errWriteFailed.Error()) {
		t.Errorf("expected write error in log, got %q", logOutput)
	}
}
