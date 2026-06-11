package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The policy-version interceptor reaches matchesAdminPath through
// serviceUnavailableMiddleware and its own handler, so it needs the same
// path-variant coverage the validate interceptor has — a normalization
// regression in either wiring would otherwise leak variants to the rule
// evaluator.
func TestPolicyVersionInterceptorMatchesPathVariants(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{
		testPolicyVersionPath + "/",
		"/admin/policy//version",
		"/admin/policy/./version",
		"/admin/policy/x/../version",
	} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			v := NewPolicyVersioner()
			v.Update(PolicySnapshot{Rules: 1, Source: "startup"})
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatalf("path variant %q leaked past the policy-version interceptor", variant)
			})
			handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
				Path:   testPolicyVersionPath,
				Source: v.Snapshot,
			})(next)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.Path = variant
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

// A double-encoded slash (%252f → literal "%2f" in the decoded path) must NOT
// match the admin path: path.Clean does not percent-decode, so the request
// falls through to the rule evaluator where default-deny rejects it. This
// pins the fail-closed behavior for both interceptors.
func TestAdminInterceptorsIgnoreEncodedSlashVariants(t *testing.T) {
	t.Parallel()
	t.Run("validate", func(t *testing.T) {
		t.Parallel()
		passedThrough := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			passedThrough = true
			w.WriteHeader(http.StatusForbidden)
		})
		handler := NewValidateInterceptor(Options{Path: testPath, Validate: newOKValidator()})(next)

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("rules: []"))
		req.URL.Path = "/admin%2fvalidate"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !passedThrough {
			t.Fatal("encoded-slash path was handled by the admin layer, want pass-through to rule evaluator")
		}
	})
	t.Run("policy-version", func(t *testing.T) {
		t.Parallel()
		passedThrough := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			passedThrough = true
			w.WriteHeader(http.StatusForbidden)
		})
		v := NewPolicyVersioner()
		v.Update(PolicySnapshot{Rules: 1, Source: "startup"})
		handler := NewPolicyVersionInterceptor(PolicyVersionOptions{
			Path:   testPolicyVersionPath,
			Source: v.Snapshot,
		})(next)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = "/admin/policy%2fversion"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !passedThrough {
			t.Fatal("encoded-slash path was handled by the admin layer, want pass-through to rule evaluator")
		}
	})
}
