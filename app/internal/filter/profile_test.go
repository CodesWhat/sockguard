package filter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareUsesResolvedProfileRules(t *testing.T) {
	defaultDeny, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	profileAllow, _ := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	profileDeny, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "profile deny", Index: 1})

	handler := MiddlewareWithOptions([]*CompiledRule{defaultDeny}, testLogger(), Options{
		Profiles: map[string]Policy{
			"readonly": {
				Rules: []*CompiledRule{profileAllow, profileDeny},
			},
		},
		ResolveProfile: func(*http.Request) (string, bool) {
			return "readonly", true
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestMiddlewareUsesResolvedProfileBodyPolicy(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})

	handler := MiddlewareWithOptions([]*CompiledRule{r1, r2}, testLogger(), Options{
		DenyResponseVerbosity: DenyResponseVerbosityVerbose,
		Profiles: map[string]Policy{
			"watchtower": {
				Rules: []*CompiledRule{r1, r2},
				Exec: ExecOptions{
					AllowedCommands: [][]string{{"/usr/local/bin/pre-update"}},
				},
			},
		},
		ResolveProfile: func(*http.Request) (string, bool) {
			return "watchtower", true
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/abc123/exec", strings.NewReader(`{"Cmd":["/usr/local/bin/pre-update"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestMiddlewareDeniesUnknownResolvedProfile(t *testing.T) {
	defaultAllow, _ := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	defaultDeny, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 1})

	handler := MiddlewareWithOptions([]*CompiledRule{defaultAllow, defaultDeny}, testLogger(), Options{
		DenyResponseVerbosity: DenyResponseVerbosityVerbose,
		ResolveProfile: func(*http.Request) (string, bool) {
			return "missing", true
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected missing profile to fail closed")
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body DenialResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(body.Reason, "profile") {
		t.Fatalf("reason = %q, want profile resolution denial", body.Reason)
	}
}

func TestMiddlewareResolveProfileCanUseRequestContext(t *testing.T) {
	defaultDeny, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 0})
	profileAllow, _ := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/_ping", Action: ActionAllow, Index: 0})
	profileDeny, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "profile deny", Index: 1})

	type ctxKey string
	const key ctxKey = "profile"

	handler := MiddlewareWithOptions([]*CompiledRule{defaultDeny}, testLogger(), Options{
		Profiles: map[string]Policy{
			"readonly": {
				Rules: []*CompiledRule{profileAllow, profileDeny},
			},
		},
		ResolveProfile: func(r *http.Request) (string, bool) {
			profile, _ := r.Context().Value(key).(string)
			return profile, profile != ""
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(context.WithValue(req.Context(), key, "readonly"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}
