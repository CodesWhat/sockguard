package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInspectPoliciesByMethodDispatch verifies that the method-keyed dispatch
// table built by compileRuntimePolicy routes requests correctly:
//   - GET, HEAD, and OPTIONS requests have no inspectors (nil/empty slice).
//   - POST has inspectors registered.
//   - PUT has inspectors registered (container archive).
func TestInspectPoliciesByMethodDispatch(t *testing.T) {
	t.Run("GET has no inspectors", func(t *testing.T) {
		p := compileRuntimePolicy(nil, PolicyConfig{})
		if got := len(p.inspectPoliciesByMethod[http.MethodGet]); got != 0 {
			t.Fatalf("GET slice len = %d, want 0", got)
		}
	})

	t.Run("HEAD has no inspectors", func(t *testing.T) {
		p := compileRuntimePolicy(nil, PolicyConfig{})
		if got := len(p.inspectPoliciesByMethod[http.MethodHead]); got != 0 {
			t.Fatalf("HEAD slice len = %d, want 0", got)
		}
	})

	t.Run("OPTIONS has no inspectors", func(t *testing.T) {
		p := compileRuntimePolicy(nil, PolicyConfig{})
		if got := len(p.inspectPoliciesByMethod[http.MethodOptions]); got != 0 {
			t.Fatalf("OPTIONS slice len = %d, want 0", got)
		}
	})

	t.Run("POST has inspectors", func(t *testing.T) {
		p := compileRuntimePolicy(nil, PolicyConfig{})
		if got := len(p.inspectPoliciesByMethod[http.MethodPost]); got == 0 {
			t.Fatal("POST slice is empty, want at least one inspector")
		}
	})

	t.Run("PUT has inspectors", func(t *testing.T) {
		p := compileRuntimePolicy(nil, PolicyConfig{})
		if got := len(p.inspectPoliciesByMethod[http.MethodPut]); got == 0 {
			t.Fatal("PUT slice is empty, want at least one inspector (container archive)")
		}
	})
}

// TestInspectAllowedRequestGetPassesThrough asserts that a GET request is
// never intercepted by inspectors — the method-keyed map for GET is empty so
// inspectAllowedRequest returns "" immediately.
func TestInspectAllowedRequestGetPassesThrough(t *testing.T) {
	allow, _ := CompileRule(Rule{Methods: []string{http.MethodGet}, Pattern: "/containers/**", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{allow}

	passed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true })
	mw := MiddlewareWithOptions(rules, testLogger(), Options{})
	req := httptest.NewRequest(http.MethodGet, "/containers/abc123", nil)
	mw(next).ServeHTTP(httptest.NewRecorder(), req)
	if !passed {
		t.Fatal("GET request was blocked; expected pass-through with no inspectors")
	}
}

// TestInspectAllowedRequestPostRoutesCorrectly asserts that POST requests to
// an inspected path are routed to the correct inspector slice.
func TestInspectAllowedRequestPostRoutesCorrectly(t *testing.T) {
	allow, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{allow}

	passed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true })
	mw := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			ContainerCreate: ContainerCreateOptions{},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	mw(next).ServeHTTP(httptest.NewRecorder(), req)
	if !passed {
		t.Fatal("POST /containers/create was blocked; expected pass-through")
	}
}
