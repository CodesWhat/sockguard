package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMatchesBuildkitTunnelInspectionDirectControlMethodPaths pins the fix
// for CodeRabbit's phase-1 finding: matchesBuildkitTunnelInspection must
// also catch direct moby.buildkit.v1.Control/<Method> paths (the third
// shape cmd/rules.go's buildkitTunnelEndpoints probes at startup), not just
// /session and /grpc — otherwise a rule admitted by
// validateBuildkitTunnelRulesForPolicy once request_body.buildkit is
// configured would bypass this deny-only inspector and reach the Docker
// socket unmediated.
func TestMatchesBuildkitTunnelInspectionDirectControlMethodPaths(t *testing.T) {
	matchPaths := []string{
		"/session",
		"/grpc",
		"/moby.buildkit.v1.Control/Solve",
		"/moby.buildkit.v1.Control/Status",
		"/moby.buildkit.v1.Control/ListWorkers",
	}
	for _, p := range matchPaths {
		if !matchesBuildkitTunnelInspection(p) {
			t.Errorf("matchesBuildkitTunnelInspection(%q) = false, want true", p)
		}
	}

	// A bare "/moby.buildkit.v1.Control" (no trailing slash, no method) must
	// NOT match — only the "/moby.buildkit.v1.Control/" prefix does.
	denyPaths := []string{
		"/moby.buildkit.v1.Control",
		"/moby.buildkit.v1.Control2/Solve",
		"/sessions",
		"/grpcs",
	}
	for _, p := range denyPaths {
		if matchesBuildkitTunnelInspection(p) {
			t.Errorf("matchesBuildkitTunnelInspection(%q) = true, want false", p)
		}
	}
}

// TestInspectAllowedRequestDeniesBuildkitDirectControlMethodPathAfterVersionStrip
// runs a version-prefixed direct Control method path through the full
// middleware pipeline (normalize → rule match → inspect) and asserts it is
// denied once request_body.buildkit is configured, exactly like /session and
// /grpc already are. This is the routing-level counterpart to the matcher
// unit test above: it proves normalizePath's version-prefix stripping feeds
// matchesBuildkitTunnelInspection the same "/moby.buildkit.v1.Control/..."
// shape a bare request would.
func TestInspectAllowedRequestDeniesBuildkitDirectControlMethodPathAfterVersionStrip(t *testing.T) {
	allow, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/moby.buildkit.v1.Control/**", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{allow}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected buildkit control method path to be denied, but request reached next handler")
	})
	mw := MiddlewareWithOptions(rules, testLogger(), Options{
		PolicyConfig: PolicyConfig{
			Buildkit: BuildkitOptions{TunnelConfigured: true},
		},
	})

	for _, path := range []string{
		"/v1.51/moby.buildkit.v1.Control/Solve",
		"/v1.51/moby.buildkit.v1.Control/Status",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			mw(next).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}
}

// TestInspectAllowedRequestPassesBuildkitDirectControlMethodPathWhenNotConfigured
// asserts the inverse: when request_body.buildkit is not configured, a
// direct Control method path is unaffected by buildkitPolicy.inspect and
// falls through unchanged, matching pre-#185 behavior.
func TestInspectAllowedRequestPassesBuildkitDirectControlMethodPathWhenNotConfigured(t *testing.T) {
	allow, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/moby.buildkit.v1.Control/**", Action: ActionAllow, Index: 0})
	rules := []*CompiledRule{allow}

	passed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true })
	mw := MiddlewareWithOptions(rules, testLogger(), Options{})

	req := httptest.NewRequest(http.MethodPost, "/v1.51/moby.buildkit.v1.Control/Solve", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	if !passed {
		t.Fatalf("expected pass-through when TunnelConfigured is false; status = %d, body: %s", rec.Code, rec.Body.String())
	}
}
