package clientacl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rootlessLabelPaths are the shapes a container-label ACL grant must not be
// allowed to carry. They split into two families that fail differently, which
// is why the refusal is on the leading slash rather than on "does it match
// anything".
//
// The single-star family (a bare "*", "containers/*", "*/json") mostly matches
// nothing once the segment walker stops trimming a leading slash off the
// pattern and the path, because the "[^/]*" a "*" compiles to cannot cross a
// separator — that holds for a bare "*" and for "containers/*", both harmless
// grants that silently do nothing. "*/json" is the exception: its leading "*"
// consumes the empty segment a rooted path's leading "/" produces, so it does
// match a rooted path, specifically "/json" (though not "/containers/json").
// Whichever way a given single-star pattern breaks, it is not one an operator
// meant to write, which is why this file's rejection does not depend on
// telling the "live" ones apart from the "dead" ones — every rootless pattern
// is refused outright, regardless.
//
// The deep-wildcard family is the dangerous one. "**" compiles to "^(?s:.*)$",
// "**/json" to "^(?s:.*)/json$" and "*/**" to "^[^/]*(/(?s:.*))?$" — every one
// of those matches straight across the leading slash. A label reading
// `com.sockguard.allow.get=**` grants every GET the global policy allows, which
// is the opposite of the narrow per-client grant its author wrote. Labels never
// reach config.Validate, so compileContainerLabelRules is the only gate.
var rootlessLabelPaths = []string{
	"**",
	"**/json",
	"*/**",
	"*",
	"containers/*",
	"containers/**",
	"*/json",
}

func TestCompileContainerLabelRulesRejectsRootlessPaths(t *testing.T) {
	for _, path := range rootlessLabelPaths {
		t.Run(path, func(t *testing.T) {
			_, hasACL, err := compileContainerLabelRules(map[string]string{
				DefaultLabelPrefix + "get": path,
			}, DefaultLabelPrefix)
			if err == nil {
				t.Fatalf("compileContainerLabelRules(%q) error = nil, want a rootless path rejection", path)
			}
			// hasACLLabels stays true on refusal so the caller fails closed on
			// this client rather than treating it as a container with no ACL
			// labels, which passes through to the global policy.
			if !hasACL {
				t.Fatalf("compileContainerLabelRules(%q) hasACLLabels = false; a refused label must not read as no labels at all", path)
			}
			for _, want := range []string{"must start with '/'", path, "/" + path} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestCompileContainerLabelRulesAcceptsRootedPaths(t *testing.T) {
	for _, path := range rootlessLabelPaths {
		rooted := "/" + path
		t.Run(rooted, func(t *testing.T) {
			rules, hasACL, err := compileContainerLabelRules(map[string]string{
				DefaultLabelPrefix + "get": rooted,
			}, DefaultLabelPrefix)
			if err != nil {
				t.Fatalf("compileContainerLabelRules(%q) error = %v, want nil", rooted, err)
			}
			if !hasACL || len(rules) != 1 {
				t.Fatalf("compileContainerLabelRules(%q) = (%d rules, hasACL=%v), want (1, true)", rooted, len(rules), hasACL)
			}
		})
	}
}

// TestMiddlewareRefusesRootlessLabelPathsFailClosed runs the refusal through
// the middleware, which is where it has to land: a rootless label is refused
// with the same logged 502 a malformed pattern already gets, and the request
// never reaches the proxy. Before the reject, `com.sockguard.allow.get=**`
// answered 202 here.
func TestMiddlewareRefusesRootlessLabelPathsFailClosed(t *testing.T) {
	for _, path := range rootlessLabelPaths {
		t.Run(path, func(t *testing.T) {
			handler := middlewareWithDeps(testLogger(), Options{
				ContainerLabels: ContainerLabelOptions{
					Enabled:     true,
					LabelPrefix: "com.sockguard.allow.",
				},
			}, fakeResolver{
				found: true,
				client: resolvedClient{
					Labels: map[string]string{"com.sockguard.allow.get": path},
				},
			}.resolveClient)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatalf("label path %q reached the proxy; a rootless grant must fail closed", path)
			}))

			for _, requestPath := range []string{"/containers/json", "/_ping", "/v1.45/containers/json"} {
				req := httptest.NewRequest(http.MethodGet, requestPath, nil)
				req.RemoteAddr = "172.18.0.5:45678"
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code != http.StatusBadGateway {
					t.Fatalf("GET %s with label %q = %d, want %d; body: %s",
						requestPath, path, rec.Code, http.StatusBadGateway, rec.Body.String())
				}
			}
		})
	}
}

// TestMiddlewareStillHonorsRootedLabelPaths is the other half: rooting the
// label is the fix an operator makes, and it has to keep working. A rooted
// grant admits what it names and nothing else, so the refusal above cannot be
// passing by breaking label ACLs outright.
func TestMiddlewareStillHonorsRootedLabelPaths(t *testing.T) {
	tests := []struct {
		label   string
		allowed string
		denied  string
	}{
		{label: "/**", allowed: "/containers/json", denied: ""},
		{label: "/containers/**", allowed: "/containers/json", denied: "/events"},
		{label: "/containers/*", allowed: "/containers/json", denied: "/containers/abc/json"},
		{label: "/*/json", allowed: "/containers/json", denied: "/containers"},
		{label: "/**/json", allowed: "/containers/json", denied: "/containers/logs"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			newHandler := func(reached *bool) http.Handler {
				return middlewareWithDeps(testLogger(), Options{
					ContainerLabels: ContainerLabelOptions{
						Enabled:     true,
						LabelPrefix: "com.sockguard.allow.",
					},
				}, fakeResolver{
					found: true,
					client: resolvedClient{
						Labels: map[string]string{"com.sockguard.allow.get": tt.label},
					},
				}.resolveClient)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					*reached = true
					w.WriteHeader(http.StatusAccepted)
				}))
			}

			reached := false
			req := httptest.NewRequest(http.MethodGet, tt.allowed, nil)
			req.RemoteAddr = "172.18.0.5:45678"
			rec := httptest.NewRecorder()
			newHandler(&reached).ServeHTTP(rec, req)
			if !reached || rec.Code != http.StatusAccepted {
				t.Fatalf("GET %s with label %q = %d (reached=%v), want %d",
					tt.allowed, tt.label, rec.Code, reached, http.StatusAccepted)
			}

			if tt.denied == "" {
				return
			}
			reached = false
			req = httptest.NewRequest(http.MethodGet, tt.denied, nil)
			req.RemoteAddr = "172.18.0.5:45678"
			rec = httptest.NewRecorder()
			newHandler(&reached).ServeHTTP(rec, req)
			if reached || rec.Code != http.StatusForbidden {
				t.Fatalf("GET %s with label %q = %d (reached=%v), want %d",
					tt.denied, tt.label, rec.Code, reached, http.StatusForbidden)
			}
		})
	}
}
