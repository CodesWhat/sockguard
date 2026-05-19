package differential

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/codeswhat/sockguard/internal/filter"
)

// FuzzPathRoutingDifferential is the fuzzing counterpart of
// TestPathDifferentialNoEndpointEscalation. That test pins one narrow policy —
// allow only GET /containers/json — and fires a hand-written corpus of crafted
// paths at it; this fuzzer pins the same policy and lets the fuzzing engine
// mutate the path (and method) freely, searching for a crafted request the
// table never thought of.
//
// It is pure-logic: no sockets, no recording daemon. url.ParseRequestURI is the
// exact parser net/http's server applies to a request line, so u.Path is the
// path sockguard's filter sees. filter.Evaluate yields sockguard's allow/deny
// verdict, and classifyDockerRoute models the endpoint the daemon would route
// to. Skipping the proxy round-trip keeps each execution cheap enough for the
// per-PR fuzz budget while still exercising the real normalization code.
//
// The invariant: whenever sockguard *allows* a request, the endpoint the daemon
// resolves must be one the policy would also permit — routeContainerList (the
// read sockguard judged) or routeUnknown (the daemon routes nowhere, 404/405).
// Any other route means a client smuggled a forbidden endpoint past the filter.
// The over-decode bypass that motivated the NormalizePath fix —
// GET /containers/%252e/json normalizing to /containers/json for sockguard
// while the daemon routes the literal /containers/%2e/json to container.inspect
// — is seeded directly so regressions are caught on the first execution.
func FuzzPathRoutingDifferential(f *testing.F) {
	// The entire policy: one exact-path allow rule. Everything else is
	// default-deny. A request is safe to allow only if the daemon would route
	// it to the same read sockguard judged, or to nothing at all.
	rule, err := filter.CompileRule(filter.Rule{
		Methods: []string{http.MethodGet},
		Pattern: "/containers/json",
		Action:  filter.ActionAllow,
		Index:   0,
	})
	if err != nil {
		f.Fatalf("compile policy rule: %v", err)
	}
	rules := []*filter.CompiledRule{rule}

	safeDaemonRoutes := map[routeCategory]bool{
		routeContainerList: true,
		routeUnknown:       true,
	}

	seeds := []struct {
		method string
		target string
	}{
		{http.MethodGet, "/containers/json"},
		{http.MethodGet, "/v1.45/containers/json"},
		{http.MethodGet, "/v1.45/v1.46/containers/json"},
		{http.MethodGet, "/containers/json/"},
		{http.MethodGet, "//containers/json"},
		{http.MethodGet, "/containers//json"},
		{http.MethodGet, "/containers/./json"},
		{http.MethodGet, "/containers/json/../json"},
		{http.MethodGet, "/containers/json/../create"},
		{http.MethodGet, "/containers/json/../../exec/abc/start"},
		{http.MethodGet, "/containers/%6a%73%6f%6e"},
		{http.MethodGet, "/containers%2Fjson"},
		{http.MethodGet, "/containers/%256a%2573%256f%256e"},
		{http.MethodGet, "/containers/%252e/json"}, // the over-decode bypass trigger
		{http.MethodGet, "/containers/%2e/json"},
		{http.MethodGet, "/containers/%2e%2e/create"},
		{http.MethodGet, "/images/json"},
		{http.MethodGet, "/exec/abc/json"},
		{http.MethodGet, "/containers/json?all=1"},
		{http.MethodGet, "/containers/json;ignore=1"},
		{http.MethodGet, "/Containers/json"},
		{http.MethodPost, "/containers/json"},
		{http.MethodPost, "/containers/json/../create"},
		{http.MethodPost, "/containers/json/../../exec/abc/start"},
		{"get", "/containers/json"},
	}
	for _, s := range seeds {
		f.Add(s.method, s.target)
	}

	f.Fuzz(func(t *testing.T, method, target string) {
		// url.ParseRequestURI is the parser net/http's server applies to the
		// request line — a target it rejects would never reach the filter.
		u, err := url.ParseRequestURI(target)
		if err != nil {
			return
		}
		req := &http.Request{Method: method, URL: u}

		action, _, _ := filter.Evaluate(rules, req)
		if action != filter.ActionAllow {
			return
		}

		// sockguard allowed the request, so the proxy forwards it and the
		// daemon routes on its own view of the path. The proxy forwards
		// EscapedPath(), which the daemon decodes back to this same u.Path, so
		// classifyDockerRoute models the daemon's routing of u.Path.
		route := classifyDockerRoute(method, u.Path)
		if !safeDaemonRoutes[route] {
			t.Errorf("BYPASS: sockguard allowed %s %q under policy {GET /containers/json}, "+
				"but the daemon would route %q to %q",
				method, target, u.Path, route)
		}
	})
}
