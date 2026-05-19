package differential

import (
	"net/http"
	"testing"
)

// TestPathDifferentialNoEndpointEscalation is the core parser-differential
// test. It pins one narrow policy — allow only GET /containers/json, a
// read-only container list — and fires a corpus of crafted paths at it, each
// designed to make sockguard's normalized view of the request disagree with
// the view the daemon routes on.
//
// The invariant under test: whenever sockguard *allows* a request, the
// endpoint the daemon actually resolves must be one sockguard's policy would
// also permit. With this policy the only permitted daemon outcomes are:
//
//   - routeContainerList — the endpoint sockguard judged, executed faithfully;
//   - routeUnknown — the daemon routes nowhere (404/405) and executes nothing.
//
// Any other route means a client smuggled a forbidden endpoint past the
// filter: a policy bypass. The corpus deliberately includes cases where
// sockguard and the daemon *do* diverge (e.g. double percent-encoding) to
// prove the harness observes the divergence and still classifies it correctly
// — divergence is only a bypass when it escalates to a real, forbidden route.
func TestPathDifferentialNoEndpointEscalation(t *testing.T) {
	t.Parallel()

	daemon := newRecordingDaemon(t)
	// The entire policy: one exact-path allow rule. Everything else is
	// default-deny. A request is "safe to allow" only if the daemon would
	// route it to the same read sockguard judged, or to nothing at all.
	chain := buildChain(t, daemon.socketPath, allowRule(http.MethodGet, "/containers/json"))

	safeDaemonRoutes := map[routeCategory]bool{
		routeContainerList: true,
		routeUnknown:       true,
	}

	tests := []struct {
		name        string
		method      string
		target      string
		wantAllowed bool
	}{
		// --- Docker API version prefix ---
		// sockguard strips a strict /vN or /vN.N prefix before matching; the
		// daemon strips a broader /v{[0-9.]+} prefix. Stripped paths must land
		// on the same endpoint; unstrippable prefixes must fall through to deny.
		{"baseline exact path", http.MethodGet, "/containers/json", true},
		{"version prefix v1.45", http.MethodGet, "/v1.45/containers/json", true},
		{"version prefix v1", http.MethodGet, "/v1/containers/json", true},
		{"version prefix v9.99", http.MethodGet, "/v9.99/containers/json", true},
		{"version prefix with leading zero", http.MethodGet, "/v01.45/containers/json", true},
		{"uppercase V is not a version prefix", http.MethodGet, "/V1.45/containers/json", false},
		{"only one version prefix is stripped", http.MethodGet, "/v1.45/v1.46/containers/json", false},

		// --- dot-segment and slash normalization ---
		// sockguard runs path.Clean on the decoded path; the daemon's router
		// does the same. They must agree on where ".." and "//" resolve to.
		{"trailing slash", http.MethodGet, "/containers/json/", true},
		{"leading doubled slash", http.MethodGet, "//containers/json", true},
		{"interior doubled slash", http.MethodGet, "/containers//json", true},
		{"single-dot segment", http.MethodGet, "/containers/./json", true},
		{"dot-dot resolving back to json", http.MethodGet, "/containers/json/../json", true},
		{"dot-dot from create to json", http.MethodGet, "/containers/create/../json", true},
		{"excess dot-dot cannot climb past root", http.MethodGet, "/containers/json/../../../containers/json", true},
		{"dot-dot into create (GET)", http.MethodGet, "/containers/json/../create", false},
		{"dot-dot into create (POST)", http.MethodPost, "/containers/json/../create", false},
		{"dot-dot escaping to exec start", http.MethodPost, "/containers/json/../../exec/abc/start", false},

		// --- case sensitivity ---
		// Docker routes path segments case-sensitively; so must sockguard.
		{"capitalized first segment", http.MethodGet, "/Containers/json", false},
		{"capitalized last segment", http.MethodGet, "/containers/JSON", false},

		// --- separator and injection tricks ---
		// A matrix-param ';', an injected ';', and a NUL byte are all literal
		// path characters to Go's parser — none collapse to /containers/json.
		{"matrix parameter suffix", http.MethodGet, "/containers/json;ignore=1", false},
		{"semicolon in first segment", http.MethodGet, "/containers;x/json", false},
		{"trailing NUL byte", http.MethodGet, "/containers/json%00", false},

		// --- percent-encoding ---
		// sockguard decodes up to two layers of percent-encoding; the daemon
		// decodes one. Single-encoded paths converge on both sides. Double
		// encoding makes sockguard see /containers/json while the daemon sees
		// a literal %XX segment — a divergence, but a safe one: the daemon
		// routes nowhere (routeUnknown), it cannot reach a different endpoint.
		{"encoded last segment", http.MethodGet, "/containers/%6a%73%6f%6e", true},
		{"encoded separator", http.MethodGet, "/containers%2Fjson", true},
		{"double-encoded last segment", http.MethodGet, "/containers/%256a%2573%256f%256e", true},
		{"encoded dot-dot into create (POST)", http.MethodPost, "/containers/json/%2e%2e/create", false},
		{"encoded dot-dot from create to json", http.MethodGet, "/containers/create/%2e%2e/json", true},

		// --- query string and method ---
		{"query string is ignored by path matching", http.MethodGet, "/containers/json?all=1", true},
		{"correct path with wrong method", http.MethodPost, "/containers/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, fwd := sendRequest(t, chain, daemon, tt.method, tt.target, nil)

			if res.allowed != tt.wantAllowed {
				t.Fatalf("%s %q: allowed = %v, want %v (status %d, body %q)",
					tt.method, tt.target, res.allowed, tt.wantAllowed, res.statusCode, res.body)
			}

			if !res.allowed {
				// A denial must come from the filter (403), not from a proxy
				// failure (502) that would also leave the daemon untouched.
				if res.statusCode != http.StatusForbidden {
					t.Fatalf("%s %q was denied with status %d, want %d",
						tt.method, tt.target, res.statusCode, http.StatusForbidden)
				}
				return
			}

			// Allowed: the daemon received the request. Classify the endpoint
			// it would actually execute against what sockguard's policy permits.
			route := classifyDockerRoute(tt.method, fwd.Path)
			if !safeDaemonRoutes[route] {
				t.Fatalf("BYPASS: sockguard allowed %s %q under policy {GET /containers/json}, "+
					"but the daemon received %q which routes to %q",
					tt.method, tt.target, fwd.Path, route)
			}
		})
	}
}
