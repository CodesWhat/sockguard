package differential

import (
	"net/http"
	"testing"
)

// TestPathDifferentialExtendedEvasionAxes extends the corpus in
// path_differential_test.go with axes the original ~30-case table did
// not exercise. Same policy ({GET /containers/json}, default-deny
// otherwise), same bypass-vs-honest-divergence framing. Every case
// here is net-new — not a duplicate of TestPathDifferentialNoEndpointEscalation.
//
// Axes covered here:
//
//   - Pathological Docker API version prefixes (`v0`, bare `v`, three-part
//     `v1.45.99`) — version-prefix regex was tested against `v1`, `v1.45`,
//     and double-zero forms; these poke at the boundary.
//   - Repeated slashes beyond two in a row, and a leading single-dot
//     segment — extra normalization shapes path.Clean must handle.
//   - Encoded whitespace in path segments (space, tab, LF, CR) — the
//     control characters that adjacent layers (req-line parser, log
//     formatter) might mishandle. Anything decoded into the segment
//     must not silently land on /containers/json.
//   - Encoded backslash — Windows-style separator that net/http treats
//     as a literal path byte; must never collapse to a slash.
func TestPathDifferentialExtendedEvasionAxes(t *testing.T) {
	t.Parallel()

	daemon := newRecordingDaemon(t)
	chain := buildChain(t, daemon.socketPath, allowRule(http.MethodGet, "/containers/json"))

	safeDaemonRoutes := map[RouteCategory]bool{
		RouteContainerList: true,
		RouteUnknown:       true,
	}

	tests := []struct {
		name        string
		method      string
		target      string
		wantAllowed bool
	}{
		// --- pathological version prefixes ---
		// The version-strip regex must accept exactly /vN or /vN.N. Bare
		// 'v' and three-part versions are not Docker version prefixes;
		// they remain literal path segments that do not match the
		// allow rule.
		{"version zero is a valid prefix", http.MethodGet, "/v0/containers/json", true},
		{"bare v is not a version prefix", http.MethodGet, "/v/containers/json", false},
		{"three-part version is not a version prefix", http.MethodGet, "/v1.45.99/containers/json", false},

		// --- repeated slashes and leading-dot segment ---
		// path.Clean collapses any run of slashes to one and drops a
		// "./" prefix; the daemon's router does the same. Both views
		// must converge to /containers/json.
		{"triple leading slash", http.MethodGet, "///containers/json", true},
		{"four interior slashes", http.MethodGet, "/containers////json", true},
		{"leading single-dot segment", http.MethodGet, "/./containers/json", true},

		// --- encoded whitespace in path ---
		// %20 (space) and %09 (tab) are literal bytes inside path
		// segments; they must not silently collapse to /containers/json.
		// %0a and %0d (LF/CR) are the control bytes that worry request
		// smugglers — net/http rejects literal CRLF in the request line,
		// but percent-encoded forms reach the application layer as
		// literal bytes in a segment and must stay isolated there.
		{"encoded space in last segment", http.MethodGet, "/containers/json%20", false},
		{"encoded tab in last segment", http.MethodGet, "/containers/json%09", false},
		{"encoded LF in last segment", http.MethodGet, "/containers/json%0a", false},
		{"encoded CR in last segment", http.MethodGet, "/containers/json%0d", false},

		// --- encoded backslash ---
		// '\' is a literal path byte in URLs; net/http does not promote
		// it to '/'. /containers%5cjson decodes to /containers\json,
		// which is one path segment and does not match the policy.
		{"encoded backslash in path", http.MethodGet, "/containers%5cjson", false},
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
				if res.statusCode != http.StatusForbidden {
					t.Fatalf("%s %q was denied with status %d, want %d",
						tt.method, tt.target, res.statusCode, http.StatusForbidden)
				}
				return
			}

			route := ClassifyDockerRoute(tt.method, fwd.Path)
			if !safeDaemonRoutes[route] {
				t.Fatalf("BYPASS: sockguard allowed %s %q under policy {GET /containers/json}, "+
					"but the daemon received %q which routes to %q",
					tt.method, tt.target, fwd.Path, route)
			}
		})
	}
}
