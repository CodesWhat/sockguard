package cmd

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const (
	reasonCodeRequestTargetNotRooted  = "request_target_not_rooted"
	requestTargetNotRootedDenyMessage = "request target must be a path beginning with '/'"
)

// withRequestTargetGuard rejects a request whose target is not a rooted path,
// which is every HTTP/1.1 request-target form except origin-form and an
// absolute-form URI that carries a path.
//
// Go's server parses each of the other forms without complaint and hands the
// handler a request the Docker API cannot describe:
//
//   - "GET * HTTP/1.1" (asterisk-form) arrives with r.URL.Path == "*".
//     The server intercepts only "OPTIONS *" (globalOptionsHandler, disabled
//     by http.Server.DisableGeneralOptionsHandler, which sockguard leaves at
//     its default), so every other method's asterisk-form reaches the chain.
//   - "GET http://host HTTP/1.1" with no path, "GET foo:bar" (opaque), and
//     "CONNECT host:port" (authority-form) all arrive with r.URL.Path == "".
//
// NormalizePath preserves both shapes verbatim, so before this guard they
// reached rule evaluation unrooted. A catch-all "/**" allow rule admitted
// them on the match-all fast path even though the regex that pattern stands
// for, "^(/(?s:.*))?$", does not match "*" — the same fast-path/regex
// divergence as the rootless-pattern and literal-prefix fixes. The forwarded
// request would then not even have been the one evaluated: url.URL.RequestURI
// substitutes "/" for an empty path, so the daemon would have seen "GET /"
// where policy saw "".
//
// Rejecting is the fail-closed answer rather than canonicalizing to "/": no
// Docker or Podman endpoint is addressed by "*" or by an empty path, so there
// is nothing to preserve, and 400 is what the rest of the proxy already
// returns for a request it cannot parse into a policy decision (an
// unparseable container-remove query, a resource-limit request whose shape is
// invalid). Canonicalizing would instead invent a target the client never
// sent and hand it to the rule set.
//
// The layer sits inside access/audit logging, request-ID and trace
// correlation, and the metrics recorder so the rejection is a first-class
// denial in every observability surface, and outside clientacl so no
// container-label ACL ever matches an unrooted path either — a label granting
// "/**" compiles to the same match-all matcher.
//
// It is a hard rejection in every rollout mode, like the resource-limit
// guard's malformed-request 400s: warn and audit exist to preview what a
// policy would block, and this is not a policy decision but a request the
// proxy cannot turn into one.
//
// Only the main chain carries it. The dedicated admin listener
// (buildAdminHandlerChain) does no glob matching at all — its endpoints
// compare exact paths — so an unrooted target there already falls through to
// that chain's 404 terminal with an admin_unknown_path reason code, reaching
// neither policy evaluation nor the daemon.
func withRequestTargetGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL == nil || !strings.HasPrefix(r.URL.Path, "/") {
				logging.SetDeniedWithCode(w, r, reasonCodeRequestTargetNotRooted,
					requestTargetNotRootedDenyMessage, filter.NormalizePath)
				_ = httpjson.Write(w, http.StatusBadRequest,
					httpjson.ErrorResponse{Message: requestTargetNotRootedDenyMessage})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
