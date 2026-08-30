package visibility

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// compatEventsPath is the normalized path of the Docker-compat event stream.
// It is the spelling every Docker client sends, and — because Podman
// registers /events and /libpod/events on one handler
// (pkg/api/server/register_events.go at v5.8.1 puts compat.GetEvents behind
// both) — the spelling that carries Podman's filter semantics on a Podman
// upstream while carrying dockerd's on a Docker one.
const compatEventsPath = "/events"

// podmanEventsDenyReason is the operator-facing reason the middleware reports
// when it refuses GET /events against a Podman upstream.
//
// The endpoint is scopeable with ONE selector and no more. Podman stamps a
// container's labels onto its container events, and the `label` event filter
// matches against exactly that map, so a single injected value isolates
// correctly. What cannot be expressed is a policy with more than one
// selector: libpod/events/filters.go's applyFilters carries the comment
// "Filters under the same key are disjunctive while each key must match
// (conjuctive)", and util.FiltersFromRequest flattens every value of the
// `label` key into that one key, so two selectors are ORed. Visibility
// selectors are ANDed by definition (a resource must satisfy every one), and
// there is no second filter key to hold the extra selector —
// generateEventFilter accepts only container, event/status, image, pod,
// volume, type and label, and errors on anything else. Injecting two values
// would therefore stream every event matching EITHER selector, which is
// strictly more than the policy allows.
//
// Filtering the response instead is not available. /events is a long-lived
// NDJSON stream — proxy.isLongLivedUpstreamRequest already exempts it from
// the per-request upstream deadline for that reason — and this package's
// response-side filtering buffers the whole body before rewriting it, which
// would turn an event stream into a request that never returns.
//
// So it is refused. Streaming a superset would be the dishonest alternative:
// a client watching an event stream cannot tell a quiet host from a filter
// that silently stopped applying.
const podmanEventsDenyReason = "events denied: this upstream is Podman, whose GET /events filters labels " +
	"disjunctively, so a visibility policy with more than one visible_resource_labels selector cannot be " +
	"enforced on it"

// handlePodmanCompatEventsRequest applies the visibility policy to
// GET /events when the upstream is Podman.
//
// The three branches are the three things Podman's filter semantics allow:
//
//   - No selectors (a patterns-only policy): forwarded untouched, exactly as
//     it is on a Docker upstream. Pattern axes do not reach this endpoint on
//     either engine — needsPatternResponseFilter covers the four
//     container/image list endpoints and nothing else — and
//     compileVisibilityPolicies already warns at startup that a patterns-only
//     policy leaves the event stream unrestricted.
//   - One selector: written as the sole `label` filter value.
//   - Two or more: refused, without contacting the upstream, so no event
//     belonging to another tenant is ever read.
//
// The refusal does not consult RequestMeta.AllowsPassThrough, unlike the
// hidden-resource 404 in handleVisibilityInspectRequest. Warn mode exists to
// let an operator measure the impact of a deny before enforcing it, and that
// trade works for a single request: one response goes out, one would_deny
// record goes in the log. It does not work here. Forwarding means the
// unfiltered stream — the exact disclosure this closes — runs for as long as
// the client holds the connection, and there is no after-the-fact measurement
// of a stream the operator can weigh against it.
func handlePodmanCompatEventsRequest(next http.Handler, w http.ResponseWriter, r *http.Request, policy *compiledPolicy) {
	switch len(policy.selectors) {
	case 0:
		next.ServeHTTP(w, r)
	case 1:
		forwarded, err := setPodmanEventLabelFilter(r, policy.selectors[0])
		if err != nil {
			logging.SetDeniedWithCode(w, r, reasonCodeVisibilityFilterInvalid, err.Error(), nil)
			_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
			return
		}
		next.ServeHTTP(w, forwarded)
	default:
		denyPodmanCompatEvents(w, r)
	}
}

// denyPodmanCompatEvents refuses the request with a 403.
//
// The status is 403 rather than the 404 handleVisibilityInspectRequest
// returns for a hidden resource: 404 exists there to deny an existence oracle
// for a caller-named resource, and /events is a fixed endpoint of the API
// whose existence is public.
func denyPodmanCompatEvents(w http.ResponseWriter, r *http.Request) {
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPodmanEvents, podmanEventsDenyReason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: podmanEventsDenyReason})
}

// setPodmanEventLabelFilter REPLACES the `label` filter key with the policy's
// single selector, rather than appending to it the way
// addVisibilityLabelFilters does on every other list endpoint and on this one
// against a Docker upstream.
//
// Appending is safe on a conjunctive filter: dockerd ANDs event label pairs
// through filters.Args.MatchKVList, and so do Podman's own LIST endpoints,
// which run label filters through filters.MatchLabelFilters (containers,
// volumes, networks) or libimage's applyFilters for images, both of which
// require every value to match. Podman's EVENT filter is the one that does
// not. A client-supplied `label` value would sit beside the injected selector
// under the same disjunctive key, so a caller could name any label a hidden
// container carries and be handed its events. Unconditional replacement is
// the same defense internal/ownership's addOwnerLabelFilter already applies,
// for the same reason — and it is why owner isolation was never exposed here.
//
// The query is re-encoded on every request rather than short-circuited when
// the selector already appears. That matters beyond tidiness:
// dockerfilters.Decode also accepts Docker's legacy map[string]map[string]bool
// spelling, so leaving the raw query untouched would forward a client-authored
// encoding of it carrying extra label values the decode had already seen.
func setPodmanEventLabelFilter(r *http.Request, selector compiledSelector) (*http.Request, error) {
	query := r.URL.Query()
	filters, err := dockerfilters.Decode(query.Get("filters"))
	if err != nil {
		return r, err
	}
	value := selector.key
	if selector.hasValue {
		value += "=" + selector.value
	}
	filterKey := visibilityLabelFilterKey(compatEventsPath)
	filters[filterKey] = []string{value}
	encoded, err := json.Marshal(filters)
	if err != nil {
		return r, fmt.Errorf("encode filters: %w", err)
	}
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	// Podman's event handler ORs repeated values under one key, so this
	// selector has to remain the sole label value. A later owner-isolation
	// layer sees the marker and refuses the request rather than dropping this
	// visibility constraint or appending an owner value that would widen it.
	return dockerfilters.RecordSoleValueFilter(r, filterKey), nil
}
