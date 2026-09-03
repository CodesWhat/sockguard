package visibility

import (
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// LibpodEventsPath is the normalized path of Podman's native
// GET /libpod/events endpoint.
//
// It is not a spelling of "/events": NormalizePath strips the API version
// prefix but not the "/libpod" segment, so /v5.8.1/libpod/events — what a
// Podman binding actually sends — normalizes here and never onto the
// Docker-compat path. Podman serves BOTH from one handler
// (pkg/api/server/register_events.go at v5.8.1 registers /events and
// /libpod/events on compat.GetEvents), so the two accept the identical
// `filters` query shape: a JSON-encoded map[string][]string, read by
// util.FiltersFromRequest — which also accepts Docker's legacy
// map[string]map[string]bool spelling, and prefers a lowercase `filters`
// parameter over a capitalized `Filters` one.
const LibpodEventsPath = libpodPrefix + "events"

// libpodEventsDenyReason is the operator-facing reason this middleware reports
// when it refuses GET /libpod/events.
//
// The endpoint IS scopeable, unlike /libpod/system/df: Podman stamps a
// container's labels onto its container events (libpod/events.go builds every
// container event with Details.Attributes = c.Labels()), and the `label` event
// filter matches against exactly that map. Injecting one selector therefore
// isolates it correctly, and that is what happens for a single-selector
// policy.
//
// What cannot be expressed is a policy with MORE than one selector. Podman
// evaluates event filters with libpod/events/filters.go's applyFilters, whose
// own comment reads "Filters under the same key are disjunctive while each key
// must match" — every `label=` value lands under the one "label" key, so two
// selectors are ORed. Visibility selectors are ANDed by definition
// (matchesSelectors requires every one of them), and there is no second filter
// key to put the extra selector under: generateEventFilter accepts only
// container, event/status, image, pod, volume, type and label, and errors on
// anything else. So a two-selector policy injected as two values would return
// every event matching EITHER selector — strictly more than the policy allows.
//
// Filtering the response instead is not available here the way it is for
// /system/df. /libpod/events is a streamed NDJSON endpoint — internal/proxy's
// isLongLivedUpstreamRequest already exempts it from the per-request upstream
// deadline for exactly that reason — and this package's response-side
// filtering buffers the whole body before rewriting it, which would convert a
// long-lived event stream into a request that never returns.
//
// So the endpoint is refused. Reporting a subset would be the dishonest
// alternative in the same way an emptied /libpod/system/df report was: a
// client watching an event stream cannot tell a quiet host from a filter that
// silently stopped applying.
const libpodEventsDenyReason = "libpod events denied: " +
	"GET /libpod/events filters labels disjunctively, so a visibility policy with more than one " +
	"visible_resource_labels selector cannot be enforced on it"

// handleLibpodVisibilityEventsRequest applies the visibility policy to
// GET /libpod/events.
//
// The three branches are the three things the endpoint's filter semantics
// allow:
//
//   - No selectors (a patterns-only policy): forwarded untouched, exactly as
//     the Docker-compat /events is. Pattern axes reach neither endpoint —
//     needsPatternResponseFilter covers the four container/image list
//     endpoints and nothing else — and compileVisibilityPolicies already warns
//     at startup that a patterns-only policy leaves the event stream
//     unrestricted.
//   - One selector: injected as the sole `label` filter value.
//   - Two or more: refused. See libpodEventsDenyReason.
//
// Like denyLibpodSystemDataUsage, the refusal does not honor
// RequestMeta.AllowsPassThrough. A warn-mode deployment forwarding the
// unfiltered stream is the exact disclosure this closes, and a stream is not a
// verdict an operator can measure the impact of after the fact.
func handleLibpodVisibilityEventsRequest(next http.Handler, w http.ResponseWriter, r *http.Request, policy *compiledPolicy) {
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
		denyLibpodEvents(w, r)
	}
}

// denyLibpodEvents refuses GET /libpod/events with a 403 without contacting
// the upstream, so no event belonging to another tenant is ever read.
//
// The status is 403 rather than the 404 handleVisibilityInspectRequest returns
// for a hidden resource, for the same reason denyLibpodSystemDataUsage uses
// 403: 404 exists there to deny an existence oracle for a caller-named
// resource, and /libpod/events is a fixed endpoint of the Podman API whose
// existence is public.
func denyLibpodEvents(w http.ResponseWriter, r *http.Request) {
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityLibpodEvents, libpodEventsDenyReason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: libpodEventsDenyReason})
}
