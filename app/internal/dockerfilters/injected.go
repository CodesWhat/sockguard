package dockerfilters

import (
	"context"
	"net/http"
	"slices"
)

// Two middlewares write the same `filters` query key on the same request:
// visibility appends its configured label selectors, and ownership then
// replaces the key with the proxy-enforced owner label. Replacement is
// deliberate — a client-supplied label selector must never reach the daemon
// on an ownership-scoped list, because Swarm's control-plane list endpoints
// fold `label` values into a map[string]string
// (daemon/cluster/filters.go: convertKVStringsToMap over Args.Get, whose
// iteration order is randomized), so a client value repeating the owner key
// can silently displace the proxy's.
//
// Replacing everything, though, also discarded the selectors visibility had
// just injected, leaving the request owner-scoped but not visibility-scoped —
// a silent widening. The two layers have to compose.
//
// They compose through this record: a layer that injects selectors notes them
// on the request, and a later layer that must drop client-supplied values can
// tell the two apart. Values from separate layers then arrive together under
// one key, which both engines AND:
//
//   - Docker: api/types/filters.Args.MatchKVList, used by every list endpoint
//     that honors `label` (daemon/list.go, daemon/images/image_list.go,
//     daemon/network/filter.go, volume/service/by.go, daemon/events/filter.go),
//     returns false unless EVERY value matches.
//   - Podman: containers/common/pkg/filters.MatchLabelFilters returns false on
//     the first value with no matching label.
//
// This is the exception to the usual "one filter key is an OR" reading: `label`
// is matched key-by-key against a label map, not disjunctively against a single
// field the way `name` or `status` are (Args.Match).
//
// The record is per-request state, so it lives in the request context rather
// than in a package-level map: middlewares run concurrently across requests.

type injectedContextKey struct{}

// RecordInjectedSelectors returns a request whose context notes values as
// filter values this proxy injected under filterKey, in addition to anything
// already recorded for that key. It returns r unchanged when there is nothing
// to record.
//
// Call it for every selector the layer enforces, including one the client
// happened to send already: a later layer drops client-supplied values, and a
// policy-enforced selector must survive that drop whether or not this layer
// had to write it.
func RecordInjectedSelectors(r *http.Request, filterKey string, values []string) *http.Request {
	if r == nil || len(values) == 0 {
		return r
	}
	ctx := r.Context()
	existing, _ := ctx.Value(injectedContextKey{}).(map[string][]string)
	merged := make(map[string][]string, len(existing)+1)
	for key, recorded := range existing {
		merged[key] = recorded
	}
	// slices.Clip caps the shared slice at its length so the append below
	// copies instead of writing into the previous record's backing array.
	merged[filterKey] = append(slices.Clip(merged[filterKey]), values...)
	return r.WithContext(context.WithValue(ctx, injectedContextKey{}, merged))
}

// InjectedSelectors returns the filter values this proxy injected under
// filterKey earlier in the request's middleware chain, in injection order. It
// returns nil when no layer injected anything, which is the ordinary case for
// an endpoint only one layer rewrites.
//
// The returned slice aliases the record; callers must not append to it in
// place.
func InjectedSelectors(r *http.Request, filterKey string) []string {
	if r == nil {
		return nil
	}
	recorded, _ := r.Context().Value(injectedContextKey{}).(map[string][]string)
	return recorded[filterKey]
}
