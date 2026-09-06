package logging

import (
	"net/http"
	"net/url"
)

// RequestQuery returns the request's parsed query string, reusing the parse
// already performed for this request instead of running another one.
//
// url.URL.Query() re-parses RawQuery and allocates a fresh url.Values on every
// call, so a request whose query several middlewares and inspectors read paid
// for the same parse several times: three times for a swarm update (one per
// rotate* flag), twice for a service update in the resource-limit guard, twice
// for the proxy's ?stream= classification. The parse is memoized on the
// request's RequestMeta, which is the per-request state the chain already
// threads through the wrapped ResponseWriter and the request context, so the
// memo costs no extra allocation on requests that read the query once or not
// at all.
//
// The memo is keyed on the raw query string rather than a bare "already
// parsed" flag because there are two ways a key can go stale, and both are
// live in this chain:
//
//   - A middleware downstream of the filter can rewrite r.URL.RawQuery.
//     ownership and visibility both do, to scope a list to the caller's own
//     resources, and the proxy's request-deadline classifier reads the query
//     after them. A parse cached before the rewrite would answer for the
//     query the client sent rather than the one going upstream.
//   - RequestMeta is recycled through a sync.Pool. A meta handed to a later
//     request carries whatever the previous one left behind until it is
//     zeroed; comparing the raw string means a stale memo can only ever be
//     reused for a byte-identical query, which parses to the same values.
//
// The returned url.Values is SHARED with every other reader of this request
// and must be treated as read-only. Callers that need to fold, filter, or
// rewrite keys build their own map from it (see filter.foldQueryKeys).
//
// When no RequestMeta is attached — a unit test exercising an inspector
// directly, or any caller outside the serve chain — this falls back to a plain
// parse, so behavior is identical with or without the memo.
func RequestQuery(r *http.Request) url.Values {
	values, _ := ParseRequestQuery(r)
	return values
}

// ParseRequestQuery is RequestQuery plus the url.ParseQuery error that
// url.URL.Query() discards. Callers that reject a malformed query outright,
// rather than acting on the partial values Query() hands back, need the error;
// routing both kinds of caller through here keeps them on one parse.
func ParseRequestQuery(r *http.Request) (url.Values, error) {
	if r == nil || r.URL == nil {
		return nil, nil
	}
	raw := r.URL.RawQuery
	meta := Meta(r.Context())
	if meta == nil {
		return url.ParseQuery(raw)
	}
	if meta.queryParsed && meta.queryRaw == raw {
		return meta.queryValues, meta.queryErr
	}
	values, err := url.ParseQuery(raw)
	meta.queryRaw = raw
	meta.queryValues = values
	meta.queryErr = err
	meta.queryParsed = true
	return values, err
}
