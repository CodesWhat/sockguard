package responsefilter

import (
	"errors"
	"net/http"
)

// conditionalRequestHeaders is the RFC 9110 §13.1 precondition set: the
// request headers that ask an upstream to answer with a validator verdict —
// 304 Not Modified or 412 Precondition Failed — instead of the
// representation itself.
//
// All five are listed, including the two that cannot produce a 304 on their
// own. If-Match and If-Unmodified-Since are evaluated against the daemon's
// validator for the body the daemon holds, and that is not the body this
// proxy returns: every read-side filter either rewrites it, drops items out
// of it, or refuses it. A precondition on a representation the client never
// receives has nothing to be true about.
var conditionalRequestHeaders = [...]string{
	"If-Match",
	"If-Modified-Since",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
}

// errNotModifiedRevalidation is the response-filter refusal for a 304 that
// arrives anyway. See Filter.ModifyResponse.
var errNotModifiedRevalidation = errors.New("upstream answered 304 Not Modified; sockguard cannot revalidate a cached copy of a filtered representation")

// StripConditionalRequestHeaders removes every conditional request header from
// header, so the upstream answers with the representation the read-side
// filters can inspect rather than a 304 confirming whatever the client already
// holds.
//
// The cached copy is the problem. It was produced under the policy in force
// when the client fetched it, which may be no policy at all — the visibility
// axes, the owner label and the redaction options are all hot-reloadable, and
// the ETag a client revalidates against is the daemon's, computed over the
// unfiltered body. Forwarding the conditional request lets the daemon confirm
// that copy without a single byte passing a filter, so every read-side control
// is skipped by a client that fetched once before the policy tightened.
//
// dockerd and Podman emit neither ETag nor Last-Modified on the JSON API
// routes today, so a conditional request against them is already answered with
// a full 200 and this strip changes nothing observable. It is here so the
// fail-closed guarantee holds against the upstreams this proxy does not
// control rather than against the one it was tested on.
func StripConditionalRequestHeaders(header http.Header) {
	for _, name := range conditionalRequestHeaders {
		header.Del(name)
	}
}
