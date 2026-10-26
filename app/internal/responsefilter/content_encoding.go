package responsefilter

import (
	"io"
	"net/http"

	"github.com/codeswhat/sockguard/v2/app/internal/bodycodec"
	requestfilter "github.com/codeswhat/sockguard/v2/app/internal/filter"
)

// identityContentCoding is RFC 9110 §8.4.1's "no transformation" coding. It is
// the only response encoding this package can hand to a JSON decoder as it
// stands, and the only one it asks an upstream for.
const identityContentCoding = bodycodec.Identity

// PinIdentityAcceptEncoding replaces Accept-Encoding on an upstream-bound
// request with identity, so the daemon answers with the bytes the read-side
// filters can parse.
//
// It is a Set and not a Del, and the difference is not stylistic. net/http's
// Transport adds "Accept-Encoding: gzip" to any request that carries none and
// then transparently decompresses the response, so deleting the header hands
// the decision to a code path this package does not control: the upstream
// still compresses, and the guarantee that ModifyResponse sees identity bytes
// rests on Transport internals rather than on anything stated here. Setting
// identity keeps Transport out of it — a non-empty Accept-Encoding suppresses
// the automatic gzip — and tells the far side, including anything terminating
// TLS in front of a remote daemon, not to compress in the first place.
//
// Nothing is lost against a real daemon. Neither dockerd nor Podman runs a
// compression middleware on the JSON API, so identity is what they answer
// with anyway; the coding only ever appears when a proxy in between adds one.
//
// Vary needs no handling. The client's Accept-Encoding no longer reaches the
// upstream and no longer influences the response, so there is no
// per-encoding variance for a cache to key on.
//
// It runs unconditionally, alongside StripConditionalRequestHeaders and for
// the same reason: the response filter has no request-side hook of its own,
// and its path set is a dispatch table rather than a predicate a middleware
// could consult without going stale.
func PinIdentityAcceptEncoding(header http.Header) {
	header.Set("Accept-Encoding", identityContentCoding)
}

// decodedResponseReader returns a reader over resp.Body's identity-encoded
// bytes, decompressing when the upstream compressed anyway.
//
// PinIdentityAcceptEncoding makes this the unlikely path rather than the dead
// one. An upstream is free to ignore Accept-Encoding, and a client that
// reaches a remote daemon through a TLS-terminating proxy is exactly where an
// unsolicited Content-Encoding comes from. Before this, those bytes went
// straight into the JSON decoder and every filtered read became a 502 on the
// gzip magic bytes.
//
// The caller bounds the decompressed stream — withResponseBody and
// streamArrayResponse both wrap this in the same MaxResponseBodyBytes
// LimitedReader they already applied to the raw body — which turns that cap
// into the gzip-bomb guard for this path. bodycodec bounds the compressed
// stream as well, because the caller's limit counts output bytes and would let
// an archive that expands to nothing pull an unbounded number of input bytes
// off the socket first.
//
// The decode itself lives in internal/bodycodec, which the visibility and
// ownership middlewares read their buffered bodies through, so the three
// layers cannot drift on the size cap or on which codings they accept.
func decodedResponseReader(resp *http.Response) (io.Reader, error) {
	return bodycodec.Reader(resp.Header, resp.Body, requestfilter.MaxResponseBodyBytes)
}
