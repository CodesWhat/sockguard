package responsefilter

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	requestfilter "github.com/codeswhat/sockguard/app/internal/filter"
)

// identityContentCoding is RFC 9110 §8.4.1's "no transformation" coding. It is
// the only response encoding this package can hand to a JSON decoder as it
// stands, and the only one it asks an upstream for.
const identityContentCoding = "identity"

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
// into the gzip-bomb guard for this path. The compressed stream is bounded
// here as well, because the caller's limit counts output bytes and would let
// an archive that expands to nothing pull an unbounded number of input bytes
// off the socket first.
//
// Anything other than gzip or identity is refused rather than guessed at.
// Handing br or zstd bytes to the decoder produces the same 502 with a worse
// error, and forwarding them unread would mean redacting nothing on a route
// policy says must be redacted.
func decodedResponseReader(resp *http.Response) (io.Reader, error) {
	values := resp.Header.Values("Content-Encoding")
	if len(values) == 0 {
		return resp.Body, nil
	}

	// Join before matching so a body wrapped twice ("gzip, gzip", or two
	// Content-Encoding header lines) fails the single-token comparison
	// instead of being half-decoded by a Get that returns only the first.
	coding := strings.ToLower(strings.TrimSpace(strings.Join(values, ", ")))
	switch coding {
	case "", identityContentCoding:
		return resp.Body, nil
	case "gzip", "x-gzip":
		compressed := &io.LimitedReader{R: resp.Body, N: requestfilter.MaxResponseBodyBytes + 1}
		gzr, err := gzip.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("decode gzip response body: %w", err)
		}
		return gzr, nil
	default:
		return nil, fmt.Errorf("unsupported response Content-Encoding %q", coding)
	}
}
