// Package bodycodec turns an upstream response body back into the
// identity-encoded bytes a JSON decoder can read.
//
// Three layers read a Docker API response body before it reaches the client:
// internal/responsefilter redacts it, internal/visibility filters list bodies
// by the visibility policy, and internal/ownership filters GET /system/df by
// owner label. Each of them used to assume the bytes were uncompressed. The
// proxy asks for that (see responsefilter.PinIdentityAcceptEncoding) and
// neither dockerd nor Podman compresses the JSON API, but an intermediary
// between sockguard and the daemon — a TLS-terminating proxy in front of a
// remote engine, most obviously — is free to ignore the pin and gzip anyway,
// and then every filtered read fails on the gzip magic bytes.
//
// This package is the one decode, so the three layers cannot drift on the size
// cap or on which codings they accept. It is a leaf: stdlib only, no import of
// internal/filter or of any layer that uses it, so nothing here can cycle back
// into a caller. The byte limit is a parameter rather than a constant for the
// same reason — the callers own it, and all three pass
// filter.MaxResponseBodyBytes.
package bodycodec

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Identity is RFC 9110 §8.4.1's "no transformation" coding: the only response
// encoding these callers can hand to a JSON decoder as it stands, and the only
// one the proxy asks an upstream for.
const Identity = "identity"

// ErrTooLarge identifies a body refused because its decoded form ran past the
// caller's limit. It is a sentinel because the callers already have a
// response-too-large verdict with its own reason code, and a gzip archive that
// expands past the cap is that verdict rather than a filter that failed.
var ErrTooLarge = errors.New("decoded response body exceeds byte limit")

// Reader returns a reader over body's identity-encoded bytes, decompressing
// when the upstream compressed anyway.
//
// The limit bounds the compressed stream, because the caller's own cap counts
// output bytes and would otherwise let an archive that expands to nothing pull
// an unbounded number of input bytes off the socket first. Bounding the
// decoded stream stays the caller's job on this path: it already wraps the
// result in a LimitedReader of its own.
//
// An identity-encoded body is returned as it arrived, so the common case
// allocates nothing.
func Reader(header http.Header, body io.Reader, limit int64) (io.Reader, error) {
	coding := codingOf(header)
	if isIdentity(coding) {
		return body, nil
	}
	return decode(coding, body, limit)
}

// Bytes returns body's identity-encoded bytes for a caller that has already
// buffered the response.
//
// It is Reader's counterpart for the two middlewares that intercept the
// response through an http.ResponseWriter rather than a ModifyResponse hook:
// they hold the upstream body as a bounded []byte by the time they can act on
// it, so there is no stream left to wrap. Unlike Reader it bounds the decoded
// size itself — nothing downstream of it will — and refuses anything past the
// limit with ErrTooLarge.
//
// An identity-encoded body is returned as the same slice, uncopied, so the
// path a real daemon takes costs one header lookup. The coding is checked
// before the bytes.Reader is built rather than inside decode, because building
// one unconditionally put a heap allocation on every filtered list response
// for a wrapper nothing on that path reads.
func Bytes(header http.Header, body []byte, limit int64) ([]byte, error) {
	coding := codingOf(header)
	if isIdentity(coding) {
		return body, nil
	}

	decoded, err := decode(coding, bytes.NewReader(body), limit)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	// limit+1 so a body of exactly the limit is kept and the first byte past
	// it is what trips the refusal.
	if _, err := buf.ReadFrom(&io.LimitedReader{R: decoded, N: limit + 1}); err != nil {
		return nil, fmt.Errorf("decode %s response body: %w", coding, err)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("%w (%d byte limit)", ErrTooLarge, limit)
	}
	return buf.Bytes(), nil
}

// codingOf returns the single content coding header names, lowercased.
//
// The values are joined before matching so a body wrapped twice ("gzip, gzip",
// or two Content-Encoding header lines) fails the single-token comparison
// below instead of being half-decoded by a Get that returns only the first.
func codingOf(header http.Header) string {
	values := header.Values("Content-Encoding")
	if len(values) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strings.Join(values, ", ")))
}

// isIdentity reports whether coding leaves the body as the sender's own bytes,
// which is the set the callers can hand straight to a JSON decoder. It is the
// one definition of that set: Reader and Bytes each consult it before doing
// any work, so neither can end up decoding a body the other passes through.
func isIdentity(coding string) bool {
	return coding == "" || coding == Identity
}

// decode wraps body in the reader for coding. Both entry points filter out the
// identity codings first, so every coding that reaches here needs work.
//
// Anything other than gzip is refused rather than guessed at. Handing br or
// zstd bytes to a JSON decoder produces the same failure with a worse error,
// and forwarding them unread would mean applying no policy on a route that
// exists to apply one.
func decode(coding string, body io.Reader, limit int64) (io.Reader, error) {
	switch coding {
	case "gzip", "x-gzip":
		compressed := &io.LimitedReader{R: body, N: limit + 1}
		gzr, err := gzip.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("decode %s response body: %w", coding, err)
		}
		return gzr, nil
	default:
		return nil, fmt.Errorf("unsupported response Content-Encoding %q", coding)
	}
}
