package filter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxResponseBodyBytes is the upper bound for Docker API response bodies that
// sockguard inspects and optionally redacts. Responses larger than this limit
// are rejected to avoid unbounded memory allocation.
const MaxResponseBodyBytes = 8 << 20 // 8 MiB

type bodyTooLargeError struct {
	limit int64
}

func (e *bodyTooLargeError) Error() string {
	return fmt.Sprintf("request body exceeds %d byte limit", e.limit)
}

func isBodyTooLargeError(err error) bool {
	var target *bodyTooLargeError
	return errors.As(err, &target)
}

// readBoundedBody reads up to max+1 bytes, rejecting oversized payloads before
// the request can be forwarded while still restoring safe-sized bodies for
// downstream use. Once the body has been successfully buffered, Close errors
// are ignored because forwarding can safely continue from the restored copy.
//
// An oversized body is restored too, with what was read put back in front of
// the rest of it, and one that declares itself oversized is not read at all.
// Warn and audit forward a request refused as too large, so it still has to
// carry every byte the client sent.
//
// Every inspector reads a JSON body it is about to decode for policy, so this
// is also where a body whose object keys the engines could read differently
// is refused, with a requestRejectionError that names the key. See
// rejectAmbiguousBodyKeys.
func readBoundedBody(r *http.Request, max int64) ([]byte, error) {
	body, err := readBoundedBodyUnchecked(r, max)
	if err != nil {
		return nil, err
	}
	// After the restore, for the same reason an oversized body is restored:
	// warn and audit forward a request this refuses.
	if err := rejectAmbiguousBodyKeys(body); err != nil {
		return nil, err
	}
	return body, nil
}

// readBoundedBodyUnchecked is readBoundedBody without the key check, for the
// resource-limit guard, which makes that check itself: it isn't a filter
// inspector, so it has to decide what a rollout mode does with the refusal.
func readBoundedBodyUnchecked(r *http.Request, max int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	if r.ContentLength > max {
		return nil, &bodyTooLargeError{limit: max}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		_ = r.Body.Close()
		return nil, err
	}
	if int64(len(body)) > max {
		r.Body = prefixedBody{Reader: io.MultiReader(bytes.NewReader(body), r.Body), Closer: r.Body}
		return nil, &bodyTooLargeError{limit: max}
	}
	_ = r.Body.Close()

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return body, nil
}

// prefixedBody is a request body some of which has already been read: Reader
// gives that part back and then the rest, and Closer closes the original.
type prefixedBody struct {
	io.Reader
	io.Closer
}

// replaceRequestBody installs final as the request body a mutation
// committed, keeping every transport-relevant field in lockstep so a stale
// Content-Length or Transfer-Encoding cannot survive a rewrite: it closes
// the previous body, installs final via io.NopCloser(bytes.NewReader(...)),
// sets r.ContentLength (the proxy layer never reads the literal
// Content-Length header — see readBoundedBody's doc comment and
// internal/proxy/proxy.go, which relies on req.ContentLength exclusively),
// clears r.TransferEncoding plus any stale Transfer-Encoding/Content-Length
// request headers, and installs GetBody so a retried/redirected request
// re-reads the same committed bytes rather than a drained reader.
//
// Callers must only invoke this after every rule that will be applied has
// been applied without error — there is no partial-body state this function
// can be called into.
func replaceRequestBody(r *http.Request, final []byte) {
	final = bytes.Clone(final)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(final))
	r.ContentLength = int64(len(final))
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Content-Length")
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(final)), nil
	}
}
