package filter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/codeswhat/sockguard/v3/app/internal/bytesize"
)

// MaxResponseBodyBytes is the default upper bound for Docker API response
// bodies that sockguard inspects and optionally redacts. Responses larger than
// the limit in force are rejected to avoid unbounded memory allocation. The
// limit in force is ResponseBodyLimit, which response.max_buffered_body sets.
const MaxResponseBodyBytes = 8 << 20 // 8 MiB

// MaxResponseBodyBytesCeiling is the largest response.max_buffered_body the
// config validator accepts. Every buffered response is held in memory, so the
// cap stays well under anything that could take the proxy down.
const MaxResponseBodyBytesCeiling = 256 << 20 // 256 MiB

// responseBodyLimit holds the configured limit; zero means the default.
var responseBodyLimit atomic.Int64

// ResponseBodyLimit returns the byte limit for buffered response bodies:
// response.max_buffered_body, or MaxResponseBodyBytes when it is unset.
func ResponseBodyLimit() int64 {
	if n := responseBodyLimit.Load(); n > 0 {
		return n
	}
	return MaxResponseBodyBytes
}

// SetResponseBodyLimit sets the buffered response body limit. A value that is
// not positive restores the default. The handler chain build calls it on
// startup and on every hot reload, so a reload applies a changed limit to the
// requests that follow it.
func SetResponseBodyLimit(n int64) {
	if n < 0 {
		n = 0
	}
	responseBodyLimit.Store(n)
}

// ResponseTooLargeMessage is the client-facing text for a response that was too
// big to buffer. It names the setting that governs the limit, because the
// alternative is a bare 502 and an operator guessing at what to raise.
func ResponseTooLargeMessage() string {
	return "upstream response too large to filter: it exceeds response.max_buffered_body (" +
		bytesize.Format(ResponseBodyLimit()) + "); raise that setting (maximum " +
		bytesize.Format(MaxResponseBodyBytesCeiling) + ") to filter responses this size"
}

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
