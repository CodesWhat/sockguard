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
func readBoundedBody(r *http.Request, max int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	if r.ContentLength > max {
		if err := r.Body.Close(); err != nil {
			return nil, err
		}
		return nil, &bodyTooLargeError{limit: max}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, &bodyTooLargeError{limit: max}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return body, nil
}
