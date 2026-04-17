package filter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
// downstream use.
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
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
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
