package filter

import (
	"bytes"
	"io"
	"net/http"
)

// readBoundedBody reads up to max+1 bytes so callers can detect oversize
// payloads while still restoring the original request body for downstream use.
func readBoundedBody(r *http.Request, max int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return body, nil
}
