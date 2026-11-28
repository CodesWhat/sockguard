package httpjson

import (
	"fmt"
	"io"
	"net/http"
)

// ReadResponseBody reads a response within the byte limit, even when the
// transport does not know its length. The caller owns and closes resp.Body.
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("upstream response body exceeds %d byte limit", limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("upstream response body exceeds %d byte limit", limit)
	}
	return body, nil
}
