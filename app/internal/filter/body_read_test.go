package filter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadBoundedBodyRestoresRequestBody(t *testing.T) {
	payload := []byte(`{"Name":"cache"}`)
	req := httptest.NewRequest(http.MethodPost, "/volumes/create", bytes.NewReader(payload))

	body, err := readBoundedBody(req, int64(len(payload)))
	if err != nil {
		t.Fatalf("readBoundedBody() error = %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("readBoundedBody() body = %q, want %q", string(body), string(payload))
	}
	if req.ContentLength != int64(len(payload)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(payload))
	}

	resetBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(resetBody, payload) {
		t.Fatalf("reset body = %q, want %q", string(resetBody), string(payload))
	}
}

func TestReadBoundedBodyRejectsOversizedPayload(t *testing.T) {
	const maxBodyBytes = 4

	payload := []byte("12345")
	req := httptest.NewRequest(http.MethodPost, "/secrets/create", bytes.NewReader(payload))

	body, err := readBoundedBody(req, maxBodyBytes)
	if body != nil {
		t.Fatalf("readBoundedBody() body = %q, want nil", string(body))
	}
	if !isBodyTooLargeError(err) {
		t.Fatalf("readBoundedBody() error = %v, want body-too-large error", err)
	}
}
