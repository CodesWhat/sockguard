package httpjson

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadResponseBodyLimit(t *testing.T) {
	t.Parallel()

	const limit = 64
	for _, tt := range []struct {
		name          string
		size          int
		contentLength int64
		wantRead      int
		wantError     bool
	}{
		{name: "exact limit", size: limit, contentLength: -1, wantRead: limit},
		{name: "one byte over the limit", size: limit + 1, contentLength: -1, wantRead: limit + 1, wantError: true},
		{name: "unknown oversized length", size: limit + 2, contentLength: -1, wantRead: limit + 1, wantError: true},
		{name: "declared oversized length", size: limit + 2, contentLength: limit + 2, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := strings.NewReader(strings.Repeat(" ", tt.size))
			resp := &http.Response{Body: io.NopCloser(reader), ContentLength: tt.contentLength}
			got, err := ReadResponseBody(resp, limit)
			if tt.wantError {
				if err == nil || got != nil {
					t.Fatalf("read = %d bytes, %v; want error with no data", len(got), err)
				}
			} else if err != nil || len(got) != tt.size {
				t.Fatalf("read = %d bytes, %v; want %d bytes", len(got), err, tt.size)
			}
			if n := tt.size - reader.Len(); n != tt.wantRead {
				t.Fatalf("consumed %d bytes, want %d", n, tt.wantRead)
			}
		})
	}
}

func TestReadResponseBodyReadFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("read interrupted")
	resp := &http.Response{Body: io.NopCloser(iotest.ErrReader(want)), ContentLength: -1}
	if got, err := ReadResponseBody(resp, 64); got != nil || !errors.Is(err, want) {
		t.Fatalf("read = %v, %v; want no body and %v", got, err, want)
	}
}
