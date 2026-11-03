package filter

import (
	"strings"
	"testing"
)

// Serial on purpose: the limit is process-wide.
func TestResponseBodyLimit(t *testing.T) {
	t.Cleanup(func() { SetResponseBodyLimit(0) })

	SetResponseBodyLimit(0)
	if got := ResponseBodyLimit(); got != MaxResponseBodyBytes {
		t.Fatalf("default limit = %d, want %d", got, MaxResponseBodyBytes)
	}
	SetResponseBodyLimit(32 << 20)
	if got := ResponseBodyLimit(); got != 32<<20 {
		t.Fatalf("limit = %d, want 32MiB", got)
	}
	SetResponseBodyLimit(-5)
	if got := ResponseBodyLimit(); got != MaxResponseBodyBytes {
		t.Fatalf("negative limit should restore the default, got %d", got)
	}
}

func TestResponseTooLargeMessageNamesSetting(t *testing.T) {
	t.Cleanup(func() { SetResponseBodyLimit(0) })
	SetResponseBodyLimit(32 << 20)
	got := ResponseTooLargeMessage()
	for _, want := range []string{"upstream response too large to filter", "response.max_buffered_body", "32MiB", "256MiB"} {
		if !strings.Contains(got, want) {
			t.Fatalf("message %q missing %q", got, want)
		}
	}
}
