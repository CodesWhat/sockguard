package dockerfilters

import (
	"strings"
	"testing"
)

func TestDecodeRejectsOversizedInput(t *testing.T) {
	t.Parallel()
	oversized := `{"label":["` + strings.Repeat("a", MaxEncodedBytes) + `"]}`
	if _, err := Decode(oversized); err == nil {
		t.Fatalf("Decode(%d bytes) = nil error, want size-limit error", len(oversized))
	}
}

func TestDecodeAcceptsInputAtSizeLimit(t *testing.T) {
	t.Parallel()
	const overhead = len(`{"label":[""]}`)
	atLimit := `{"label":["` + strings.Repeat("a", MaxEncodedBytes-overhead) + `"]}`
	if len(atLimit) != MaxEncodedBytes {
		t.Fatalf("test input is %d bytes, want exactly %d", len(atLimit), MaxEncodedBytes)
	}
	filters, err := Decode(atLimit)
	if err != nil {
		t.Fatalf("Decode(at-limit input) error = %v, want nil", err)
	}
	if len(filters["label"]) != 1 {
		t.Fatalf("label values = %d, want 1", len(filters["label"]))
	}
}
