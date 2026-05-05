package logging

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func zeroTraceRandRead(dst []byte) (int, error) {
	clear(dst)
	return len(dst), nil
}

func TestTraceContextFromRequestRejectsNilAndMissingTraceparent(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
	}{
		{name: "nil request"},
		{name: "missing traceparent", req: httptest.NewRequest(http.MethodGet, "/info", nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ok := traceContextFromRequest(tt.req)
			if ok {
				t.Fatalf("traceContextFromRequest() ok = true, want false")
			}
			if ctx != (traceContext{}) {
				t.Fatalf("traceContextFromRequest() ctx = %#v, want zero value", ctx)
			}
		})
	}
}

func TestTraceContextFromRequestKeepsIncomingTraceFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set(traceparentHeader, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	ctx, ok := traceContextFromRequest(req)
	if !ok {
		t.Fatal("traceContextFromRequest() ok = false, want true")
	}
	if ctx.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("traceID = %q, want incoming trace ID", ctx.traceID)
	}
	if ctx.parentID != "00f067aa0ba902b7" {
		t.Fatalf("parentID = %q, want incoming parent ID", ctx.parentID)
	}
	if ctx.flags != "01" {
		t.Fatalf("flags = %q, want incoming flags", ctx.flags)
	}
	requireTraceIdentifier(t, "spanID", ctx.spanID, 16)
	if ctx.spanID == ctx.parentID {
		t.Fatalf("spanID = %q, want proxy-local span distinct from incoming parent", ctx.spanID)
	}
}

func TestTraceSampledParsesFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags string
		want  bool
	}{
		{name: "sampled", flags: "01", want: true},
		{name: "not sampled", flags: "00", want: false},
		{name: "sampled with other bits", flags: "0f", want: true},
		{name: "high nibble only", flags: "10", want: false},
		{name: "wrong length", flags: "0", want: false},
		{name: "invalid high nibble", flags: "g1", want: false},
		{name: "invalid low nibble", flags: "0g", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := traceSampled(tt.flags); got != tt.want {
				t.Fatalf("traceSampled(%q) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

func TestNewTraceIdentifiersUseLowerHexNonZeroValues(t *testing.T) {
	requireTraceIdentifier(t, "traceID", newTraceID(), 32)
	requireTraceIdentifier(t, "spanID", newTraceSpanID(), 16)
}

func TestNewTraceIdentifiersFallBackWhenRandReturnsAllZero(t *testing.T) {
	originalRead := traceRandRead
	traceRandRead = zeroTraceRandRead
	t.Cleanup(func() {
		traceRandRead = originalRead
	})

	requireTraceIdentifier(t, "traceID", newTraceID(), 32)
	requireTraceIdentifier(t, "spanID", newTraceSpanID(), 16)
}

func TestAllZero(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{name: "nil", want: true},
		{name: "empty", in: []byte{}, want: true},
		{name: "all zero", in: []byte{0x00, 0x00}, want: true},
		{name: "contains non-zero", in: []byte{0x00, 0x01}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allZero(tt.in); got != tt.want {
				t.Fatalf("allZero(%x) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsLowerHex(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty", value: "", want: true},
		{name: "digits and lowercase letters", value: "0123456789abcdef", want: true},
		{name: "uppercase letter", value: "abcDef", want: false},
		{name: "after lowercase range", value: "abcg", want: false},
		{name: "before digit range", value: "/0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLowerHex(tt.value); got != tt.want {
				t.Fatalf("isLowerHex(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestLowerHexValue(t *testing.T) {
	tests := []struct {
		name   string
		in     byte
		want   byte
		wantOK bool
	}{
		{name: "zero digit", in: '0', want: 0, wantOK: true},
		{name: "nine digit", in: '9', want: 9, wantOK: true},
		{name: "a", in: 'a', want: 10, wantOK: true},
		{name: "f", in: 'f', want: 15, wantOK: true},
		{name: "uppercase", in: 'A', wantOK: false},
		{name: "after lowercase range", in: 'g', wantOK: false},
		{name: "before digit range", in: '/', wantOK: false},
		{name: "after digit range", in: ':', wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lowerHexValue(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("lowerHexValue(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("lowerHexValue(%q) value = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func requireTraceIdentifier(t *testing.T, name, value string, wantLen int) {
	t.Helper()

	if len(value) != wantLen {
		t.Fatalf("%s len = %d, want %d", name, len(value), wantLen)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s = %q, want hex: %v", name, value, err)
	}
	if hex.EncodeToString(decoded) != value {
		t.Fatalf("%s = %q, want lowercase canonical hex", name, value)
	}
	if allZero(decoded) {
		t.Fatalf("%s = %q, want non-zero value", name, value)
	}
}
