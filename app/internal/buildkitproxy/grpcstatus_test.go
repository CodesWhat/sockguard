package buildkitproxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestWriteGRPCStatus tables writeGRPCStatus's message and no-message
// variants: both must still produce a gRPC "Trailers-Only" HTTP 200 with the
// right Content-Type/Grpc-Status, and an empty message must omit Grpc-Message
// entirely rather than writing an empty header value.
func TestWriteGRPCStatus(t *testing.T) {
	cases := []struct {
		name        string
		code        int
		message     string
		wantMessage string
	}{
		{"with message", grpcCodePermissionDenied, "Solve/Solve is denied", "Solve/Solve is denied"},
		{"empty message omits Grpc-Message", grpcCodeUnimplemented, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeGRPCStatus(rec, tc.code, tc.message)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d (gRPC Trailers-Only errors use HTTP 200)", rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/grpc" {
				t.Errorf("Content-Type = %q, want application/grpc", got)
			}
			if got := rec.Header().Get("Grpc-Status"); got != strconv.Itoa(tc.code) {
				t.Errorf("Grpc-Status = %q, want %d", got, tc.code)
			}
			if got := rec.Header().Get("Grpc-Message"); got != tc.wantMessage {
				t.Errorf("Grpc-Message = %q, want %q", got, tc.wantMessage)
			}
		})
	}
}

// TestWriteGRPCTrailerStatus mirrors TestWriteGRPCStatus's message/
// no-message table, but for the trailer-carried variant used mid-stream.
func TestWriteGRPCTrailerStatus(t *testing.T) {
	cases := []struct {
		name        string
		code        int
		message     string
		wantMessage string
	}{
		{"with message", grpcCodeResourceExhausted, "too big", "too big"},
		{"empty message omits trailer message", grpcCodeResourceExhausted, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeGRPCTrailerStatus(rec, tc.code, tc.message)

			if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != strconv.Itoa(tc.code) {
				t.Errorf("Trailer:Grpc-Status = %q, want %d", got, tc.code)
			}
			if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Message"); got != tc.wantMessage {
				t.Errorf("Trailer:Grpc-Message = %q, want %q", got, tc.wantMessage)
			}
		})
	}
}

func TestPercentEncodeGRPCMessage(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii passes through", "Solve/Solve is denied", "Solve/Solve is denied"},
		{"empty string", "", ""},
		{"percent sign escaped", "100% denied", "100%25 denied"},
		{"control character escaped", "line1\nline2", "line1%0Aline2"},
		{"non-ascii byte escaped", "caf\xe9", "caf%E9"},
		{"del char escaped", "\x7f", "%7F"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := percentEncodeGRPCMessage(tc.in); got != tc.want {
				t.Errorf("percentEncodeGRPCMessage(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
