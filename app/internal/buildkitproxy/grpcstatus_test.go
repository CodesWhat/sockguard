package buildkitproxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestWriteGRPCStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGRPCStatus(rec, grpcCodePermissionDenied, "Solve/Solve is denied")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (gRPC Trailers-Only errors use HTTP 200)", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/grpc" {
		t.Errorf("Content-Type = %q, want application/grpc", got)
	}
	if got := rec.Header().Get("Grpc-Status"); got != strconv.Itoa(grpcCodePermissionDenied) {
		t.Errorf("Grpc-Status = %q, want %d", got, grpcCodePermissionDenied)
	}
	if got := rec.Header().Get("Grpc-Message"); got != "Solve/Solve is denied" {
		t.Errorf("Grpc-Message = %q, want %q", got, "Solve/Solve is denied")
	}
}

func TestWriteGRPCStatusNoMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGRPCStatus(rec, grpcCodeUnimplemented, "")
	if rec.Header().Get("Grpc-Message") != "" {
		t.Errorf("Grpc-Message = %q, want empty when message is empty", rec.Header().Get("Grpc-Message"))
	}
}

func TestWriteGRPCTrailerStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGRPCTrailerStatus(rec, grpcCodeResourceExhausted, "too big")

	if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Status"); got != strconv.Itoa(grpcCodeResourceExhausted) {
		t.Errorf("Trailer:Grpc-Status = %q, want %d", got, grpcCodeResourceExhausted)
	}
	if got := rec.Header().Get(http.TrailerPrefix + "Grpc-Message"); got != "too big" {
		t.Errorf("Trailer:Grpc-Message = %q, want %q", got, "too big")
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
