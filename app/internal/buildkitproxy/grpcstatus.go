package buildkitproxy

import (
	"net/http"
	"strconv"
	"strings"
)

// gRPC status codes this package needs to synthesize. Subset of
// google.golang.org/grpc/codes, reproduced here as untyped constants rather
// than importing grpc-go — the #185 sign-off's dependency exception is
// golang.org/x/net/http2 and google.golang.org/protobuf, explicitly NOT
// grpc-go (see registry.go's package doc), and grpc-go's codes package pulls
// in the rest of the grpc-go module graph as a transitive consequence of
// living in the same module.
//
// Phase 2 declared only the codes it raised; Phase 3's per-message Solve/
// Status decode adds the codes it needs: InvalidArgument for a message that
// fails to unmarshal or whose gRPC framing is malformed
// (buildkit_protocol_error), FailedPrecondition for a message that
// decodes cleanly but carries protobuf unknown-field bytes or an
// unrecognized FrontendAttrs key (buildkit_schema_unsupported) — the #185
// synthesis's strict-unknown-field divergence — and Internal for
// forwardControlMediated's defensive switch default (buildkit_internal_error):
// isControlMediatedMethod and the switch on method must stay in lock-step
// (both list exactly Solve and Status), but the switch's default arm exists
// so a future method added to one and not the other fails CLOSED — no
// policy decision made at all — rather than forwarding with zero mediation.
const (
	grpcCodeInvalidArgument    = 3
	grpcCodePermissionDenied   = 7
	grpcCodeResourceExhausted  = 8
	grpcCodeFailedPrecondition = 9
	grpcCodeUnimplemented      = 12
	grpcCodeInternal           = 13
)

// writeGRPCStatus writes a gRPC "Trailers-Only" error response: HTTP status
// 200 with grpc-status/grpc-message carried as HEADERS (not trailers) and no
// body, per the gRPC-over-HTTP/2 spec's "Trailers-Only for Non-Streaming
// error case" — valid whenever the response headers haven't been sent yet,
// which is true everywhere this package calls it (routing decisions made
// before any byte of the daemon's/client's real response is forwarded).
func writeGRPCStatus(w http.ResponseWriter, code int, message string) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", strconv.Itoa(code))
	if message != "" {
		h.Set("Grpc-Message", percentEncodeGRPCMessage(message))
	}
	w.WriteHeader(http.StatusOK)
}

// writeGRPCTrailerStatus sets grpc-status/grpc-message as TRAILERS on w,
// using the http.TrailerPrefix convention (valid for both HTTP/1.1 chunked
// and HTTP/2 responses via net/http's server abstractions, which is what
// golang.org/x/net/http2.Server's per-request ResponseWriter implements) —
// used when a stream's response headers (and possibly some body bytes) have
// ALREADY been relayed and sockguard needs to end the stream with an error
// status instead of the daemon's real trailers, e.g. after a mid-stream
// size-cap trip. Must be called before the handler returns (trailers ship
// when the handler completes).
func writeGRPCTrailerStatus(w http.ResponseWriter, code int, message string) {
	h := w.Header()
	h.Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(code))
	if message != "" {
		h.Set(http.TrailerPrefix+"Grpc-Message", percentEncodeGRPCMessage(message))
	}
}

// percentEncodeGRPCMessage encodes s per the gRPC spec's Percent-Encoding
// rule for grpc-message: printable ASCII (0x20-0x7E) except '%' pass
// through unescaped; everything else becomes %XX (uppercase hex). sockguard
// only ever feeds this function messages it authored itself (fixed strings
// plus method/service names already validated as printable by
// ParseGRPCPath), never raw client input, but the encoder is defensive
// regardless — see CLAUDE.md's "never log secret contents" constraint,
// which this indirectly reinforces by making it structurally impossible for
// a Grpc-Message value to break header framing.
func percentEncodeGRPCMessage(s string) string {
	needsEscape := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7E || c == '%' {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xF])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
