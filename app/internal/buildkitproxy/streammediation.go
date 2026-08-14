// Package buildkitproxy — this file carries Phase 5 (issue #185)'s shared
// streaming-mediation plumbing: the dispatch table that routes
// FileSync/DiffCopy, FileSend/DiffCopy, and Upload/Pull to their own
// mediation functions (filesync.go, filesend.go, upload.go), and the
// generic per-message-validating relay primitives all three build on —
// streamRelayReader for the request direction (a pull-based io.ReadCloser
// suitable as an outgoing http.Request.Body, so golang.org/x/net/http2's
// Transport does the actual concurrent body-pump) and relayValidatedFrames
// for a response direction with no hold-and-inspect needs (FileSync's own
// response relay, which DOES need to hold, gets its own loop in filesync.go).
//
// Unlike Phase 3's forwardControlMediated (a single buffered request
// message), every method mediated here is a bidirectional STREAM of many
// gRPC messages. bridge.go's existing forward()/forwardWithBody already
// relay a streaming body byte-for-byte with no decode (Phase 2's scope) —
// what this phase adds is a per-message decode/validate pass in the middle
// of that same relay, reusing readGRPCFrame (streamframing.go) in a loop
// instead of framing.go's single-message readUnaryGRPCMessage.
package buildkitproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// isStreamMediatedMethod reports whether service/method on endpoint is one
// of Phase 5's three per-message-streaming-mediated RPCs — the methods
// handleStream routes through forwardStreamMediated instead of the plain
// byte-verbatim forward(). All three are EndpointSession methods (buildkitd
// calling back into the client's session server); moby.buildkit.v1.Control's
// Solve/Status (EndpointGRPC) are Phase 3's own, separate,
// isControlMediatedMethod-gated path.
func isStreamMediatedMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointSession {
		return false
	}
	switch service {
	case "moby.filesync.v1.FileSync", "moby.filesync.v1.FileSend":
		return method == "DiffCopy"
	case "moby.upload.v1.Upload":
		return method == "Pull"
	}
	return false
}

// forwardStreamMediated dispatches an already-Classify'd-Mediate,
// already-Policy.Allowed'd stream to its service-specific mediation
// function. The default arm is unreachable today — isStreamMediatedMethod's
// table above lists exactly these three (service, method) pairs — but
// mirrors forwardControlMediated's own defensive switch default: if the two
// ever drift, fail CLOSED (an Internal gRPC status, audited
// buildkit_internal_error) rather than forward with zero policy evaluation.
func (b *bridge) forwardStreamMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	switch service {
	case "moby.filesync.v1.FileSync":
		b.forwardFileSyncMediated(w, r, service, method)
	case "moby.filesync.v1.FileSend":
		b.forwardFileSendMediated(w, r, service, method)
	case "moby.upload.v1.Upload":
		b.forwardUploadMediated(w, r, service, method)
	default:
		writeGRPCStatus(w, grpcCodeInternal, "internal routing error")
		b.audit(service, method, Deny, "buildkit_internal_error")
		b.recordDeniedAndMaybeClose()
	}
}

// streamRelayReader is a pull-style io.ReadCloser that decodes each gRPC
// length-prefixed frame read from src (via readGRPCFrame), runs its payload
// through validate, and — once admitted — serves the frame's ORIGINAL bytes
// verbatim to its own Read calls, exactly as required by the "on allow
// forward the original bytes, never a re-encoded message" constraint Phase 3
// established. Used as an http.Request's outgoing Body: golang.org/x/net/
// http2.Transport pumps it on its own goroutine while concurrently awaiting
// response headers, so no separate goroutine/pipe is needed here.
//
// The first denial or transport-level error is sticky: once Read returns a
// non-nil error, every subsequent call returns the same error, and — for a
// denial specifically — .denial is populated so the caller (which only sees
// whatever error RoundTrip itself surfaces) can recover the gRPC
// status/audit-reason to use. A clean io.EOF at a frame boundary (the
// stream's normal end) is reported as plain io.EOF with .denial left nil.
type streamRelayReader struct {
	src      io.ReadCloser
	maxLen   int64
	validate func(payload []byte) *mediationDenial

	buf []byte
	err error
	// denial is written by Read (on the request-body-pump goroutine
	// golang.org/x/net/http2.Transport runs) and read by forwardStreamRelay
	// via Denial() on the RoundTrip-calling goroutine. Those goroutines are
	// NOT ordered when RoundTrip returns for a reason unrelated to this reader
	// (a peer RST_STREAM/GOAWAY on the client leg, whose peer is the untrusted
	// client process) while Read is mid-frame — so this field must be atomic,
	// not a plain pointer. buf/err stay plain: they are only ever touched by
	// the single Read goroutine and never read externally.
	denial atomic.Pointer[mediationDenial]
}

func (r *streamRelayReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		frame, payload, ferr := readGRPCFrame(r.src, r.maxLen)
		if errors.Is(ferr, io.EOF) {
			r.err = io.EOF
			return 0, io.EOF
		}
		if ferr != nil {
			if errors.Is(ferr, errMessageTooLarge) {
				r.denial.Store(deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "a message exceeds sockguard's size cap"))
			} else {
				r.denial.Store(deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC stream framing"))
			}
			r.err = errStreamFrameProtocolError
			return 0, r.err
		}
		if d := r.validate(payload); d != nil {
			r.denial.Store(d)
			r.err = errStreamFrameProtocolError
			return 0, r.err
		}
		r.buf = frame
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Denial returns the sticky mediation denial Read recorded, or nil. Safe to
// call concurrently with Read — see the denial field's doc comment for why
// the plain-field read it replaces was a genuine data race.
func (r *streamRelayReader) Denial() *mediationDenial {
	return r.denial.Load()
}

func (r *streamRelayReader) Close() error {
	return r.src.Close()
}

// relayValidatedFrames is the "push" counterpart to streamRelayReader, for a
// response direction with no hold-and-inspect needs (FileSend/Upload; see
// filesync.go's relayFileSyncContent for the one response relay that DOES
// hold). It reads frames from src via readGRPCFrame, validates each payload,
// and writes admitted frames to w (flushed immediately, matching bridge.go's
// existing flushWriter convention for every other streaming response this
// package relays) until src reaches a clean end-of-stream.
//
// Returns (denial, nil) when validate rejects a frame — the caller has
// already written response headers by this point (see forwardStreamRelay),
// so a denial becomes a TRAILER status, mirroring forwardWithBody's own
// mid-stream size-cap handling. Returns (nil, err) for a genuine transport/
// write failure, which the caller treats as tunnel-ending exactly like
// forwardWithBody's own response-copy error path. Returns (nil, nil) on a
// clean end of stream.
func relayValidatedFrames(w http.ResponseWriter, src io.Reader, maxLen int64, validate func(payload []byte) *mediationDenial) (*mediationDenial, error) {
	fw := flushWriter{w}
	for {
		frame, payload, err := readGRPCFrame(src, maxLen)
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			if errors.Is(err, errMessageTooLarge) {
				return deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "a message exceeds sockguard's size cap"), nil
			}
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC stream framing"), nil
		}
		if d := validate(payload); d != nil {
			return d, nil
		}
		if _, werr := fw.Write(frame); werr != nil {
			return nil, werr
		}
	}
}

// bytesMessageCapValidator is the shared per-message validator for
// FileSend/Upload's BytesMessage frames (filesend.go, upload.go): decode,
// deny unknown fields exactly like every other mediated message
// (buildkit_schema_unsupported), and track a cumulative byte total against
// maxTotalBytes (buildkit_byte_limit_exceeded once exceeded) — "apply byte
// caps, no content inspection" per the #185 synthesis. newMsg constructs a
// fresh, empty instance of the CALLER'S OWN concrete BytesMessage type
// (filesync.BytesMessage or upload.BytesMessage) rather than sharing one
// type across both services by cross-decoding: the two are independently
// vendored, wire-identical TODAY, but keeping each service's decode against
// its own vendored descriptor means a future schema divergence between them
// is still caught by hasUnknownFields instead of silently masked. One
// instance is used per direction (request, response) of a single stream so
// each direction's total is tracked independently against the same ceiling.
type bytesMessageCapValidator struct {
	newMsg        func() proto.Message
	maxTotalBytes int64
	total         int64
}

func (v *bytesMessageCapValidator) validate(payload []byte) *mediationDenial {
	msg := v.newMsg()
	if err := proto.Unmarshal(payload, msg); err != nil {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC message")
	}
	if hasUnknownFields(msg) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	v.total += int64(len(payload))
	if v.maxTotalBytes > 0 && v.total > v.maxTotalBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_byte_limit_exceeded", "cumulative BuildKit stream bytes exceed sockguard's configured limit")
	}
	return nil
}

// rawByteCapValidator is bytesMessageCapValidator's undecoded sibling: it
// enforces the identical cumulative-byte ceiling without ever calling
// proto.Unmarshal on the message payload. filesend.go's FileSend/DiffCopy
// mediation uses this instead of bytesMessageCapValidator for a concrete,
// verified reason: moby/buildkit's own FileSend server implementation
// (session/filesync/filesync.go's SyncTarget.DiffCopy) dispatches to ONE OF
// TWO different wire shapes depending on which exporter negotiated the
// transfer — syncTargetDiffCopy (local/"outdir" export) drives
// fsutil.ReceiveRoot directly against the raw grpc.ServerStream, which calls
// stream.RecvMsg(&fsutiltypes.Packet{}) — bypassing the codegen'd
// FileSend_DiffCopyServer's typed BytesMessage accessor entirely, despite
// filesync.proto declaring FileSend.DiffCopy as stream BytesMessage on both
// sides (see filesync.pb.go's raw descriptor). grpc's low-level
// SendMsg/RecvMsg(m any) only cares about the dynamic type actually passed
// to it, not the stream's statically declared message type, which is
// exactly the escape hatch buildkit's own code relies on here. Decoding
// every FileSend payload as a BytesMessage would therefore either spuriously
// deny a real, successful `docker buildx build -o type=local` (syncTargetDiffCopy
// mode's frames are Packet-shaped, not BytesMessage-shaped, so an unknown-
// field check against BytesMessage would misfire) or silently misinterpret
// content sockguard should not be interpreting at all — matching the #185
// synthesis's own explicit instruction for FileSend, "byte caps, no content
// inspection," taken literally rather than layering an inspection the
// synthesis never asked for onto a message shape this package cannot safely
// assume.
type rawByteCapValidator struct {
	maxTotalBytes int64
	total         int64
}

func (v *rawByteCapValidator) validate(payload []byte) *mediationDenial {
	v.total += int64(len(payload))
	if v.maxTotalBytes > 0 && v.total > v.maxTotalBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_byte_limit_exceeded", "cumulative BuildKit stream bytes exceed sockguard's configured limit")
	}
	return nil
}

// forwardStreamRelay is the RoundTrip/header-copy plumbing shared by every
// Phase 5 streaming mediation path: build the outgoing request around
// reqValidate's streamRelayReader, RoundTrip it to the client leg, copy the
// response headers/status, then hand resp.Body to relayResponse for the
// method-specific content relay. Every branch mirrors bridge.go's own
// forwardWithBody (Phase 2) as closely as a per-message-validating relay
// allows: a request-side denial or size-cap trip ends the stream with a
// HEADER-based gRPC status (nothing has been written to w yet); a genuine
// transport failure tears the whole tunnel down (fail-closed, matching
// every other bridge.go transport-failure path); a response-side denial
// ends the stream with a TRAILER-based status (response headers are already
// committed by then); success is audited exactly once, here, after
// relayResponse confirms the whole stream relayed cleanly — unlike
// forwardControlMediated's single buffered message, a stream's outcome
// genuinely isn't known until it ends.
func (b *bridge) forwardStreamRelay(
	w http.ResponseWriter, r *http.Request, service, method string,
	reqValidate func(payload []byte) *mediationDenial,
	relayResponse func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error),
) {
	host := r.Host
	if host == "" {
		host = "buildkitd"
	}

	reqRelay := &streamRelayReader{src: r.Body, maxLen: b.limits.MaxMessageBytes, validate: reqValidate}

	outReq := &http.Request{
		Method:        r.Method,
		URL:           &url.URL{Scheme: "http", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery},
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        r.Header.Clone(),
		Host:          host,
		Body:          reqRelay,
		ContentLength: -1,
	}

	// Carry the inbound stream's context onto the outgoing leg so a client
	// disconnect cancels the daemon-side RoundTrip too (a struct-literal
	// http.Request otherwise defaults to context.Background()), matching
	// forwardWithBody and httputil.ReverseProxy's own context propagation.
	resp, err := b.clientLeg.RoundTrip(outReq.WithContext(r.Context()))
	if err != nil {
		if d := reqRelay.Denial(); d != nil {
			writeGRPCStatus(w, d.code, d.message)
			b.audit(service, method, Deny, d.reasonCode)
			b.recordDeniedAndMaybeClose()
			return
		}
		// Unlike forwardWithBody's limitedReadCloser (Phase 2), which
		// returns errMessageTooLarge verbatim from its Read, streamRelayReader
		// always converts a size-cap trip into r.denial (with a specific
		// buildkit_message_too_large reason) plus the generic sentinel
		// errStreamFrameProtocolError -- so reqRelay.denial above already
		// covers every size/framing error this reader can produce, and there
		// is no separate errMessageTooLarge case to check here.
		b.logger.Warn("buildkit: forwarding stream failed; terminating tunnel",
			"error", logging.SafeString(err.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: forward %s/%s: %w", service, method, err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	denial, ioErr := relayResponse(w, resp.Body)
	switch {
	case denial != nil:
		writeGRPCTrailerStatus(w, denial.code, denial.message)
		b.audit(service, method, Deny, denial.reasonCode)
		// Count response-side denials against the abuse budget too. On
		// EndpointSession the roles are reversed (see filesync.go's package
		// doc): the FileSync/FileSend/Upload service runs on the untrusted
		// client side, so a response-direction denial — an oversized export, a
		// Dockerfile that trips RUN inspection, a byte-cap trip — is just as
		// client-driven as a request-side one. Omitting this would let a client
		// drive unbounded denials on an open tunnel without ever consuming
		// DeniedStreamBudget, exactly what that budget exists to bound.
		b.recordDeniedAndMaybeClose()
	case ioErr != nil:
		b.logger.Warn("buildkit: relaying stream response failed; terminating tunnel",
			"error", logging.SafeString(ioErr.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: relay %s/%s response: %w", service, method, ioErr))
	default:
		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(http.TrailerPrefix+k, v)
			}
		}
		b.audit(service, method, Mediate, "")
	}
}
