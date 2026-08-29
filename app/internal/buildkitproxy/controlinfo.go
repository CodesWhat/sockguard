// Package buildkitproxy — this file carries the RESPONSE-side mediation for
// moby.buildkit.v1.Control's two host-describing read RPCs, Info and
// ListWorkers. Both were classified Passthrough through Phase 5: the request
// was gated by Policy.Allowed (policy.go) but the daemon's reply was relayed
// byte-for-byte, and that reply describes the HOST, not the caller — worker
// labels (which carry the daemon host's own hostname, executor, snapshotter
// and network mode), the daemon's garbage-collection thresholds, and its CDI
// device inventory. registry.go now classifies both Mediate and routes them
// here.
//
// What "permitted" means for these two responses. Policy has no per-worker,
// per-platform, per-label or per-device field — nothing in it can admit any
// of the metadata above — so the filter is a FIXED field-number allowlist,
// the same "no enabling knob, fixed table" convention solve.go's
// allowedSolveFrontends and knownFrontendAttrKeys already use, rather than a
// new config surface. A field survives only when a method this Policy can
// admit lets the caller act on it:
//
//   - WorkerRecord.ID and WorkerRecord.platforms are kept: Control/Solve is
//     the only build-driving RPC Policy can admit, and a client must know a
//     worker's identity and platform set to target a build at it at all.
//   - BuildkitVersion is kept, on both messages, matching the classic Docker
//     API path: internal/responsefilter's redactInfoPayload never redacts
//     GET /info's ServerVersion, so the BuildKit equivalent is not treated as
//     a leak here either. It is also what buildx reads to negotiate features.
//   - WorkerRecord.Labels is dropped. It is pure host topology — buildkitd
//     publishes org.mobyproject.buildkit.worker.{hostname,executor,
//     snapshotter,network,selinux.enabled} — the same category
//     redactInfoPayload strips from GET /info under RedactHostTopology.
//   - WorkerRecord.GCPolicy is dropped. It is the readout of the daemon's
//     disk-management configuration, which is exactly the surface
//     Control/Prune and Control/DiskUsage are hard-denied for (registry.go's
//     DeniedExamples, no enabling knob).
//   - WorkerRecord.CDIDevices is dropped. It is the host's device inventory
//     (the analog of GET /info's DiscoveredDevices, also redacted under
//     RedactHostTopology), and no FrontendAttrs key sockguard recognizes
//     (knownFrontendAttrKeys) can request a device anyway, so a caller could
//     never use one through this proxy.
//
// Only the RESPONSE direction is mediated. InfoRequest is an empty message
// and ListWorkersRequest carries one field, a client-chosen worker filter
// that only narrows what the daemon returns — which this filter then narrows
// again regardless — so neither request carries a policy-relevant field, and
// both are forwarded byte-for-byte exactly as they were under Passthrough.
//
// The filter works on protobuf WIRE bytes (google.golang.org/protobuf's
// protowire) rather than decoded messages, because InfoResponse,
// ListWorkersResponse and WorkerRecord are among the message types
// buildkitproto's control.proto trim deliberately left unvendored (see
// PROVENANCE.md) — precisely because these two RPCs used to be Passthrough.
// A wire-level allowlist needs no new module (protowire ships inside the
// google.golang.org/protobuf dependency buildkitproto already pulls in) and
// no descriptor regeneration, and it fails closed by construction: a field
// number absent from the tables below is denied, never relayed.
package buildkitproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// responseFieldRule is one row of a response field-number allowlist. Its zero
// value means "keep this field's bytes verbatim"; drop means "never relay
// this field"; a non-nil nested table means "recurse into this field's
// submessage and rewrite it against that table". Exactly one of drop/nested
// is ever set.
type responseFieldRule struct {
	drop   bool
	nested map[protowire.Number]responseFieldRule
}

// The four tables below mirror moby/buildkit v0.32.0's
// api/services/control/control.proto and api/types/worker.proto — the same
// upstream tag PROVENANCE.md pins every vendored .proto to. Field NUMBERS,
// not names, are the contract: protobuf never renumbers an existing field, so
// a number missing from a table means upstream added something this filter
// has not reviewed, which is denied (buildkit_schema_unsupported) rather than
// silently dropped or silently relayed — the same strict-schema posture
// evaluateSolveRequest takes on the request side.
//
// The tables form an acyclic graph three levels deep at most
// (ListWorkersResponse -> WorkerRecord -> Platform/BuildkitVersion), so
// filterControlResponseMessage's recursion is statically bounded and needs no
// depth cap of its own, unlike solve.go's solveDefinitionExecMaxDepth (whose
// input nesting is client-controlled).

// controlPlatformFields is solver/pb's Platform, reached through
// WorkerRecord.platforms. Every field is kept: a platform triple is what a
// caller matches its own build target against, and OSVersion/OSFeatures are
// part of that identity rather than separate host facts.
var controlPlatformFields = map[protowire.Number]responseFieldRule{
	1: {}, // Architecture
	2: {}, // OS
	3: {}, // Variant
	4: {}, // OSVersion
	5: {}, // OSFeatures
}

// controlBuildkitVersionFields is api/types' BuildkitVersion, reached both
// directly (InfoResponse) and through WorkerRecord. Every field is kept — see
// this file's doc comment on the GET /info ServerVersion parity.
var controlBuildkitVersionFields = map[protowire.Number]responseFieldRule{
	1: {}, // package
	2: {}, // version
	3: {}, // revision
	4: {}, // dockerfileVersion
}

// controlWorkerRecordFields is api/types' WorkerRecord — the only message in
// either response where anything is actually withheld. See this file's doc
// comment for why each dropped field is dropped.
var controlWorkerRecordFields = map[protowire.Number]responseFieldRule{
	1: {},                                     // ID
	2: {drop: true},                           // Labels
	3: {nested: controlPlatformFields},        // platforms
	4: {drop: true},                           // GCPolicy
	5: {nested: controlBuildkitVersionFields}, // BuildkitVersion
	6: {drop: true},                           // CDIDevices
}

// controlInfoResponseFields is control.proto's InfoResponse.
var controlInfoResponseFields = map[protowire.Number]responseFieldRule{
	1: {nested: controlBuildkitVersionFields}, // buildkitVersion
}

// controlListWorkersResponseFields is control.proto's ListWorkersResponse.
var controlListWorkersResponseFields = map[protowire.Number]responseFieldRule{
	1: {nested: controlWorkerRecordFields}, // record (repeated)
}

// isControlResponseFilteredMethod reports whether service/method on endpoint
// is one of the two Control RPCs whose RESPONSE is rewritten before the
// client sees it — the methods forwardAdmitted routes through
// forwardControlInfoMediated instead of Phase 3's forwardControlMediated
// (which mediates a REQUEST message) or the plain byte-verbatim forward.
// Both are already Classify()'d Mediate and already passed Policy.Allowed by
// the time this is consulted; it only decides which forwarding strategy an
// already-admitted call uses.
func isControlResponseFilteredMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointGRPC || service != "moby.buildkit.v1.Control" {
		return false
	}
	return method == "Info" || method == "ListWorkers"
}

// forwardControlInfoMediated relays Control/Info and Control/ListWorkers with
// the client's request bytes untouched and the daemon's response message
// rewritten against this file's field allowlists.
//
// The whole response is buffered and filtered BEFORE any header is written,
// so a response sockguard cannot parse or filter ends the stream with a
// header-based gRPC status and no body at all — never a partially-relayed
// unfiltered message. That is the same fail-closed shape
// internal/responsefilter takes on the classic Docker API path, where an
// unparsable protected response becomes a generic error instead of forwarded
// data. Buffering is bounded by Limits.MaxMessageBytes, the identical cap
// forwardWithBody applies to this response today.
//
// A response-side failure here is NOT counted against the denied-stream abuse
// budget, unlike forwardStreamRelay's response-side denials. On EndpointGRPC
// the responder is buildkitd itself, not the untrusted client, and no field a
// client controls on either of these requests can make the daemon emit a
// response this filter rejects — so charging the client's budget for it would
// let a schema-drifted daemon tear down every tunnel. This matches
// forwardWithBody, whose own response-direction size-cap trip is audited
// without calling recordDeniedAndMaybeClose either.
func (b *bridge) forwardControlInfoMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	var fields map[protowire.Number]responseFieldRule
	switch method {
	case "Info":
		fields = controlInfoResponseFields
	case "ListWorkers":
		fields = controlListWorkersResponseFields
	default:
		// Unreachable today — isControlResponseFilteredMethod names exactly
		// these two — but if it and this switch ever drift, fail CLOSED
		// rather than fall through with a nil table, which
		// filterControlResponseMessage would treat as "every field number is
		// unknown" and deny anyway, but only after the round trip already
		// happened. Same defensive-default convention as
		// forwardControlMediated's own switch.
		writeGRPCStatus(w, grpcCodeInternal, "internal routing error")
		b.audit(service, method, Deny, "buildkit_internal_error")
		b.recordDeniedAndMaybeClose()
		return
	}

	host := r.Host
	if host == "" {
		host = "buildkitd"
	}

	outReq := &http.Request{
		Method:        r.Method,
		URL:           &url.URL{Scheme: "http", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery},
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        r.Header.Clone(),
		Host:          host,
		Body:          newLimitedReadCloser(r.Body, b.limits.MaxMessageBytes),
		ContentLength: -1,
	}

	resp, err := b.clientLeg.RoundTrip(outReq.WithContext(r.Context()))
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {
			writeGRPCStatus(w, grpcCodeResourceExhausted, "request message exceeds sockguard's size cap")
			b.audit(service, method, Deny, "buildkit_message_too_large")
			return
		}
		b.logger.Warn("buildkit: forwarding stream failed; terminating tunnel",
			"error", logging.SafeString(err.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: forward %s/%s: %w", service, method, err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	frame, denial := filterControlUnaryResponse(newLimitedReadCloser(resp.Body, b.limits.MaxMessageBytes), b.limits.MaxMessageBytes, fields)
	if denial != nil {
		writeGRPCStatus(w, denial.code, denial.message)
		b.audit(service, method, Deny, denial.reasonCode)
		return
	}

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// The relayed body is a re-encoded frame, never the daemon's original
	// bytes, so any Content-Length the daemon declared no longer describes it.
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)

	if len(frame) > 0 {
		if _, werr := (flushWriter{w}).Write(frame); werr != nil {
			b.logger.Warn("buildkit: relaying stream response failed; terminating tunnel",
				"error", logging.SafeString(werr.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
				"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
			b.audit(service, method, Deny, "buildkit_protocol_error")
			b.closeAll(fmt.Errorf("buildkitproxy: relay %s/%s response: %w", service, method, werr))
			return
		}
	}

	for k, vv := range resp.Trailer {
		for _, v := range vv {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
	b.audit(service, method, Mediate, "")
}

// filterControlUnaryResponse reads the single gRPC length-prefixed message a
// unary RPC's response stream carries, rewrites it against fields, and
// returns the re-encoded frame ready to write to the client.
//
// Info and ListWorkers are both unary/unary in upstream's control.proto —
// neither side is declared `stream` — but the gRPC wire format cannot enforce
// that, so the shape is checked rather than assumed. A response carrying no
// message at all is legal and returns (nil, nil): that is what a gRPC error
// status looks like (Trailers-Only, or headers plus trailers with no
// DATA frame), and the caller relays the daemon's own status untouched. A
// response carrying MORE than one message is a protocol violation for a unary
// RPC and fails closed, the same way framing.go's readUnaryGRPCMessage
// rejects trailing bytes on a unary REQUEST stream.
//
// maxLen bounds the payload length any single frame's header may declare,
// before any attempt to read that many bytes; src is expected to already be
// wrapped in a limitedReadCloser so the cumulative response is bounded too.
func filterControlUnaryResponse(src io.Reader, maxLen int64, fields map[protowire.Number]responseFieldRule) ([]byte, *mediationDenial) {
	_, payload, err := readGRPCFrame(src, maxLen)
	switch {
	case errors.Is(err, io.EOF):
		return nil, nil
	case errors.Is(err, errMessageTooLarge):
		return nil, deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "response message exceeds sockguard's size cap")
	case err != nil:
		return nil, denyControlResponseUnparsable()
	}

	filtered, denial := filterControlResponseMessage(payload, fields)
	if denial != nil {
		return nil, denial
	}

	if _, _, err := readGRPCFrame(src, maxLen); !errors.Is(err, io.EOF) {
		return nil, denyControlResponseUnparsable()
	}

	frame := make([]byte, grpcMessageHeaderLen+len(filtered))
	//nolint:gosec // G115: len(filtered) always fits a uint32. It is bounded by the payload readGRPCFrame returned, whose length came from the frame header's own uint32, and filtering only ever removes fields and re-encodes tags/lengths minimally — the result is never longer than the input.
	binary.BigEndian.PutUint32(frame[1:grpcMessageHeaderLen], uint32(len(filtered)))
	copy(frame[grpcMessageHeaderLen:], filtered)
	return frame, nil
}

// filterControlResponseMessage rewrites one protobuf message's wire bytes to
// contain only the fields named in fields, recursing into nested tables.
// Every field number in every table above is length-delimited (a string, a
// submessage, or a map entry), so a known field arriving with any other wire
// type is treated as unparsable rather than guessed at.
//
// Denials distinguish the two failure causes an operator needs to tell apart:
// an unrecognized field number is schema drift the daemon introduced
// (buildkit_schema_unsupported — a reviewed table bump is the fix), while
// malformed wire bytes or an unexpected wire type mean the response could not
// be sanitized at all (buildkit_response_filter_failed). Neither ever falls
// back to relaying the original bytes.
func filterControlResponseMessage(payload []byte, fields map[protowire.Number]responseFieldRule) ([]byte, *mediationDenial) {
	out := make([]byte, 0, len(payload))
	for len(payload) > 0 {
		number, wireType, tagLen := protowire.ConsumeTag(payload)
		if tagLen < 0 {
			return nil, denyControlResponseUnparsable()
		}
		payload = payload[tagLen:]

		valueLen := protowire.ConsumeFieldValue(number, wireType, payload)
		if valueLen < 0 {
			return nil, denyControlResponseUnparsable()
		}
		value := payload[:valueLen]
		payload = payload[valueLen:]

		rule, known := fields[number]
		if !known {
			return nil, deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
		}
		if wireType != protowire.BytesType {
			return nil, denyControlResponseUnparsable()
		}
		if rule.drop {
			continue
		}
		if rule.nested == nil {
			out = protowire.AppendTag(out, number, wireType)
			out = append(out, value...)
			continue
		}

		inner, innerLen := protowire.ConsumeBytes(value)
		if innerLen < 0 {
			return nil, denyControlResponseUnparsable()
		}
		nested, denial := filterControlResponseMessage(inner, rule.nested)
		if denial != nil {
			return nil, denial
		}
		out = protowire.AppendTag(out, number, protowire.BytesType)
		out = protowire.AppendBytes(out, nested)
	}
	return out, nil
}

// denyControlResponseUnparsable is the single denial every "sockguard cannot
// make sense of these response bytes" path returns. Internal rather than
// InvalidArgument because on EndpointGRPC the peer that produced the bytes is
// buildkitd, not the client being answered — nothing the client sent is
// wrong.
func denyControlResponseUnparsable() *mediationDenial {
	return deny(grpcCodeInternal, "buildkit_response_filter_failed", "the BuildKit daemon's response could not be filtered")
}
