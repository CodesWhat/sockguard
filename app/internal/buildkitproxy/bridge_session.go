// Package buildkitproxy — this file carries Phase 4 (issue #185)'s HTTP-
// orchestration layer for the EndpointSession RPCs mediated at the
// per-message level: moby.filesync.v1.Auth's four RPCs,
// moby.buildkit.secrets.v1.Secrets/GetSecret, and moby.sshforward.v1.SSH's
// CheckAgent/ForwardAgent. It mirrors bridge.go's forwardControlMediated —
// buffer/decode/policy-check, then on admission forward the client's
// ORIGINAL frame bytes verbatim, never re-encoded — calling into
// session_mediation.go's pure evaluate* functions for the actual decisions.
// FileSync/FileSend/Upload are Phase 5's scope and are NOT touched here;
// they stay on bridge.go's plain byte-verbatim forward.
package buildkitproxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/codeswhat/sockguard/internal/buildkitproto/auth"
	"github.com/codeswhat/sockguard/internal/logging"
)

// isSessionMediatedMethod reports whether service/method on endpoint is one
// of Phase 4's per-message-mediated EndpointSession RPCs. FileSync/FileSend/
// Upload deliberately stay OUT of this function's true set — Phase 5's
// scope — so handleStream keeps routing them through the plain forward()
// path unchanged.
func isSessionMediatedMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointSession {
		return false
	}
	switch service {
	case "moby.filesync.v1.Auth":
		switch method {
		case "Credentials", "FetchToken", "GetTokenAuthority", "VerifyTokenAuthority":
			return true
		}
	case "moby.buildkit.secrets.v1.Secrets":
		return method == "GetSecret"
	case "moby.sshforward.v1.SSH":
		switch method {
		case "CheckAgent", "ForwardAgent":
			return true
		}
	}
	return false
}

// forwardSessionMediated is Phase 4's entry point for every
// isSessionMediatedMethod call: it enforces the per-session credential-call
// quota shared across all of them (Limits.MaxCredentialCallsPerSession —
// see its doc comment for why Auth/Secrets/SSH share one counter rather than
// each getting their own), then dispatches to the per-service handler. A
// quota trip is a per-RPC resource condition, not a policy denial or
// protocol error, so unlike every other denial path in this file it does
// NOT call recordDeniedAndMaybeClose — a client legitimately admitted by
// policy that simply made too many calls is not the connection-level abuse
// signal that guard exists to catch.
func (b *bridge) forwardSessionMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	if !b.admitCredentialCall() {
		writeGRPCStatus(w, grpcCodeResourceExhausted, "too many BuildKit credential session calls for this session")
		b.audit(service, method, Deny, "buildkit_credential_call_limit_exceeded")
		return
	}

	switch service {
	case "moby.filesync.v1.Auth":
		b.forwardAuthMediated(w, r, service, method)
	case "moby.buildkit.secrets.v1.Secrets":
		b.forwardSecretsMediated(w, r, service, method)
	case "moby.sshforward.v1.SSH":
		b.forwardSSHMediated(w, r, service, method)
	default:
		// Unreachable today — isSessionMediatedMethod only routes these three
		// services — but if it and this switch ever drift (a service added to
		// one and not the other), fail CLOSED rather than forward with zero
		// policy evaluation, mirroring forwardControlMediated's identical
		// defensive default.
		d := deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
	}
}

// admitCredentialCall increments and checks the bridge's per-session
// credential-call counter against Limits.MaxCredentialCallsPerSession. Safe
// for concurrent use — buildkitd may have multiple Auth/Secrets/SSH streams
// in flight at once on the same tunnel, each on its own http2.Server
// handler goroutine. A zero or negative limit disables the quota.
func (b *bridge) admitCredentialCall() bool {
	if b.limits.MaxCredentialCallsPerSession <= 0 {
		return true
	}
	return b.credentialCalls.Add(1) <= int64(b.limits.MaxCredentialCallsPerSession)
}

// denyFramingError maps readUnaryGRPCMessage's error into the right gRPC
// status and audit reason for a Phase 4 session-mediated unary RPC —
// identical in shape to forwardControlMediated's own inline handling of the
// same error, factored out here since Phase 4 has four call sites for it
// (Auth's four RPCs collapse to one readUnaryGRPCMessage call site each
// serviced by forwardAuthMediated, plus Secrets and CheckAgent) rather than
// Phase 3's two.
func (b *bridge) denyFramingError(w http.ResponseWriter, service, method string, err error) {
	if errors.Is(err, errMessageTooLarge) {
		writeGRPCStatus(w, grpcCodeResourceExhausted, "request message exceeds sockguard's size cap")
		b.audit(service, method, Deny, "buildkit_message_too_large")
		return
	}
	writeGRPCStatus(w, grpcCodeInvalidArgument, "malformed BuildKit gRPC request framing")
	b.audit(service, method, Deny, "buildkit_protocol_error")
	b.recordDeniedAndMaybeClose()
}

// forwardAuthMediated mediates moby.filesync.v1.Auth's four RPCs: buffer the
// daemon's single gRPC request message, decode/policy-check it via
// session_mediation.go's evaluate* functions, and on admission forward the
// ORIGINAL frame bytes verbatim. Response bodies — which for Credentials/
// FetchToken carry actual secret material (CredentialsResponse.Secret,
// FetchTokenResponse.Token) — are never decoded on this path.
func (b *bridge) forwardAuthMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		b.denyFramingError(w, service, method, err)
		return
	}

	var (
		d    *mediationDenial
		host string
	)
	switch method {
	case "Credentials":
		var req *auth.CredentialsRequest
		req, d = evaluateCredentialsRequest(payload, b.policy.Session.Auth)
		if req != nil {
			host = req.GetHost()
		}
	case "FetchToken":
		var req *auth.FetchTokenRequest
		req, d = evaluateFetchTokenRequest(payload, b.policy.Session.Auth)
		if req != nil {
			host = req.GetHost()
		}
	case "GetTokenAuthority":
		var req *auth.GetTokenAuthorityRequest
		req, d = evaluateGetTokenAuthorityRequest(payload, b.policy.Session.Auth)
		if req != nil {
			host = req.GetHost()
		}
	case "VerifyTokenAuthority":
		var req *auth.VerifyTokenAuthorityRequest
		req, d = evaluateVerifyTokenAuthorityRequest(payload, b.policy.Session.Auth)
		if req != nil {
			host = req.GetHost()
		}
	default:
		// Unreachable today — isSessionMediatedMethod's Auth case only routes
		// these four method names — but fail CLOSED on drift regardless, same
		// rationale as forwardSessionMediated's own default arm.
		d = deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
	}

	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	// Registry hosts are low-cardinality operator-facing config values, not
	// secrets — safe to log in the clear (unlike the secret/SSH IDs
	// forwardSecretsMediated/forwardCheckAgent/forwardSSHAgentStream hash
	// before logging). But log the NORMALIZED host — the value policy
	// actually compared — never req.GetHost() raw: normalizeAuthHost trims
	// surrounding whitespace before the allowlist comparison, so an admitted
	// raw Host may still carry leading/trailing CR/LF that would forge audit
	// log lines. SafeString on top matches every other attr audit emits.
	normalizedHost, _ := normalizeAuthHost(host)
	b.audit(service, method, Mediate, "", slog.String("registry_host", logging.SafeString(normalizedHost)))
	b.forwardWithBody(w, r, service, method, io.NopCloser(bytes.NewReader(frame)))
}

// forwardSecretsMediated mediates moby.buildkit.secrets.v1.Secrets/GetSecret:
// buffer, decode/policy-check via evaluateGetSecretRequest, and on admission
// forward the ORIGINAL frame bytes verbatim. The response
// (GetSecretResponse.data) carries the actual secret content — never decoded
// or logged on this path.
func (b *bridge) forwardSecretsMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		b.denyFramingError(w, service, method, err)
		return
	}

	req, d := evaluateGetSecretRequest(payload, b.policy.Session.Secrets)
	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	b.audit(service, method, Mediate, "", slog.String("secret_id_sha256", shortHash(req.GetID())))
	b.forwardWithBody(w, r, service, method, io.NopCloser(bytes.NewReader(frame)))
}

// forwardSSHMediated dispatches moby.sshforward.v1.SSH's two RPCs to their
// own handlers: CheckAgent is unary (a decoded request message to check),
// ForwardAgent is a bidirectional byte stream gated by metadata instead (see
// forwardSSHAgentStream).
func (b *bridge) forwardSSHMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	switch method {
	case "CheckAgent":
		b.forwardCheckAgent(w, r, service, method)
	case "ForwardAgent":
		b.forwardSSHAgentStream(w, r, service, method)
	default:
		// Unreachable today — isSessionMediatedMethod's SSH case only routes
		// these two method names — but fail CLOSED on drift regardless.
		d := deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
	}
}

// forwardCheckAgent mediates moby.sshforward.v1.SSH/CheckAgent: buffer,
// decode/policy-check via evaluateCheckAgentRequest, and on admission
// forward the ORIGINAL frame bytes verbatim.
func (b *bridge) forwardCheckAgent(w http.ResponseWriter, r *http.Request, service, method string) {
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		b.denyFramingError(w, service, method, err)
		return
	}

	req, d := evaluateCheckAgentRequest(payload, b.policy.Session.SSH)
	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	b.audit(service, method, Mediate, "", slog.String("ssh_id_sha256", shortHash(req.GetID())))
	b.forwardWithBody(w, r, service, method, io.NopCloser(bytes.NewReader(frame)))
}

// forwardSSHAgentStream mediates moby.sshforward.v1.SSH/ForwardAgent: a
// bidirectional stream of raw BytesMessage frames carrying the actual SSH
// agent protocol. Per the #185 Phase 4 requirement, those bytes are opaque
// and MUST NEVER be decoded or logged — the only mediation decision here is
// the agent ID carried in the stream's gRPC metadata
// (evaluateForwardAgentID), checked BEFORE a single byte of the stream is
// relayed. Once admitted, this is exactly forward()'s plain byte-verbatim
// relay (the same size caps apply via forwardWithBody's limitedReadCloser on
// both directions) — no framing or decoding of any kind, in either
// direction, at any point.
func (b *bridge) forwardSSHAgentStream(w http.ResponseWriter, r *http.Request, service, method string) {
	id, d := evaluateForwardAgentID(r, b.policy.Session.SSH)
	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	b.audit(service, method, Mediate, "", slog.String("ssh_id_sha256", shortHash(id)))
	b.forwardWithBody(w, r, service, method, r.Body)
}
