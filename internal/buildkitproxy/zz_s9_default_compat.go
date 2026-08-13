package buildkitproxy

import (
	"bufio"

	"bytes"
	"context"

	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"encoding/hex"
	"errors"
	"fmt"

	"github.com/codeswhat/sockguard/internal/buildkitproto/auth"

	"github.com/codeswhat/sockguard/internal/buildkitproto/control"

	"github.com/codeswhat/sockguard/internal/buildkitproto/fsutiltypes"
	"github.com/codeswhat/sockguard/internal/buildkitproto/secrets"
	"github.com/codeswhat/sockguard/internal/buildkitproto/sshforward"

	"github.com/codeswhat/sockguard/internal/buildkitproto/upload"

	"github.com/codeswhat/sockguard/internal/dockerfileinspect"
	"github.com/codeswhat/sockguard/internal/httpjson"

	"github.com/codeswhat/sockguard/internal/logging"
	"golang.org/x/net/http2"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"io"
	"log/slog"
	"net"

	"net/http"
	"net/textproto"

	"net/url"
	"path"

	"regexp"
	"slices"
	"sort"

	"strconv"
	"strings"
	"sync"

	"sync/atomic"
	"time"
)

// errMessageTooLarge is returned by limitedReadCloser once a stream's
// cumulative bytes exceed its configured cap. It is a stream-local
// condition, never grounds for tearing down the whole tunnel — see
// bridge.forward's handling.
var errMessageTooLarge = errors.New("buildkitproxy: message exceeds configured size cap")

// bridgeLegs names the two connections a mediated tunnel bridges, already
// assigned to their h2c ROLE (not their client/daemon identity, which
// differs by endpoint — see the doc comments on Mediator.ServeGRPC/
// ServeSession): serverConn is where sockguard runs http2.Server.ServeConn
// (accepting incoming streams as one *http.Request per stream), and
// clientConn is the connection sockguard dials outbound requests on via an
// http2.Transport-backed http2.ClientConn.
//
// For EndpointGRPC (POST /grpc): serverConn is the hijacked Docker-client
// connection (the client is the gRPC client dialing IN to sockguard),
// clientConn is sockguard's own dial to the daemon (the daemon is the gRPC
// server sockguard dials OUT to).
//
// For EndpointSession (POST /session), per the #185 synthesis's reversed
// roles: serverConn is sockguard's own dial to the daemon (buildkitd
// becomes the gRPC CLIENT, dialing calls in over that connection),
// clientConn is the hijacked Docker-client connection (the CLI runs the
// gRPC SERVER for Auth/Secrets/SSH/FileSync/FileSend/Upload on its side of
// that same hijacked connection).
type bridgeLegs struct {
	endpoint   Endpoint
	serverConn net.Conn
	clientConn net.Conn
}

// clientLegConn is the minimal surface bridge.forward and bridge.closeAll
// need from the client leg's HTTP/2 connection. *http2.ClientConn satisfies
// this structurally in production; tests exercising forward()'s error
// handling (a genuine RoundTrip failure vs. a response-body copy failure vs.
// the size-cap path) use a hand-rolled fake instead of driving a real
// network round trip end to end, since those specific failure modes aren't
// reproducible deterministically over a live http2.ClientConn.
type clientLegConn interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Close() error
}

// bridge holds the per-tunnel state the routing handler (handleStream)
// closes over: which session this is, what policy/limits govern it, and the
// single client-leg connection every admitted stream is relayed through.
type bridge struct {
	legs     bridgeLegs
	session  *Session
	policy   Policy
	limits   Limits
	logger   *slog.Logger
	guard    *streamAbuseGuard
	registry *SessionRegistry

	clientLeg clientLegConn

	// credentialCalls is Phase 4's per-session credential-call counter — see
	// Limits.MaxCredentialCallsPerSession and forwardSessionMediated
	// (bridge_session.go) for what it bounds. atomic.Int64 rather than a
	// mutex-guarded int since concurrent http2.Server handler goroutines (one
	// per stream) may all be admitting Auth/Secrets/SSH calls at once.
	credentialCalls atomic.Int64

	closeOnce sync.Once
	closeMu   sync.Mutex
	closeErr  error
}

// runBridge terminates legs.serverConn as h2c, dials legs.clientConn as an
// h2c client, and relays every admitted stream between them until the
// connection ends (gracefully or otherwise). It blocks until done. A
// non-nil return means the tunnel was torn down because of a protocol/
// transport-level failure — a Deny'd stream or a size-cap trip on an
// otherwise-healthy connection is NOT such a failure and does not produce a
// non-nil return (see bridge.forward and bridge.recordDeniedAndMaybeClose,
// which close early only once the DeniedStreamBudget itself is exceeded).
// registry is the same SessionRegistry session was opened from — Phase 3's
// forwardControlMediated consults it (via SessionKey, not session.ID; see
// SessionRegistry.OwnsRef's doc comment) to admit Control/Solve refs and
// check Control/Status ref ownership.
func runBridge(ctx context.Context, legs bridgeLegs, session *Session, policy Policy, limits Limits, logger *slog.Logger, registry *SessionRegistry) error {
	b := &bridge{
		legs:     legs,
		session:  session,
		policy:   policy,
		limits:   limits,
		logger:   logger,
		guard:    newStreamAbuseGuard(limits),
		registry: registry,
	}
	defer b.closeAll(nil)

	clientTransport := &http2.Transport{AllowHTTP: true}
	cc, err := clientTransport.NewClientConn(legs.clientConn)
	if err != nil {

		b.closeAll(fmt.Errorf("buildkitproxy: establish client leg: %w", err))
		return b.finalErr()
	}
	b.clientLeg = cc

	srv := &http2.Server{
		MaxConcurrentStreams: limits.MaxConcurrentStreams,
		IdleTimeout:          limits.IdleTimeout,
		ReadIdleTimeout:      limits.ReadIdleTimeout,
	}
	srv.ServeConn(legs.serverConn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(b.handleStream),
	})

	return b.finalErr()
}

// closeAll closes both legs of the tunnel exactly once. err, if non-nil, is
// recorded as runBridge's return value — used for genuine protocol/transport
// failures per the #185 Phase 2 scope's fail-closed requirement ("any error
// in the bridge... must terminate the tunnel, never fall back to opaque
// proxying"). A nil err (the normal path, via runBridge's deferred call)
// just performs cleanup after a graceful end.
//
// closeAll is called from both runBridge's own goroutine (the deferred
// cleanup, and the early client-leg-handshake-failure path) and stream
// handler goroutines http2.Server spawns (recordDeniedAndMaybeClose, forward)
// — closeErr is guarded by closeMu, not just closeOnce, because closing
// legs.serverConn here and runBridge's ServeConn call noticing that closure
// and returning are NOT themselves a synchronization point the Go memory
// model recognizes: without closeMu, runBridge reading closeErr after
// ServeConn returns would be a data race with a handler goroutine's write
// inside this closure. See finalErr, which every closeErr read must go
// through instead of touching the field directly.
func (b *bridge) closeAll(err error) {
	b.closeOnce.Do(func() {
		b.closeMu.Lock()
		b.closeErr = err
		b.closeMu.Unlock()
		if b.clientLeg != nil {
			_ = b.clientLeg.Close()
		}
		_ = b.legs.clientConn.Close()
		_ = b.legs.serverConn.Close()
	})
}

// finalErr returns the error closeAll recorded (nil if closeAll was never
// called, or was called with nil) — the only safe way to read closeErr once
// more than one goroutine may have touched it. See closeAll's doc comment.
func (b *bridge) finalErr() error {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	return b.closeErr
}

// handleStream is the http.Handler golang.org/x/net/http2.Server invokes
// once per HTTP/2 stream on the server leg — one *http.Request per gRPC
// call, per the #185 synthesis's chosen bridging granularity (see
// registry.go's package doc). It classifies the call's fully-qualified
// method through the Phase 1 registry, then — for a Mediate or Passthrough
// category — checks whether this request's Policy actually turned that
// category on (Policy.Allowed; see its doc comment for why this is a
// separate, necessary gate). A call that clears both checks is, for every
// method EXCEPT moby.buildkit.v1.Control's Solve/Status, relayed
// byte-for-byte to the client leg with no message-content decision (Phase
// 2's scope; the remaining Session-endpoint Mediate methods — Auth, Secrets,
// SSH, FileSync, FileSend, Upload — get their own per-message mediation in
// Phases 4-5). Solve/Status route through forwardControlMediated instead —
// see isControlMediatedMethod.
func (b *bridge) handleStream(w http.ResponseWriter, r *http.Request) {
	service, method, ok := ParseGRPCPath(r.URL.Path)
	if !ok {
		writeGRPCStatus(w, grpcCodeUnimplemented, "malformed gRPC method path")
		b.audit("", "", Deny, "buildkit_protocol_error")
		b.recordDeniedAndMaybeClose()
		return
	}

	disposition := Classify(b.legs.endpoint, service, method)
	switch disposition {
	case Mediate, Passthrough:
		if !b.policy.Allowed(b.legs.endpoint, service, method) {

			writeGRPCStatus(w, grpcCodePermissionDenied, fmt.Sprintf("%s/%s is not enabled by this profile's request_body.buildkit policy", service, method))
			b.audit(service, method, Deny, "buildkit_policy_denied")
			b.recordDeniedAndMaybeClose()
			return
		}
		if isControlMediatedMethod(b.legs.endpoint, service, method) {

			b.forwardControlMediated(w, r, service, method)
			return
		}
		if isSessionMediatedMethod(b.legs.endpoint, service, method) {

			b.forwardSessionMediated(w, r, service, method)
			return
		}
		if isStreamMediatedMethod(b.legs.endpoint, service, method) {

			b.forwardStreamMediated(w, r, service, method)
			return
		}
		b.audit(service, method, disposition, "")
		b.forward(w, r, service, method)
	default:

		writeGRPCStatus(w, grpcCodePermissionDenied, fmt.Sprintf("%s/%s is denied by sockguard's BuildKit mediation policy", service, method))
		b.audit(service, method, Deny, "buildkit_method_denied")
		b.recordDeniedAndMaybeClose()
	}
}

// recordDeniedAndMaybeClose records a Deny/protocol-error stream against the
// connection's abuse budget and tears the whole tunnel down once that budget
// is exceeded — see Limits' doc comment for why a burst of denials is
// itself an abuse signal on a connection that should almost never produce
// one.
func (b *bridge) recordDeniedAndMaybeClose() {
	if b.guard.recordDenied() {
		b.logger.Warn("buildkit: denied-stream budget exceeded; terminating tunnel",
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.closeAll(errors.New("buildkitproxy: denied-stream abuse budget exceeded"))
	}
}

// forward relays one admitted (Mediate or Passthrough) stream to the client
// leg, preserving original request/response bytes verbatim — no protobuf
// decode/re-encode on this path (Phase 2 scope, and still true for every
// Phase 3+ method that isn't Control/Solve or Control/Status). It is a thin
// wrapper over forwardWithBody using the stream's own r.Body unmodified;
// forwardControlMediated instead supplies an already-buffered, already
// policy-checked body (the exact bytes readUnaryGRPCMessage read) once its
// own decode/policy checks pass.
func (b *bridge) forward(w http.ResponseWriter, r *http.Request, service, method string) {
	b.forwardWithBody(w, r, service, method, r.Body)
}

// forwardWithBody does forward's actual relay work against an explicit body
// rather than always r.Body — see forward's doc comment for why.  A genuine
// RoundTrip/transport failure tears the whole tunnel down (fail-closed); a
// size-cap trip on either direction ends only this stream with a
// RESOURCE_EXHAUSTED gRPC status, since an oversized single message is a
// per-RPC condition, not evidence the connection itself is compromised.
func (b *bridge) forwardWithBody(w http.ResponseWriter, r *http.Request, service, method string, body io.ReadCloser) {
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
		Body:          newLimitedReadCloser(body, b.limits.MaxMessageBytes),
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

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	limitedBody := newLimitedReadCloser(resp.Body, b.limits.MaxMessageBytes)
	_, copyErr := io.Copy(flushWriter{w}, limitedBody)

	switch {
	case errors.Is(copyErr, errMessageTooLarge):
		writeGRPCTrailerStatus(w, grpcCodeResourceExhausted, "response message exceeds sockguard's size cap")
		b.audit(service, method, Deny, "buildkit_message_too_large")
	case copyErr != nil:
		b.logger.Warn("buildkit: relaying stream response failed; terminating tunnel",
			"error", logging.SafeString(copyErr.Error()), "service", logging.SafeString(service), "method", logging.SafeString(method),
			"endpoint", b.legs.endpoint.String(), "session_id", b.session.ID)
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.closeAll(fmt.Errorf("buildkitproxy: relay %s/%s response: %w", service, method, copyErr))
	default:
		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(http.TrailerPrefix+k, v)
			}
		}
	}
}

// isControlMediatedMethod reports whether service/method on endpoint is one
// of Phase 3's two per-message-mediated Control RPCs — the only methods
// handleStream routes through forwardControlMediated instead of the plain
// byte-verbatim forward. Both are already Classify()'d Mediate and (by the
// time this is consulted) already passed Policy.Allowed — this function
// only decides which forwarding STRATEGY an already-admitted call uses.
func isControlMediatedMethod(endpoint Endpoint, service, method string) bool {
	if endpoint != EndpointGRPC || service != "moby.buildkit.v1.Control" {
		return false
	}
	return method == "Solve" || method == "Status"
}

// forwardControlMediated is Phase 3 (issue #185)'s per-message mediation
// path for Control/Solve and Control/Status: buffer the client's single gRPC
// request message (readUnaryGRPCMessage), decode it with the vendored
// buildkitproto stubs, run policy checks (evaluateSolveRequest /
// evaluateStatusRequest, plus Status's ref-ownership check below), and only
// on admission forward the exact original frame bytes via forwardWithBody —
// never a re-encoded message, per the #185 Phase 3 constraint. Every denial
// path here ends the STREAM only (a per-stream gRPC status plus
// recordDeniedAndMaybeClose's soft connection-abuse budget), matching the
// task's fail-closed granularity: "per-stream policy/decode failure -> gRPC
// status on that stream only, session survives."
func (b *bridge) forwardControlMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	frame, payload, err := readUnaryGRPCMessage(r.Body, b.limits.MaxMessageBytes)
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {

			writeGRPCStatus(w, grpcCodeResourceExhausted, "request message exceeds sockguard's size cap")
			b.audit(service, method, Deny, "buildkit_message_too_large")
			return
		}
		writeGRPCStatus(w, grpcCodeInvalidArgument, "malformed BuildKit gRPC request framing")
		b.audit(service, method, Deny, "buildkit_protocol_error")
		b.recordDeniedAndMaybeClose()
		return
	}

	var (
		d        *mediationDenial
		ref      string
		solveReq *control.SolveRequest
	)
	switch method {
	case "Solve":
		solveReq, d = evaluateSolveRequest(payload, b.policy)
		if solveReq != nil {
			ref = solveReq.GetRef()
		}
	case "Status":
		var req *control.StatusRequest
		req, d = evaluateStatusRequest(payload)
		if d == nil && !b.registry.OwnsRef(b.session.Key, req.GetRef()) {
			d = deny(grpcCodePermissionDenied, "buildkit_ref_not_owned", "this ref does not belong to an admitted Solve for this client/profile")
		}
	default:

		d = deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
	}

	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

	if method == "Solve" {
		if !b.registry.PutRef(b.session, ref, b.limits.MaxRefsPerSession) {
			writeGRPCStatus(w, grpcCodeResourceExhausted, "too many concurrent BuildKit solve refs admitted for this client")
			b.audit(service, method, Deny, "buildkit_ref_limit_exceeded")
			b.recordDeniedAndMaybeClose()
			return
		}

		if !admitSolveUploadKeys(b.registry, b.session.Key, solveReq, b.limits.MaxUploadKeysPerSession) {
			writeGRPCStatus(w, grpcCodeResourceExhausted, "too many BuildKit upload-session contexts named by this Solve for this client")
			b.audit(service, method, Deny, "buildkit_upload_key_limit_exceeded")
			b.recordDeniedAndMaybeClose()
			return
		}
	}

	b.audit(service, method, Mediate, "")
	b.forwardWithBody(w, r, service, method, io.NopCloser(bytes.NewReader(frame)))
}

// audit emits the #185 synthesis's buildkit_rpc audit event: one line per
// gRPC call carried inside the mediated tunnel. reasonCode is empty for an
// admitted (Mediate/Passthrough) call — only denials and errors carry one of
// the synthesis's low-cardinality reason codes. Never logs message content,
// credentials, or secret/SSH identifiers raw — this event carries only
// method identity and the routing decision, plus whatever extra attrs a
// caller supplies. extra is Phase 4's addition (bridge_session.go's
// forwardAuthMediated/forwardSecretsMediated/forwardCheckAgent/
// forwardSSHAgentStream): a registry host (low-cardinality, safe to log raw)
// or a secret/SSH agent ID hashed via shortHash (never raw) — every other
// caller in this package passes none, which is a no-op append.
func (b *bridge) audit(service, method string, disposition Disposition, reasonCode string, extra ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("event", "buildkit_rpc"),
		slog.String("endpoint", b.legs.endpoint.String()),
		slog.Uint64("session_id", b.session.ID),
		slog.String("profile", logging.SafeString(b.session.Profile)),
		slog.String("service", logging.SafeString(service)),
		slog.String("method", logging.SafeString(method)),
		slog.String("disposition", disposition.String()),
	}
	if reasonCode != "" {
		attrs = append(attrs, slog.String("reason_code", reasonCode))
	}
	attrs = append(attrs, extra...)
	level := slog.LevelDebug
	if disposition == Deny {
		level = slog.LevelInfo
	}
	b.logger.LogAttrs(context.Background(), level, "buildkit gRPC call routed", attrs...)
}

// flushWriter wraps an http.ResponseWriter so every Write flushes
// immediately, matching sockguard's existing FlushInterval:-1 convention
// (internal/proxy.NewWithTransport) for streaming endpoints — a mediated
// BuildKit stream is exactly that, and gRPC's framing already provides its
// own message boundaries so buffering here would only add latency, never
// throughput.
type flushWriter struct {
	w http.ResponseWriter
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// limitedReadCloser caps the cumulative bytes read from r at limit,
// returning errMessageTooLarge once that many bytes are EXCEEDED — a body of
// exactly limit bytes must still reach the underlying reader's own io.EOF
// cleanly, never errMessageTooLarge. remaining tracks bytes still allowed,
// but Read buffers one byte past it (following the same technique as the
// stdlib's http.MaxBytesReader) so a single Read can distinguish "the
// underlying reader stopped at exactly the cap" from "there was at least one
// more byte beyond it" without needing a lookahead Read of its own. A limit
// <= 0 disables the cap (returns r unchanged).
type limitedReadCloser struct {
	r         io.ReadCloser
	remaining int64
}

func newLimitedReadCloser(r io.ReadCloser, limit int64) io.ReadCloser {
	if limit <= 0 || r == nil {
		return r
	}
	return &limitedReadCloser{r: r, remaining: limit}
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {

	if int64(len(p))-1 > l.remaining {
		p = p[:l.remaining+1]
	}
	n, err := l.r.Read(p)

	if int64(n) <= l.remaining {
		l.remaining -= int64(n)
		return n, err
	}

	n = int(l.remaining)
	l.remaining = 0
	return n, errMessageTooLarge
}

func (l *limitedReadCloser) Close() error {
	return l.r.Close()
}

// isSessionMediatedMethod reports whether service/method on endpoint is one
// of Phase 4's per-message-mediated EndpointSession RPCs. FileSync/FileSend/
// Upload stay OUT of this function's true set — they are Phase 5's scope and
// route through isStreamMediatedMethod/forwardStreamMediated instead.
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

		d = deny(grpcCodeInternal, "buildkit_internal_error", "internal routing error")
	}

	if d != nil {
		writeGRPCStatus(w, d.code, d.message)
		b.audit(service, method, Deny, d.reasonCode)
		b.recordDeniedAndMaybeClose()
		return
	}

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

// forwardFileSendMediated is bridge.go's dispatch target for
// moby.filesync.v1.FileSend/DiffCopy (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated).
//
// The SessionRegistry.HasAdmittedSolve check runs BEFORE any stream relay
// begins — a pre-condition on the whole call, not a per-message check — per
// the #185 synthesis's "allow only when bound to an admitted Solve from the
// same SessionKey" (buildkit_session_mismatch on failure). FileSend's
// BytesMessage.Data carries no ref or other identifying field of its own to
// check with a more specific SessionRegistry.OwnsRef lookup (unlike
// Control/Status, which names the ref it's asking about directly) — "has
// this identity+profile solved anything at all yet" is the strongest check
// available; see HasAdmittedSolve's own doc comment.
func (b *bridge) forwardFileSendMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	if !b.registry.HasAdmittedSolve(b.session.Key) {
		writeGRPCStatus(w, grpcCodePermissionDenied, "FileSend requires an admitted BuildKit solve for this client/profile")
		b.audit(service, method, Deny, "buildkit_session_mismatch")
		b.recordDeniedAndMaybeClose()
		return
	}

	reqCap := &rawByteCapValidator{maxTotalBytes: b.limits.MaxFileSendBytes}
	respCap := &rawByteCapValidator{maxTotalBytes: b.limits.MaxFileSendBytes}

	b.forwardStreamRelay(w, r, service, method, reqCap.validate, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return relayValidatedFrames(w, src, b.limits.MaxMessageBytes, respCap.validate)
	})
}

// fsutilDirNameHeader is the gRPC metadata key — surfaced as an HTTP/2
// header by the h2c mediation this package builds on — buildx sets on every
// FileSync/DiffCopy call to name which local directory the sync is for. See
// this file's package doc for the upstream source confirming both the key
// name and buildx's two literal values.
const fsutilDirNameHeader = "dir-name"

// fsutilDirNameDockerfile is the one dir-name value that triggers hold-and-
// inspect. Every other value (buildx's "context", any named additional
// build context, or an absent/empty header) gets caps + structural
// validation only — the #185 synthesis's "context filesync gets caps +
// structural validation but NOT content inspection" applied literally: only
// this exact name is treated specially, nothing else is guessed at.
const fsutilDirNameDockerfile = "dockerfile"

// forwardFileSyncMediated is bridge.go's dispatch target for
// moby.filesync.v1.FileSync/DiffCopy (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated). It builds the request- and
// response-direction validators/relays described in this file's package doc
// and hands them to forwardStreamRelay, which owns the actual RoundTrip/
// header-copy/audit plumbing shared by every Phase 5 streaming method.
func (b *bridge) forwardFileSyncMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	isDockerfile := r.Header.Get(fsutilDirNameHeader) == fsutilDirNameDockerfile
	holdForInspection := isDockerfile && !b.policy.Control.Solve.AllowRunInstructions

	resp := newFileSyncRespRelay(holdForInspection, b.limits.MaxFileSyncFiles, b.limits.MaxFileSyncPathLength, b.limits.MaxFileSyncFileBytes, b.limits.MaxFileSyncTotalBytes)

	b.forwardStreamRelay(w, r, service, method, validateFileSyncRequestPacket, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return resp.relay(w, src, b.limits.MaxMessageBytes)
	})
}

// validateFileSyncRequestPacket is the per-message validator for FileSync/
// DiffCopy's REQUEST direction: structural validation only (decode, unknown
// fields, and a packet-type check restricted to the three types fsutil's
// receiver ever actually sends — see this file's package doc). No path or
// byte-cap concern lives on this side; those apply to the response
// direction's PACKET_STAT/PACKET_DATA instead (fileSyncRespRelay).
func validateFileSyncRequestPacket(payload []byte) *mediationDenial {
	pkt := &fsutiltypes.Packet{}
	if err := proto.Unmarshal(payload, pkt); err != nil {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed FileSync packet")
	}
	if hasUnknownFields(pkt) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	switch pkt.GetType() {
	case fsutiltypes.Packet_PACKET_REQ, fsutiltypes.Packet_PACKET_FIN, fsutiltypes.Packet_PACKET_ERR:
		return nil
	default:
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "unexpected FileSync packet type for this stream direction")
	}
}

// heldFileSyncEntry accumulates one file's PACKET_DATA content (and the
// original frame bytes to replay verbatim once released) while
// fileSyncRespRelay holds it for Dockerfile inspection.
type heldFileSyncEntry struct {
	content []byte
	frames  [][]byte
}

// fileSyncRespRelay is the stateful, per-stream response-direction handler
// for FileSync/DiffCopy: it decodes every Packet, enforces the file-count/
// path-length/byte caps described in limits.go's Phase 5 field doc comments,
// and — when holdForInspection is true — buffers each file's DATA
// independently (keyed by its Stat-assigned ID; see this file's package doc
// on interleaving) until that file's own EOF, running dockerfileinspect
// against the reassembled bytes before releasing them.
type fileSyncRespRelay struct {
	holdForInspection bool
	maxFiles          int
	maxPathLength     int
	maxFileBytes      int64
	maxTotalBytes     int64

	fileCount     int
	totalBytes    int64
	nextStatIndex uint32
	fileBytes     map[uint32]int64
	held          map[uint32]*heldFileSyncEntry
	doneFiles     map[uint32]bool
}

func newFileSyncRespRelay(holdForInspection bool, maxFiles, maxPathLength int, maxFileBytes, maxTotalBytes int64) *fileSyncRespRelay {
	return &fileSyncRespRelay{
		holdForInspection: holdForInspection,
		maxFiles:          maxFiles,
		maxPathLength:     maxPathLength,
		maxFileBytes:      maxFileBytes,
		maxTotalBytes:     maxTotalBytes,
		fileBytes:         make(map[uint32]int64),
		held:              make(map[uint32]*heldFileSyncEntry),
		doneFiles:         make(map[uint32]bool),
	}
}

// relay is fileSyncRespRelay's read loop: decode one gRPC frame at a time
// from src (readGRPCFrame — the same streaming framing every Phase 5 method
// uses), dispatch by Packet type, and write admitted frames to w. Matches
// forwardStreamRelay's relayResponse signature.
func (s *fileSyncRespRelay) relay(w http.ResponseWriter, src io.Reader, maxMessageBytes int64) (*mediationDenial, error) {
	fw := flushWriter{w}
	for {
		frame, payload, err := readGRPCFrame(src, maxMessageBytes)
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			if errors.Is(err, errMessageTooLarge) {
				return deny(grpcCodeResourceExhausted, "buildkit_message_too_large", "a message exceeds sockguard's size cap"), nil
			}
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC stream framing"), nil
		}

		pkt := &fsutiltypes.Packet{}
		if err := proto.Unmarshal(payload, pkt); err != nil {
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed FileSync packet"), nil
		}
		if hasUnknownFields(pkt) {
			return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema"), nil
		}

		switch pkt.GetType() {
		case fsutiltypes.Packet_PACKET_STAT:
			if d := s.handleStat(pkt); d != nil {
				return d, nil
			}
			if _, werr := fw.Write(frame); werr != nil {
				return nil, werr
			}
		case fsutiltypes.Packet_PACKET_DATA:
			d, release := s.handleData(pkt, frame)
			if d != nil {
				return d, nil
			}
			for _, rframe := range release {
				if _, werr := fw.Write(rframe); werr != nil {
					return nil, werr
				}
			}
		case fsutiltypes.Packet_PACKET_FIN, fsutiltypes.Packet_PACKET_ERR:
			if _, werr := fw.Write(frame); werr != nil {
				return nil, werr
			}
		default:
			return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "unexpected FileSync packet type for this stream direction"), nil
		}
	}
}

// handleStat validates one PACKET_STAT entry: a nil Stat is fsutil's
// end-of-listing terminator (send.go's sender.walk sends exactly one,
// unconditionally, after every real entry) and carries no path to check or
// index to assign. A non-nil Stat is counted against maxFiles and has its
// Path/Linkname checked via validateFsutilPath (see pathsafety.go), then is
// assigned the next sequential index — matching fsutil's own 0-based,
// walk-order ID assignment (send.go's sender.walk increments its own
// counter once per entry in exactly this order) — that later PACKET_DATA
// packets will reference via their own ID field.
func (s *fileSyncRespRelay) handleStat(pkt *fsutiltypes.Packet) *mediationDenial {
	stat := pkt.GetStat()
	if stat == nil {
		return nil
	}

	s.fileCount++
	if s.maxFiles > 0 && s.fileCount > s.maxFiles {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "FileSync stream exceeds sockguard's configured file-count limit")
	}
	if d := validateFsutilPath(stat.GetPath(), s.maxPathLength); d != nil {
		return d
	}
	if stat.GetLinkname() != "" {
		if d := validateFsutilPath(stat.GetLinkname(), s.maxPathLength); d != nil {
			return d
		}
	}

	s.fileBytes[s.nextStatIndex] = 0
	s.nextStatIndex++
	return nil
}

// handleData validates and, in holdForInspection mode, buffers one
// PACKET_DATA chunk. It returns a non-nil denial to end the stream, or a
// (possibly empty) list of original frames now safe to forward: in
// non-holding mode this is always exactly the frame just validated; in
// holding mode it is empty until the file's own EOF chunk (an empty Data
// payload) arrives, at which point — if dockerfileinspect finds nothing
// disqualifying in the reassembled content — it is every frame held for
// that file's ID, in original arrival order, including this EOF frame.
// Unlike relay's readGRPCFrame/proto.Unmarshal calls, nothing in this
// function can itself fail (no I/O, no decode) — its only failure mode is
// the denials in its own return value — so, unlike relay's other
// dispatch arms, there is no separate error to propagate here.
func (s *fileSyncRespRelay) handleData(pkt *fsutiltypes.Packet, frame []byte) (denial *mediationDenial, release [][]byte) {
	id := pkt.GetID()
	n := int64(len(pkt.GetData()))

	if uint64(id) >= uint64(s.nextStatIndex) {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "FileSync data references an unknown file"), nil
	}

	if s.doneFiles[id] {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "FileSync data follows this file's end-of-file packet"), nil
	}

	s.fileBytes[id] += n
	s.totalBytes += n
	if s.maxFileBytes > 0 && s.fileBytes[id] > s.maxFileBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "a FileSync file exceeds sockguard's configured single-file byte limit"), nil
	}
	if s.maxTotalBytes > 0 && s.totalBytes > s.maxTotalBytes {
		return deny(grpcCodeResourceExhausted, "buildkit_file_limit_exceeded", "FileSync stream exceeds sockguard's configured total byte limit"), nil
	}

	isEOF := n == 0

	if !s.holdForInspection {
		if isEOF {
			s.doneFiles[id] = true
		}
		return nil, [][]byte{frame}
	}

	entry, ok := s.held[id]
	if !ok {
		entry = &heldFileSyncEntry{}
		s.held[id] = entry
	}
	entry.content = append(entry.content, pkt.GetData()...)
	entry.frames = append(entry.frames, frame)

	if !isEOF {

		return nil, nil
	}

	s.doneFiles[id] = true
	delete(s.held, id)
	if frontend := dockerfileinspect.SyntaxFrontend(entry.content); frontend != "" {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "BuildKit syntax frontend directives cannot be inspected while RUN instructions are restricted"), nil
	}
	if dockerfileinspect.ContainsRunInstruction(entry.content) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "RUN instructions are not allowed"), nil
	}
	return nil, entry.frames
}

// grpcMessageHeaderLen is the 1-byte compression flag + 4-byte big-endian
// length prefix every gRPC length-prefixed message frame carries, per the
// gRPC-over-HTTP/2 wire format (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#length-prefixed-message-framing).
const grpcMessageHeaderLen = 5

// errUnaryFrameProtocolError is returned by readUnaryGRPCMessage for any
// framing violation that is NOT a size-cap trip: a nonzero/compressed flag,
// a truncated frame, or trailing bytes after the one message a unary RPC's
// request stream is allowed to carry. bridge.go's forwardControlMediated
// maps this to the buildkit_protocol_error audit reason and a per-stream
// gRPC status — never a whole-tunnel teardown, per the #185 Phase 3
// constraint that a single stream's decode failure stays stream-local.
var errUnaryFrameProtocolError = errors.New("buildkitproxy: malformed or multi-message gRPC unary request framing")

// readUnaryGRPCMessage reads exactly one gRPC length-prefixed message frame
// from r — the shape every unary-request RPC this package mediates
// (Control/Solve, Control/Status) presents on its request stream — and
// confirms no further bytes follow. It returns the COMPLETE original frame
// (5-byte header + payload, byte-for-byte as read) for forwarding to the
// daemon untouched on allow — per the #185 Phase 3 constraint "on allow
// forward the ORIGINAL bytes, never a re-encoded message" — and the payload
// alone, separately, for proto.Unmarshal to decode for the policy decision.
//
// A nonzero compression flag is rejected outright: sockguard's mediator
// never negotiates message-level gRPC compression, so a compressed frame is
// either a client sockguard's mediation was never designed against, or an
// attempt to hide message content from the very inspection this function
// exists to perform — either way, fail closed rather than decompress
// untrusted input.
//
// maxLen bounds the payload length the frame's own header declares — a
// frame declaring more than maxLen fails closed with errMessageTooLarge
// BEFORE any attempt to read that many bytes, so an attacker-controlled
// length prefix can never itself force a large allocation. maxLen <= 0
// disables the cap.
func readUnaryGRPCMessage(r io.Reader, maxLen int64) (frame, payload []byte, err error) {
	var header [grpcMessageHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message header: %w", errUnaryFrameProtocolError, err)
	}
	if header[0] != 0 {
		return nil, nil, fmt.Errorf("%w: compressed message flag set", errUnaryFrameProtocolError)
	}

	length := int64(binary.BigEndian.Uint32(header[1:5]))
	if maxLen > 0 && length > maxLen {
		return nil, nil, errMessageTooLarge
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message payload: %w", errUnaryFrameProtocolError, err)
	}

	// A unary RPC's request stream carries exactly one message; anything
	// beyond it (a second frame, or stray bytes) is a protocol violation to
	// fail closed on, not a valid continuation sockguard should keep reading.
	var extra [1]byte
	switch n, err := io.ReadFull(r, extra[:]); {
	case n > 0:
		return nil, nil, fmt.Errorf("%w: trailing bytes after the single expected message", errUnaryFrameProtocolError)
	case !errors.Is(err, io.EOF):
		return nil, nil, fmt.Errorf("%w: confirming end of stream: %w", errUnaryFrameProtocolError, err)
	}

	frame = make([]byte, grpcMessageHeaderLen+len(payload))
	copy(frame, header[:])
	copy(frame[grpcMessageHeaderLen:], payload)
	return frame, payload, nil
}

// ParseGRPCPath splits an HTTP/2 request path shaped like
// "/{proto.package.Service}/{Method}" (the standard gRPC path convention,
// and the only path shape any of the h2c-terminated streams this package
// bridges ever presents — see bridge.go's per-stream http.Handler) into its
// service and method components. ok is false for anything that doesn't fit
// that shape, including a bare "/", a path with no method segment, or one
// with extra segments — callers must treat a false ok as Deny, not as "try
// again with a different parse", since a fully-qualified gRPC method name
// with a "/" of its own is not a thing the protocol allows.
func ParseGRPCPath(path string) (service, method string, ok bool) {
	trimmed, hadSlash := strings.CutPrefix(path, "/")
	if !hadSlash || trimmed == "" {
		return "", "", false
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	service, method = trimmed[:idx], trimmed[idx+1:]
	if strings.Contains(service, "/") || strings.Contains(method, "/") {
		return "", "", false
	}
	return service, method, true
}

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

// Limits bounds resource use on a single mediated BuildKit tunnel (one
// hijacked /session or /grpc connection). Terminating a client-driven HTTP/2
// connection reopens the Rapid Reset class (CVE-2023-44487): a malicious
// client can open many streams and reset them before sockguard finishes
// classifying/forwarding, forcing repeated work per stream. golang.org/x/net
// v0.57.0 (this package's pinned version) already carries upstream's
// connection-level Rapid Reset mitigation inside http2.Server itself; Limits
// adds sockguard-specific, defense-in-depth caps on top: a hard concurrent
// stream ceiling and a budget on how many denied/errored streams a single
// connection may produce before sockguard tears the whole tunnel down,
// because a legitimate BuildKit client essentially never calls a Deny'd
// method at all — a burst of denials is itself an abuse signal, not just
// each individual denial being fine in isolation.
//
// There are no operator-facing config knobs for these values (issue #185
// Phase 2 sign-off: "no new knobs" — the request_body.buildkit block gates
// mediation as a whole, not its internal DoS budget), so the concrete
// numbers below are sockguard's own judgment call, not synthesized from the
// #185 design docs, which describe the categories of cap needed
// (MaxConcurrentStreams, stream-reset rate limiting, byte caps, idle
// timeouts) without prescribing values. They are deliberately generous
// relative to a real `docker buildx build` session (which opens at most a
// handful of concurrent streams — Solve, Status, FileSync, Auth, occasional
// Secrets/SSH) while still bounding the worst case an abusive client could
// impose.
type Limits struct {
	// MaxConcurrentStreams caps concurrent HTTP/2 streams sockguard will
	// accept on the server leg of a bridged tunnel (see bridge.go). Passed
	// straight through to http2.Server.MaxConcurrentStreams.
	MaxConcurrentStreams uint32

	// MaxMessageBytes caps the cumulative bytes sockguard will relay for a
	// single stream's request body and, separately, its response body.
	// Phase 2 forwards original bytes without decoding protobuf framing (see
	// registry.go's package doc), so this is a coarse per-stream cap, not a
	// per-length-prefixed-message one — later phases that actually decode
	// Mediate methods can tighten this per field.
	MaxMessageBytes int64

	// DeniedStreamBudget is the number of Deny-classified or
	// protocol-invalid streams sockguard tolerates on one tunnel connection
	// within DeniedStreamWindow before closing the whole connection. Zero
	// disables the budget (unlimited denials tolerated) — DefaultLimits
	// never does this.
	DeniedStreamBudget int

	// DeniedStreamWindow is the rolling window DeniedStreamBudget is counted
	// over.
	DeniedStreamWindow time.Duration

	// IdleTimeout closes a bridged tunnel connection that has carried no
	// stream activity for this long. Matches the value sockguard's existing
	// attach/exec hijack path uses (internal/proxy's hijackInactivityTimeout)
	// so operators see one consistent inactivity convention across every
	// long-lived connection sockguard terminates.
	IdleTimeout time.Duration

	// ReadIdleTimeout, when non-zero, makes http2.Server proactively PING an
	// otherwise-quiet connection to detect a half-dead peer faster than
	// IdleTimeout alone would (IdleTimeout only fires on total silence;
	// ReadIdleTimeout catches a peer that ACKs TCP but stopped speaking
	// HTTP/2).
	ReadIdleTimeout time.Duration

	// MaxRefsPerSession bounds how many distinct Control/Solve refs a single
	// mediated session (see session.go's SessionRegistry.PutRef) may admit
	// before sockguard starts refusing new Solve calls with
	// RESOURCE_EXHAUSTED — the #185 Phase 3 sign-off's "bound the per-session
	// ref count (DoS)" requirement: without a cap, a client could keep
	// calling Solve with a fresh Ref forever, growing the ref-ownership index
	// without limit for the lifetime of the connection. A real `docker
	// buildx build` session admits one Solve (occasionally a handful, for
	// multi-target bake); this is deliberately generous relative to that
	// while still bounding the worst case. Zero or negative disables the
	// bound — DefaultLimits never does this.
	MaxRefsPerSession int

	// MaxCredentialCallsPerSession bounds how many EndpointSession
	// credential-mediated calls — moby.filesync.v1.Auth's four RPCs,
	// Secrets/GetSecret, and SSH's CheckAgent/ForwardAgent — a single
	// mediated session may make before sockguard starts refusing further
	// ones with RESOURCE_EXHAUSTED — the #185 Phase 4 sign-off's per-session
	// credential-request quota. Unlike MaxRefsPerSession, an admitted call
	// here doesn't grow any registry-wide state; the risk it bounds is
	// different: every one of these RPCs unlocks live credential material (a
	// registry token, a secret payload, SSH agent access), and a client that
	// keeps calling an ADMITTED method never trips the denied-stream abuse
	// budget (recordDeniedAndMaybeClose only counts denials/errors), so
	// without this cap that traffic would otherwise be unbounded. A real
	// `docker buildx build` session makes at most a handful of these per
	// unique registry/secret/SSH mount; this is deliberately generous
	// relative to that while still bounding the worst case. Zero or negative
	// disables the bound — DefaultLimits never does this.
	MaxCredentialCallsPerSession int

	// MaxFileSyncFiles caps the number of PACKET_STAT entries (files/dirs)
	// a single FileSync/DiffCopy stream may declare before sockguard denies
	// the stream with buildkit_file_limit_exceeded.
	MaxFileSyncFiles int
	// MaxFileSyncTotalBytes caps the cumulative PACKET_DATA bytes relayed
	// across an entire FileSync/DiffCopy stream (every file combined).
	MaxFileSyncTotalBytes int64
	// MaxFileSyncPathLength caps the byte length of any single Stat.Path or
	// Stat.Linkname value — independent of MaxFileSyncFiles/
	// MaxFileSyncTotalBytes, since a single pathologically long path is a
	// distinct resource-exhaustion/parsing-cost concern from file count or
	// data volume.
	MaxFileSyncPathLength int
	// MaxFileSyncFileBytes caps the PACKET_DATA bytes belonging to any ONE
	// file within a FileSync/DiffCopy stream — including the Dockerfile
	// hold-and-inspect buffer (see filesync.go), which must itself stay
	// bounded rather than accumulate an arbitrarily large in-memory buffer
	// before sockguard ever gets to render a policy decision on it.
	MaxFileSyncFileBytes int64
	// MaxFileSendBytes caps the cumulative bytes relayed for a single
	// FileSend/DiffCopy stream (a build's exported output, daemon→client).
	// FileSend content is never inspected — only capped.
	MaxFileSendBytes int64
	// MaxUploadBytes caps the cumulative bytes relayed for a single
	// Upload/Pull stream (a client-streamed stdin/remote build context).
	// Upload content is never inspected — only capped.
	MaxUploadBytes int64
	// MaxUploadKeysPerSession bounds how many distinct one-use Upload
	// tokens a single SessionKey (client identity + profile) may have
	// admitted-but-not-yet-consumed at once (see upload.go's
	// admitSolveUploadKeys) — the same per-session DoS-budget shape as
	// MaxRefsPerSession, and deliberately NOT a request_body.buildkit knob
	// for the same reason MaxRefsPerSession isn't: it bounds sockguard's
	// own bookkeeping cost, not a build capability an operator would ever
	// want to widen. Zero or negative disables the bound.
	MaxUploadKeysPerSession int
}

// DefaultLimits returns sockguard's Phase 2 DoS budget. See Limits' doc
// comment for why these are hardcoded rather than configurable.
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentStreams: 100,
		MaxMessageBytes:      64 << 20,
		DeniedStreamBudget:   20,
		DeniedStreamWindow:   10 * time.Second,
		IdleTimeout:          10 * time.Minute,
		ReadIdleTimeout:      30 * time.Second,
		MaxRefsPerSession:    256,

		MaxCredentialCallsPerSession: 512,

		MaxFileSyncFiles:        100_000,
		MaxFileSyncTotalBytes:   512 << 20,
		MaxFileSyncPathLength:   4096,
		MaxFileSyncFileBytes:    256 << 20,
		MaxFileSendBytes:        512 << 20,
		MaxUploadBytes:          512 << 20,
		MaxUploadKeysPerSession: 64,
	}
}

// streamAbuseGuard tracks Deny/error events on one tunnel connection and
// reports when DeniedStreamBudget has been exceeded within
// DeniedStreamWindow, so the caller can close the whole connection rather
// than keep paying per-stream classification cost for an abusive client.
type streamAbuseGuard struct {
	mu     sync.Mutex
	budget int
	window time.Duration
	events []time.Time
	nowFn  func() time.Time
}

func newStreamAbuseGuard(limits Limits) *streamAbuseGuard {
	return &streamAbuseGuard{
		budget: limits.DeniedStreamBudget,
		window: limits.DeniedStreamWindow,
		nowFn:  time.Now,
	}
}

// recordDenied records one denied/errored stream and reports whether the
// connection-level budget has now been exceeded. A zero or negative budget
// disables the guard (always returns false).
func (g *streamAbuseGuard) recordDenied() bool {
	if g.budget <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	cutoff := now.Add(-g.window)
	kept := g.events[:0]
	for _, t := range g.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	g.events = kept

	return len(g.events) > g.budget
}

// Dialer is the minimal upstream-dialing seam the mediator needs to reach
// the Docker daemon for the daemon-side leg of a bridged tunnel.
// *upstream.Resolver satisfies this interface structurally; this package
// deliberately does not import internal/upstream (or internal/clientacl, for
// the caller-supplied SessionKey — see its doc comment) to stay the
// dependency-light leaf package registry.go's doc comment describes.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Mediator terminates and bridges the two opaque BuildKit HTTP tunnels
// (POST /session, POST /grpc) once request_body.buildkit is configured for
// the request's active policy. One Mediator is shared across every request
// on a listener; it holds no per-request state beyond what SessionRegistry
// tracks.
type Mediator struct {
	Dialer   Dialer
	Logger   *slog.Logger
	Limits   Limits
	Registry *SessionRegistry
}

// NewMediator returns a Mediator with Phase 2's default DoS budget (see
// DefaultLimits) and a fresh, empty SessionRegistry.
func NewMediator(dialer Dialer, logger *slog.Logger) *Mediator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Mediator{
		Dialer:   dialer,
		Logger:   logger,
		Limits:   DefaultLimits(),
		Registry: NewSessionRegistry(),
	}
}

// ServeGRPC mediates a POST /grpc upgrade: the Docker client is the gRPC
// client, buildkitd is the server. key identifies the session for the
// registry (see SessionKey's doc comment) and policy is the already-resolved
// effective policy for this request (global or client-profile) — the caller
// resolves both before calling, e.g. from internal/clientacl's client-
// profile selection plus a remote-address or TLS-identity signal.
func (m *Mediator) ServeGRPC(w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	m.serve(EndpointGRPC, w, r, policy, key)
}

// ServeSession mediates a POST /session upgrade. Per the #185 synthesis,
// roles are reversed from ServeGRPC: buildkitd becomes the gRPC client,
// dialing calls back over the SAME hijacked connection into the Docker
// client's session server (Auth, Secrets, SSH, FileSync, FileSend, Upload).
func (m *Mediator) ServeSession(w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	m.serve(EndpointSession, w, r, policy, key)
}

func (m *Mediator) serve(endpoint Endpoint, w http.ResponseWriter, r *http.Request, policy Policy, key SessionKey) {
	logPath := r.URL.Path

	if err := ValidateUpgradeRequest(r); err != nil {
		m.Logger.Warn("buildkit: rejecting malformed h2c upgrade request",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: "invalid BuildKit tunnel upgrade request"})
		return
	}

	outHeader := r.Header.Clone()
	if endpoint == EndpointSession {
		rewriteSessionAdvertisement(outHeader, policy)
	}

	dialCtx, cancel := context.WithTimeout(r.Context(), h2cDialTimeout)
	defer cancel()
	daemonConn, daemonResp, err := dialDaemonH2C(dialCtx, m.Dialer, r.URL.Path, outHeader)
	if err != nil {
		m.Logger.Error("buildkit: daemon h2c upgrade failed",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "upstream BuildKit daemon unreachable or refused h2c upgrade"})
		return
	}
	_ = daemonResp.Body.Close()

	clientConn, err := hijackClientH2C(w, daemonResp)
	if err != nil {
		m.Logger.Error("buildkit: client hijack failed",
			"error", logging.SafeString(err.Error()), "path", logging.SafeString(logPath), "endpoint", endpoint.String())
		closeConnLogged(m.Logger, daemonConn, "daemon connection", logPath)
		return
	}

	session := m.Registry.Open(key, endpoint, r.Header.Get(sessionUUIDHeader))
	defer m.Registry.Close(session.ID)

	legs := bridgeLegs{endpoint: endpoint}
	switch endpoint {
	case EndpointGRPC:
		legs.serverConn, legs.clientConn = clientConn, daemonConn
	case EndpointSession:
		legs.serverConn, legs.clientConn = daemonConn, clientConn
	}

	m.Logger.Info("buildkit: tunnel opened",
		"endpoint", endpoint.String(), "session_id", session.ID, "profile", logging.SafeString(key.Profile), "path", logging.SafeString(logPath))

	if err := runBridge(r.Context(), legs, session, policy, effectiveLimits(m.Limits, policy), m.Logger, m.Registry); err != nil {
		m.Logger.Warn("buildkit: tunnel terminated",
			"error", logging.SafeString(err.Error()), "endpoint", endpoint.String(), "session_id", session.ID)
		return
	}
	m.Logger.Info("buildkit: tunnel closed", "endpoint", endpoint.String(), "session_id", session.ID)
}

// effectiveLimits merges Phase 5 (issue #185)'s per-profile FileSync/
// FileSend/Upload cap overrides (policy.Session.{FileSync,FileSend,Upload})
// on top of base (m.Limits, one value shared by every profile — see
// Mediator's doc comment) for the single tunnel about to be bridged. A
// configured, positive per-profile value replaces the corresponding base
// field; zero (the default when a profile's request_body.buildkit.session
// cap block sets nothing) leaves base's hardcoded secure default in place —
// see limits.go's Phase 5 field doc comments and FileSyncPolicy's doc
// comment for this zero-means-default convention. Every other Limits field
// (the Phase 2 DoS budget) is untouched: those have no per-profile knob by
// design (Limits' own doc comment) and stay exactly base's value.
func effectiveLimits(base Limits, policy Policy) Limits {
	out := base
	if v := policy.Session.FileSync.MaxFiles; v > 0 {
		out.MaxFileSyncFiles = v
	}
	if v := policy.Session.FileSync.MaxTotalBytes; v > 0 {
		out.MaxFileSyncTotalBytes = v
	}
	if v := policy.Session.FileSync.MaxPathLength; v > 0 {
		out.MaxFileSyncPathLength = v
	}
	if v := policy.Session.FileSync.MaxFileBytes; v > 0 {
		out.MaxFileSyncFileBytes = v
	}
	if v := policy.Session.FileSend.MaxBytes; v > 0 {
		out.MaxFileSendBytes = v
	}
	if v := policy.Session.Upload.MaxBytes; v > 0 {
		out.MaxUploadBytes = v
	}
	return out
}

func closeConnLogged(logger *slog.Logger, conn net.Conn, label, path string) {
	if err := conn.Close(); err != nil {
		logger.Debug("buildkit: failed to close "+label, "error", logging.SafeString(err.Error()), "path", logging.SafeString(path))
	}
}

// validateFsutilPath rejects a fsutil Stat.Path or Stat.Linkname value that
// could escape the directory sockguard is mediating a sync for, or that is
// otherwise structurally unsafe to hand the daemon. All paths fsutil
// transfers over the wire are normalized to unix-style ('/'-separated,
// relative) paths — see tonistiigi/fsutil's own receive-side path handling
// — so this checks exactly that shape:
//
//   - empty: rejected (buildkit_path_rejected) — a non-terminator Stat entry
//     naming no path at all is not a legitimate protocol message.
//   - longer than maxLen (when maxLen > 0): rejected — a single
//     pathologically long path is a resource-exhaustion/parsing-cost
//     concern independent of file count or data volume (Limits.
//     MaxFileSyncPathLength).
//   - contains a NUL byte: rejected outright — defense in depth against
//     any downstream C-string-based path handling sockguard doesn't control.
//   - absolute (a leading '/'): rejected — the receiving side of a
//     FileSync/DiffCopy stream (the daemon) resolves entries relative to
//     its own destination directory; an absolute path is meaningless as a
//     relative entry and, for any implementation that ever treated it
//     otherwise, is exactly the trick this check exists to close.
//   - contains a ".." path segment: rejected — the same directory-escape
//     concern, whether the ".." appears at the front, middle, or end of the
//     path.
//
// Applied identically to both Stat.Path (every entry) and Stat.Linkname
// (only symlink entries, which carry a non-empty Linkname) — see filesync.go
// — per the #185 synthesis's "reject symlink trickery to the extent the
// protocol exposes it": a symlink whose OWN path is safe but whose TARGET
// escapes the synced directory is the same class of attack via one more
// level of indirection, so the same rule applies to both fields. This is
// deliberately stricter than what a real filesystem would consider invalid
// (an absolute symlink target is unremarkable on disk) — sockguard's job
// here is constraining what a BuildKit-mediated sync can smuggle past it,
// not reproducing every legitimate filesystem semantic.
func validateFsutilPath(path string, maxLen int) *mediationDenial {
	if path == "" {
		return deny(grpcCodeInvalidArgument, "buildkit_path_rejected", "FileSync entry path must not be empty")
	}
	if maxLen > 0 && len(path) > maxLen {
		return deny(grpcCodeResourceExhausted, "buildkit_path_rejected", "FileSync entry path exceeds sockguard's configured length limit")
	}
	if strings.ContainsRune(path, 0) {
		return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "FileSync entry path is malformed")
	}
	if strings.HasPrefix(path, "/") {
		return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "absolute FileSync entry paths are not permitted")
	}
	for part := range strings.SplitSeq(path, "/") {
		if part == ".." {
			return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "FileSync entry path traversal is not permitted")
		}
	}
	return nil
}

// Policy is the runtime-facing translation of request_body.buildkit config
// (see internal/config's BuildkitRequestBodyConfig.ToPolicy). This package
// never imports internal/config — translation flows one direction only,
// mirroring how internal/config translates into internal/filter's options
// types without filter importing config back.
//
// Phase 1 (issue #185) ships no mediator to consult this Policy at request
// time — every field here describes what LATER phases will enforce once
// the h2c-terminating transport exists. Right now the only thing anything
// reads off a Policy is Configured, via cmd/rules.go's startup admission
// check and validateBuildkitAckMutualExclusion, and filter.BuildkitOptions's
// unconditional deny-only gate.
type Policy struct {
	Control ControlPolicy
	Session SessionPolicy
}

// Configured reports whether p was set to anything other than every field
// left at its secure (false/empty) default. Because every Buildkit sub-field
// defaults to false or an empty slice (there is no default-true field the
// way e.g. network.endpoint_config.allow_aliases has), a Policy with every
// field at its zero value is behaviorally indistinguishable from "the block
// was never written" — both deny everything — so this is a plain field
// predicate without needing #186's Viper-provenance-tracking pattern (which
// exists specifically to handle a default-true field zero value could not
// represent).
//
// This is deliberately NOT reflect.DeepEqual(p, Policy{}): an explicitly
// written but empty allowlist — e.g. allowed_registries: [] — parses to a
// non-nil empty slice, which DeepEqual would treat as different from the
// zero value's nil slice even though both are empty and both deny
// everything. Each field is checked explicitly instead, by length rather
// than nilness, so a non-nil empty slice reads the same as "not configured"
// as a nil one does.
//
// SolvePolicy.AllowHostNetwork and AllowRemoteContext are deliberately NOT
// checked here even though Phase 3 populates them: those two fields are
// reused verbatim from the unrelated request_body.build block (see
// SolvePolicy's doc comment), so an operator who enables allow_host_network
// for classic POST /build alone — with no request_body.buildkit block
// written at all — must not have that alone flip Configured() to true. Doing
// so would incorrectly trip validateBuildkitAckMutualExclusion for an
// operator who never touched BuildKit mediation.
func (p Policy) Configured() bool {
	return p.Control.AllowInfo ||
		p.Control.AllowListWorkers ||
		p.Control.AllowStatus ||
		p.Control.Solve.Allow ||
		len(p.Control.Solve.AllowedCacheImportTypes) > 0 ||
		len(p.Control.Solve.AllowedCacheExportTypes) > 0 ||
		len(p.Control.Solve.AllowedCacheRegistries) > 0 ||
		len(p.Control.Solve.AllowedExporters) > 0 ||
		len(p.Control.Solve.AllowedExporterRegistries) > 0 ||
		p.Session.Health ||
		p.Session.Auth.Allow ||
		len(p.Session.Auth.AllowedRegistries) > 0 ||
		len(p.Session.Auth.AllowedRealms) > 0 ||
		len(p.Session.Auth.AllowedScopes) > 0 ||
		p.Session.Secrets.Allow ||
		len(p.Session.Secrets.AllowedIDs) > 0 ||
		p.Session.SSH.Allow ||
		len(p.Session.SSH.AllowedIDs) > 0 ||
		p.Session.FileSync.Allow ||
		p.Session.FileSend.Allow ||
		p.Session.Upload.Allow
}

// Allowed reports whether p's per-field configuration admits a call to
// service/rpcMethod on endpoint. Callers (Phase 2's bridge.go) consult this
// ONLY after Classify has already returned Mediate or Passthrough for the
// same triple — Allowed never overrides a Classify Deny, it narrows further.
//
// This is a pure boolean gate over each field's own Allow-shaped switch, not
// per-message content inspection: the allowlist fields (AllowedRegistries,
// AllowedIDs, etc.) aren't consulted here and stay unenforced until later
// phases decode messages. But the plain Allow/AllowInfo/AllowStatus/
// AllowListWorkers/Health booleans ARE a real, immediate security boundary,
// and Phase 2's mediator must consult them: Classify's registry says a
// method's CATEGORY is eligible for mediation in principle (a Phase 1
// classification fixed at compile time, identical for every operator);
// Allowed says whether THIS operator's policy actually turned that category
// on. Forwarding every Mediate/Passthrough method regardless of Allowed
// would silently defeat every per-field switch Phase 1 built — e.g. an
// operator who only sets control.solve.allow: true would otherwise also get
// Secrets/SSH/FileSync forwarded for free, with zero opt-in. The #185
// synthesis's own audit vocabulary distinguishes exactly this case
// (buildkit_method_denied for a Classify Deny vs buildkit_policy_denied for
// an Allowed() false) — a reason code nothing before Phase 2 could ever
// produce, since Phase 1 had no live mediator, which is why this gate lands
// now rather than waiting for Phase 3's per-message work.
//
// Each service's inner switch enumerates only that service's own registered
// RPC method names, mirroring registry.go's classification map exactly — an
// unrecognized rpcMethod on an otherwise-enabled service (e.g. a typo, or a
// probe for a method the daemon never actually exposes) falls through to
// this function's own `return false` rather than the service's Allow switch,
// so Allowed is default-deny standalone and doesn't depend on a caller
// having already run the triple through Classify.
func (p Policy) Allowed(endpoint Endpoint, service, rpcMethod string) bool {
	switch endpoint {
	case EndpointGRPC:
		switch service {
		case "moby.buildkit.v1.Control":
			switch rpcMethod {
			case "Solve":
				return p.Control.Solve.Allow
			case "Status":
				return p.Control.AllowStatus
			case "Info":
				return p.Control.AllowInfo
			case "ListWorkers":
				return p.Control.AllowListWorkers
			}
		case "grpc.health.v1.Health":

			switch rpcMethod {
			case "Check", "Watch":
				return p.Session.Health
			}
		}
	case EndpointSession:
		switch service {
		case "moby.filesync.v1.Auth":
			switch rpcMethod {
			case "Credentials", "FetchToken", "GetTokenAuthority", "VerifyTokenAuthority":
				return p.Session.Auth.Allow
			}
		case "moby.buildkit.secrets.v1.Secrets":
			if rpcMethod == "GetSecret" {
				return p.Session.Secrets.Allow
			}
		case "moby.sshforward.v1.SSH":
			switch rpcMethod {
			case "CheckAgent", "ForwardAgent":
				return p.Session.SSH.Allow
			}
		case "moby.filesync.v1.FileSync":

			return rpcMethod == "DiffCopy" && p.Session.FileSync.Allow
		case "moby.filesync.v1.FileSend":
			if rpcMethod == "DiffCopy" {
				return p.Session.FileSend.Allow
			}
		case "moby.upload.v1.Upload":
			if rpcMethod == "Pull" {
				return p.Session.Upload.Allow
			}
		}
	}
	return false
}

// ControlPolicy gates moby.buildkit.v1.Control, reached over POST /grpc.
type ControlPolicy struct {
	AllowInfo        bool
	AllowListWorkers bool
	AllowStatus      bool
	Solve            SolvePolicy
}

// SolvePolicy gates moby.buildkit.v1.Control/Solve. See
// config.BuildkitSolveRequestBodyConfig's doc comment for why this has no
// allow_run_instructions/allow_host_network/allow_remote_context fields of
// its own — AllowHostNetwork/AllowRemoteContext below are threaded through
// from the sibling request_body.build block by
// config.BuildkitRequestBodyConfig.ToPolicy, not duplicated config knobs.
//
// Phase 3 (issue #185) is the first phase that actually reads these fields:
// bridge.go's forwardControlMediated decodes a Solve request and checks its
// Entitlements/Frontend/FrontendAttrs/Cache/Exporters against them before
// forwarding. AllowRunInstructions has no Phase 3 equivalent: unlike classic
// POST /build (build.go), a BuildKit Solve using the dockerfile.v0 frontend
// never puts the Dockerfile's RUN instructions in the SolveRequest message
// itself — the daemon's embedded frontend resolves those from the build
// context, which sockguard cannot see until the file-sync mediation Phase 5
// ships (the #185 synthesis's "temporal enforcement on file-sync": Solve is
// forwarded before the daemon requests the Dockerfile). A raw, frontend-less
// Solve (Frontend == "") embeds its instructions as opaque serialized LLB Op
// bytes (solver/pb/ops.proto's Definition.Def is `repeated bytes`, not
// nested protobuf messages) that Phase 3's protobuf-reflection-based
// unknown-field walk (see protowalk.go) cannot decode either — a full LLB
// op-graph content policy is out of Phase 3's scope.
type SolvePolicy struct {
	Allow              bool
	AllowHostNetwork   bool
	AllowRemoteContext bool
	// AllowRunInstructions is reused verbatim from the sibling
	// request_body.build block, exactly like AllowHostNetwork/
	// AllowRemoteContext above — see this struct's doc comment for why
	// Solve itself has no phase 3 use for it. Phase 5 (issue #185) is the
	// first phase that reads it: filesync.go's Dockerfile hold-and-inspect
	// path applies the identical allow_run_instructions gate the classic
	// POST /build path does (internal/filter/build.go's buildPolicy.inspect)
	// to the Dockerfile bytes it holds from a "dockerfile"-named
	// FileSync/DiffCopy stream, via the shared internal/dockerfileinspect
	// parser — before ever releasing them to the daemon.
	AllowRunInstructions bool

	// AllowedCacheImportTypes/AllowedCacheExportTypes gate SolveRequest.
	// Cache.Imports/.Exports' CacheOptionsEntry.Type (e.g. "registry",
	// "local", "gha", "s3", "inline") — empty = deny, the standard
	// RequestBodyConfig convention.
	AllowedCacheImportTypes []string
	AllowedCacheExportTypes []string
	// AllowedCacheRegistries gates the registry host of a "registry"-typed
	// cache import/export's Attrs["ref"] image reference — shared between
	// imports and exports since both name the same kind of remote cache
	// manifest location.
	AllowedCacheRegistries []string

	// AllowedExporters gates SolveRequest.Exporters[].Type (e.g. "image",
	// "oci", "docker", "local", "tar") — empty = deny.
	AllowedExporters []string
	// AllowedExporterRegistries gates the registry host an "image"-typed
	// exporter pushes to (Attrs["push"] == "true", Attrs["name"] the target
	// image reference).
	AllowedExporterRegistries []string
}

// SessionPolicy gates the services buildkitd calls back into the client
// for, reached over POST /session.
type SessionPolicy struct {
	Health   bool
	Auth     AuthPolicy
	Secrets  SecretsPolicy
	SSH      SSHPolicy
	FileSync FileSyncPolicy
	FileSend FileSendPolicy
	Upload   UploadPolicy
}

// AuthPolicy gates moby.filesync.v1.Auth's four RPCs.
type AuthPolicy struct {
	Allow             bool
	AllowedRegistries []string
	AllowedRealms     []string
	AllowedScopes     []string
}

// SecretsPolicy gates moby.buildkit.secrets.v1.Secrets/GetSecret.
type SecretsPolicy struct {
	Allow      bool
	AllowedIDs []string
}

// SSHPolicy gates moby.sshforward.v1.SSH's CheckAgent/ForwardAgent RPCs.
type SSHPolicy struct {
	Allow      bool
	AllowedIDs []string
}

// FileSyncPolicy gates moby.filesync.v1.FileSync/DiffCopy. MaxFiles/
// MaxTotalBytes/MaxPathLength/MaxFileBytes are Phase 5 (issue #185)'s
// per-profile cap overrides — zero (the default when
// request_body.buildkit.session.file_sync sets none of them) means "use
// Limits' hardcoded secure default" rather than "unlimited"; see
// mediator.go's effectiveLimits and limits.go's Phase 5 field doc comments
// for the two-layer Policy/Limits split this implies.
type FileSyncPolicy struct {
	Allow         bool
	MaxFiles      int
	MaxTotalBytes int64
	MaxPathLength int
	MaxFileBytes  int64
}

// FileSendPolicy gates moby.filesync.v1.FileSend/DiffCopy. MaxBytes is
// Phase 5's per-profile override of Limits.MaxFileSendBytes — see
// FileSyncPolicy's doc comment for the zero-means-default convention.
type FileSendPolicy struct {
	Allow    bool
	MaxBytes int64
}

// UploadPolicy gates moby.upload.v1.Upload/Pull. MaxBytes is Phase 5's
// per-profile override of Limits.MaxUploadBytes — see FileSyncPolicy's doc
// comment for the zero-means-default convention.
type UploadPolicy struct {
	Allow    bool
	MaxBytes int64
}

// hasUnknownFields reports whether m, or any message reachable from m via a
// populated message- or group-typed field (a plain field, a list element, or
// a map value), carries protobuf unknown-field bytes — wire data present for
// a field number sockguard's vendored, pinned descriptor doesn't recognize.
// A future BuildKit/Buildx release that adds a new SolveRequest field would
// otherwise have that field silently ignored rather than reviewed; per the
// #185 synthesis this is grounds for outright denial
// (buildkit_schema_unsupported) instead.
//
// This walk does NOT reach inside solver/pb's Definition.Def: LLB's
// serialized Op graph is carried as opaque `repeated bytes`, not nested
// protobuf submessages (see solver/pb/ops.proto), so there is nothing for
// protobuf reflection to descend into there — a full LLB op-graph schema
// check would require a second, per-Op proto.Unmarshal pass this function
// does not attempt. See PROVENANCE.md and policy.go's SolvePolicy doc
// comment for that boundary.
func hasUnknownFields(m proto.Message) bool {
	if m == nil {
		return false
	}
	return messageHasUnknownFields(m.ProtoReflect())
}

// messageHasUnknownFields is hasUnknownFields' recursive worker, operating
// directly on protoreflect.Message so it can recurse into map values and
// list elements (which arrive as protoreflect.Message, not proto.Message)
// without a redundant interface round-trip at every level.
func messageHasUnknownFields(m protoreflect.Message) bool {
	if !m.IsValid() {
		return false
	}
	if len(m.GetUnknown()) > 0 {
		return true
	}

	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			valueKind := fd.MapValue().Kind()
			if valueKind != protoreflect.MessageKind && valueKind != protoreflect.GroupKind {
				return true
			}
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				if messageHasUnknownFields(mv.Message()) {
					found = true
					return false
				}
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
				return true
			}
			list := v.List()
			for i := 0; i < list.Len() && !found; i++ {
				if messageHasUnknownFields(list.Get(i).Message()) {
					found = true
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			if messageHasUnknownFields(v.Message()) {
				found = true
			}
		}
		return !found
	})
	return found
}

// Disposition is the policy classification assigned to a fully-qualified
// gRPC method reachable over one of the two opaque BuildKit tunnels.
type Disposition int

const (
	// Deny is both the explicit disposition for methods the #185 synthesis
	// names as hard-denied AND the implicit result Classify returns for any
	// (endpoint, service, method) triple not present in registry at all —
	// sockguard's default-deny identity, extended to the gRPC method level.
	Deny Disposition = iota
	// Mediate methods have their request (and, where applicable, response)
	// messages decoded and checked against policy before anything is
	// forwarded — see the request_body.buildkit config surface.
	Mediate
	// Passthrough methods are relayed without a policy decision on message
	// content, but are still size-capped and — per the #185 synthesis —
	// typed, so a rewritten/filtered response (e.g. Info/ListWorkers
	// advertising only the permitted method set) is possible without a
	// full mediation path.
	Passthrough
)

// String renders d for logs/audit records/test failure messages.
func (d Disposition) String() string {
	switch d {
	case Deny:
		return "deny"
	case Mediate:
		return "mediate"
	case Passthrough:
		return "passthrough"
	default:
		return "unknown"
	}
}

// Endpoint identifies which of sockguard's two opaque BuildKit HTTP tunnels
// (see app/internal/cmd/rules.go's buildkitTunnelEndpoints) a gRPC method is
// reached through. The same fully-qualified service+method may only ever be
// classified under one Endpoint in registry — the two tunnels carry
// disjoint service sets.
type Endpoint int

const (
	// EndpointGRPC is POST /grpc: moby.buildkit.v1.Control (the client is
	// the gRPC client; buildkitd is the server) plus the locally-served
	// gRPC health check.
	EndpointGRPC Endpoint = iota
	// EndpointSession is POST /session: the frontend/session bridge over
	// which buildkitd calls BACK into the client for auth, secrets, SSH
	// agent forwarding, and file sync/send/upload — plus the frontend
	// (LLBBridge), exporter-negotiation, and source-policy-verifier
	// surfaces this phase hard-denies.
	EndpointSession
)

// String renders e for logs/audit records/test failure messages.
func (e Endpoint) String() string {
	switch e {
	case EndpointGRPC:
		return "/grpc"
	case EndpointSession:
		return "/session"
	default:
		return "unknown"
	}
}

// method identifies one fully-qualified gRPC method: the endpoint it is
// reached through, its proto service full name, and its bare RPC name.
type method struct {
	Endpoint Endpoint
	Service  string
	Method   string
}

// registry lists every method the #185 synthesis classifies as Mediate or
// Passthrough. It is deliberately NOT exhaustive over the Deny surface —
// Classify's default for anything absent here already IS Deny, so listing a
// denied method would add a row that changes nothing. DeniedExamples below
// documents (and tests exercise) the specific deny surface the synthesis
// calls out by name, precisely so that "unlisted" isn't just an assertion —
// it is checked against the concrete methods it is supposed to cover.
//
// Grouped and ordered to match the #185 synthesis's own inventory, not
// alphabetically, so a reviewer diffing this table against the issue can
// read it top to bottom.
var registry = map[method]Disposition{

	{EndpointGRPC, "moby.buildkit.v1.Control", "Solve"}:       Mediate,
	{EndpointGRPC, "moby.buildkit.v1.Control", "Status"}:      Mediate,
	{EndpointGRPC, "moby.buildkit.v1.Control", "Info"}:        Passthrough,
	{EndpointGRPC, "moby.buildkit.v1.Control", "ListWorkers"}: Passthrough,

	{EndpointGRPC, "grpc.health.v1.Health", "Check"}: Passthrough,
	{EndpointGRPC, "grpc.health.v1.Health", "Watch"}: Passthrough,

	{EndpointSession, "moby.filesync.v1.Auth", "Credentials"}:          Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "FetchToken"}:           Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "GetTokenAuthority"}:    Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "VerifyTokenAuthority"}: Mediate,

	{EndpointSession, "moby.buildkit.secrets.v1.Secrets", "GetSecret"}: Mediate,

	{EndpointSession, "moby.sshforward.v1.SSH", "CheckAgent"}:   Mediate,
	{EndpointSession, "moby.sshforward.v1.SSH", "ForwardAgent"}: Mediate,

	{EndpointSession, "moby.filesync.v1.FileSync", "DiffCopy"}: Mediate,
	{EndpointSession, "moby.filesync.v1.FileSend", "DiffCopy"}: Mediate,

	{EndpointSession, "moby.upload.v1.Upload", "Pull"}: Mediate,
}

// Classify returns the disposition for the fully-qualified method reached
// through endpoint as proto service full name service (e.g.
// "moby.buildkit.v1.Control") and bare RPC name rpcMethod (e.g. "Solve").
// Anything not explicitly registered as Mediate or Passthrough is Deny —
// including every method under a service never listed at all — matching
// sockguard's default-deny identity (CLAUDE.md: "No match = deny") extended
// to the gRPC method-registry level per the #185 synthesis.
func Classify(endpoint Endpoint, service, rpcMethod string) Disposition {
	d, ok := registry[method{endpoint, service, rpcMethod}]
	if !ok {
		return Deny
	}
	return d
}

// ServiceAdmitted reports whether service has at least one Mediate or
// Passthrough method registered under endpoint. Phase 2's h2c mediator uses
// this to rewrite the client-advertised X-Docker-Expose-Session-Grpc-Method
// header (see upgrade.go's rewriteSessionAdvertisement) down to the
// intersection of "advertised" and "permitted" before forwarding a /session
// upgrade to the daemon, per the #185 synthesis — a service with every
// method classified Deny is stripped from the advertisement entirely rather
// than left for buildkitd to discover is denied one failed call at a time.
func ServiceAdmitted(endpoint Endpoint, service string) bool {
	for m, d := range registry {
		if m.Endpoint == endpoint && m.Service == service && d != Deny {
			return true
		}
	}
	return false
}

// ServiceAdmittedByPolicy reports whether service has at least one method
// registered under endpoint that is BOTH non-Deny per Classify AND allowed by
// p (Policy.Allowed) — the intersection ServiceAdmitted alone can't express,
// since a service can carry a Mediate/Passthrough method the registry admits
// in principle that this operator's policy still leaves off (see
// Policy.Allowed's doc comment on why Classify and Allowed are separate,
// necessary gates). upgrade.go's rewriteSessionAdvertisement uses this
// instead of the policy-blind ServiceAdmitted, so a session advertisement
// rewrite never keeps a service the selected policy actually denies — doing
// so would invite a daemon callback the bridge only rejects after the fact.
func ServiceAdmittedByPolicy(endpoint Endpoint, service string, p Policy) bool {
	for m, d := range registry {
		if m.Endpoint == endpoint && m.Service == service && d != Deny && p.Allowed(endpoint, service, m.Method) {
			return true
		}
	}
	return false
}

// DeniedExamples enumerates fully-qualified methods the #185 synthesis
// calls out BY NAME as belonging to the deny-by-default surface: "LLBBridge/*,
// nested Control/Session, containerd content, OTLP trace, Exporter
// negotiation, PolicyVerifier, Control/{Prune,DiskUsage,
// ListenBuildHistory,UpdateBuildHistory}, FileSync/TarStream". Classify
// already denies every one of these (they are simply absent from registry),
// so this list exists purely so tests and future readers have a concrete,
// reviewable enumeration of what "unlisted" is actually standing in for —
// see registry_test.go's TestClassifyDeniedExamples and
// descriptor_manifest_test.go's cross-check against the real vendored
// descriptors for the services that also appear in registry.
//
// Source proto files for method names not already vendored in
// app/internal/buildkitproto (LLBBridge, Exporter, PolicyVerifier) are
// documented in PROVENANCE.md's "Deliberately NOT vendored" section.
var DeniedExamples = []struct {
	Endpoint Endpoint
	Service  string
	Method   string
}{

	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ResolveImageConfig"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ResolveSourceMeta"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Solve"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ReadFile"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ReadDir"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "StatFile"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Evaluate"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Ping"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Return"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Inputs"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "NewContainer"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ReleaseContainer"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ExecProcess"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ReadFileContainer"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "ReadDirContainer"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "StatFileContainer"},
	{EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "Warn"},

	{EndpointGRPC, "moby.buildkit.v1.Control", "Session"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "Prune"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "DiskUsage"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "ListenBuildHistory"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "UpdateBuildHistory"},

	{EndpointGRPC, "containerd.services.content.v1.Content", "Info"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Update"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "List"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Delete"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Read"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Write"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Status"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "ListStatuses"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Abort"},

	{EndpointGRPC, "opentelemetry.proto.collector.trace.v1.TraceService", "Export"},

	{EndpointSession, "moby.exporter.v1.Exporter", "FindExporters"},
	{EndpointSession, "moby.exporter.v1.Exporter", "FinalizeExport"},

	{EndpointSession, "moby.buildkit.v1.sourcepolicy.policysession.PolicyVerifier", "CheckPolicy"},

	{EndpointSession, "moby.filesync.v1.FileSync", "TarStream"},
}

// SessionKey identifies who a mediated BuildKit tunnel belongs to. Per the
// #185 Phase 2 sign-off ("session/ref registry keyed by client identity +
// profile — never UUID alone"), the registry never trusts the
// client-supplied X-Docker-Expose-Session-Uuid value as its key: that header
// is attacker-controlled and two unrelated clients could present the same
// (or colliding) value. ClientIdentity and Profile are resolved by the
// caller — cmd/serve.go's wiring layer, which owns internal/clientacl and
// must not be imported back into this package (see mediator.go's Dialer doc
// comment for the same layering reason) — from whatever identity signal
// sockguard already trusts elsewhere for that connection (TLS client
// certificate CN, unix peer credentials, or at minimum the remote address),
// paired with the policy profile selected for the request.
type SessionKey struct {
	ClientIdentity string
	Profile        string
}

// RefState is Phase 3+'s per-solve-ref ownership record: which session
// produced a given BuildKit ref, so a later Control/Status or
// FileSend/DiffCopy call naming that ref can be checked against the session
// that actually opened it instead of trusting a caller-supplied ref string
// on its own (the #185 synthesis's "buildkit_ref_not_owned" audit reason,
// Control/Status's "ref must belong to an admitted Solve from the same
// client/profile" requirement). Phase 2 defines the shape and gives Session
// a place to hold it, but nothing populates it yet — no phase-2 code path
// ever calls Session.PutRef.
type RefState struct {
	Ref      string
	OpenedAt time.Time
}

// Session is one mediated tunnel: a single hijacked /session or /grpc
// connection tracked for its lifetime in a SessionRegistry. Profile is
// frozen at Open time and never reassigned — a config hot-reload that
// changes what a profile name means must not retroactively change the
// policy an already-open tunnel is held to (the #185 synthesis: "the
// profile is frozen at tunnel open"). ID is a sockguard-assigned, per-process
// monotonic counter, never derived from client input, used to correlate this
// session's audit log lines without exposing (or trusting) the client's own
// session UUID.
type Session struct {
	ID         uint64
	Key        SessionKey
	Endpoint   Endpoint
	Profile    string
	ClientUUID string
	OpenedAt   time.Time

	mu   sync.Mutex
	Refs map[string]*RefState
}

// PutRef records ref as owned by this session. Phase 3+ calls this when a
// Control/Solve this session issued completes; Phase 2 never calls it in any
// production code path, but the method exists now so the registry's shape
// doesn't change out from under the phase that actually needs it.
func (s *Session) PutRef(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Refs[ref] = &RefState{Ref: ref, OpenedAt: time.Now()}
}

// OwnsRef reports whether ref was previously recorded via PutRef on this
// session.
func (s *Session) OwnsRef(ref string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Refs[ref]
	return ok
}

// tryPutRef atomically checks the per-session cap (maxRefs <= 0 disables it)
// and records ref locally if there's room, reporting whether ref is now
// admitted (ok) and whether this call is what newly admitted it (isNew).
// isNew distinguishes a genuinely new ref from a re-PutRef of one the
// session already holds: SessionRegistry.PutRef must only increment the
// registry-wide refcount once per distinct ref per session, matching
// exactly how Close later decrements it once per entry in s.Refs — an
// unconditional increment on every call would let a client that calls Solve
// twice with the same Ref leak the registry-wide count by one forever, since
// Close only ever removes one contribution per distinct ref regardless of
// how many times PutRef added it locally. SessionRegistry.PutRef calls this
// under s.mu exactly once so the check-then-insert can never race against a
// concurrent PutRef call on the same session from another HTTP/2 stream
// (client-driven concurrency the streamAbuseGuard doc comment already notes
// as a live abuse surface).
func (s *Session) tryPutRef(ref string, maxRefs int) (ok, isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Refs[ref]; exists {
		return true, false
	}
	if maxRefs > 0 && len(s.Refs) >= maxRefs {
		return false, false
	}
	s.Refs[ref] = &RefState{Ref: ref, OpenedAt: time.Now()}
	return true, true
}

// refsSnapshot returns a copy of the ref strings this session currently
// holds, for SessionRegistry.Close to release without holding both s.mu and
// the registry's own mutex at once.
func (s *Session) refsSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.Refs))
	for ref := range s.Refs {
		out = append(out, ref)
	}
	return out
}

// SessionRegistry tracks every currently-open mediated BuildKit tunnel.
// Safe for concurrent use.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	nextID   uint64

	// refOwners is Phase 3's ref-ownership index: which SessionKey (client
	// identity + profile — see SessionKey's doc comment) admitted a given
	// BuildKit ref via PutRef, so a later Control/Status call naming that ref
	// can be checked with OwnsRef against the identity+profile that ran the
	// Solve, NOT against the single connection/Session.ID that happened to
	// carry it. buildx typically opens Solve and Status as two concurrent
	// streams on the very same hijacked connection, so in the common case
	// this coincides with a single Session — but per the #185 Phase 3
	// synthesis ("belongs to an admitted Solve from the same client
	// identity + profile"), ownership is deliberately scoped to the wider
	// key, not the narrower connection, so it survives a client reconnecting
	// mid-build without granting any ownership across DIFFERENT identities
	// or profiles. The map value is a refcount, not a set-membership bool,
	// because more than one live Session sharing the same SessionKey may
	// each PutRef the same ref string (harmless — same trust boundary); Close
	// only removes the contribution the session it's closing actually made.
	refOwners map[SessionKey]map[string]int

	// uploadKeys is Phase 5 (issue #185)'s one-use Upload/Pull token index:
	// which SessionKey admitted a given upload-URL id (see upload.go's
	// admitSolveUploadKeys, called from bridge.go's forwardControlMediated
	// once a Solve naming an "http://buildkit-session/<id>" context/
	// context:<name> FrontendAttrs value is admitted). Scoped to SessionKey
	// rather than a single Session for the identical structural reason
	// refOwners is: the admitting call (Control/Solve, over POST /grpc) and
	// the consuming call (Upload/Pull, over POST /session) are always two
	// DIFFERENT hijacked connections — buildx dials /session and /grpc
	// separately — so they can never share one Session.ID. Unlike
	// refOwners' refcount-per-ref shape, a value here is consumed exactly
	// once (map entry deleted on the first successful ConsumeUploadKey) and
	// is NOT released early by SessionRegistry.Close: an admitted-but-not-
	// yet-consumed token has no session of its own to tie a release to
	// (the admitting /grpc session may legitimately close before the
	// /session tunnel's Pull call ever arrives), so it stays valid until
	// consumed or the process restarts. AdmitUploadKey bounds the SET SIZE
	// per SessionKey via Limits.MaxUploadKeysPerSession to keep this from
	// growing unboundedly for one client identity across many builds.
	uploadKeys map[SessionKey]map[string]struct{}
}

// NewSessionRegistry returns an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[uint64]*Session)}
}

// Open registers a new session for key and returns it. clientUUID is the
// client-supplied X-Docker-Expose-Session-Uuid header value (or empty
// string) — recorded as advisory metadata for logs/correlation only; see
// SessionKey's doc comment for why it is never the registry's trust
// boundary.
func (r *SessionRegistry) Open(key SessionKey, endpoint Endpoint, clientUUID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextID++
	s := &Session{
		ID:         r.nextID,
		Key:        key,
		Endpoint:   endpoint,
		Profile:    key.Profile,
		ClientUUID: clientUUID,
		OpenedAt:   time.Now(),
		Refs:       make(map[string]*RefState),
	}
	r.sessions[s.ID] = s
	return s
}

// Close removes the session with the given ID, releasing every ref it
// admitted via PutRef from the registry-wide ownership index (see
// refOwners's doc comment) — a ref another still-open session sharing the
// same SessionKey also admitted stays owned; only this session's own
// contribution is released. A no-op if id doesn't exist (already closed, or
// never opened).
//
// The whole operation — unregistering from r.sessions, snapshotting the
// session's refs, and decrementing their registry-wide counts — happens
// under ONE r.mu critical section, mirroring PutRef (see its doc comment
// for the two races this serialization closes and for the r.mu → s.mu lock
// ordering refsSnapshot's nested s.mu acquisition follows).
func (r *SessionRegistry) Close(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return
	}
	delete(r.sessions, id)

	refs := s.refsSnapshot()
	if len(refs) == 0 {
		return
	}

	owners := r.refOwners[s.Key]
	for _, ref := range refs {
		if owners[ref] <= 1 {
			delete(owners, ref)
		} else {
			owners[ref]--
		}
	}
	if len(owners) == 0 {
		delete(r.refOwners, s.Key)
	}
}

// Get looks up a session by its sockguard-assigned ID.
func (r *SessionRegistry) Get(id uint64) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// Len reports the number of currently-open sessions.
func (r *SessionRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// PutRef registers ref as owned by session s, both locally (s.Refs, via
// Session.tryPutRef — used above by Close to know what to release) and under
// s.Key in the registry-wide ownership index OwnsRef consults. Returns false
// without recording anything if s already holds maxRefs distinct refs (see
// Limits.MaxRefsPerSession); maxRefs <= 0 disables the bound.
//
// The whole operation — confirming s is still registered in r.sessions,
// admitting the ref locally via tryPutRef, and publishing it to the
// registry-wide index — happens under ONE r.mu critical section, mirroring
// Close. Serializing the two on r.mu closes two races a finer-grained
// scheme was shown to leave open:
//
//  1. A PutRef whose tryPutRef insert lands after Close has already taken
//     its (then-empty) refsSnapshot would still publish to refOwners
//     moments later — an entry for a session Close has already run for and
//     will never run for again, so nothing would ever release it, and
//     OwnsRef would report true for that SessionKey/ref for the rest of
//     the process's lifetime.
//  2. The mirror image: a tryPutRef insert landing between Close's
//     r.sessions delete and its refsSnapshot puts the ref INTO the
//     snapshot without it ever reaching refOwners — Close's decrement loop
//     would then release a count this session never contributed, stealing
//     ownership from a still-open sibling session sharing the same
//     SessionKey (its Status calls would start failing
//     buildkit_ref_not_owned).
//
// Lock ordering: tryPutRef (and Close's refsSnapshot) acquire s.mu strictly
// NESTED inside the r.mu critical section, and no code path ever takes them
// in the opposite order, so the nesting cannot deadlock.
func (r *SessionRegistry) PutRef(s *Session, ref string, maxRefs int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, stillOpen := r.sessions[s.ID]; !stillOpen {
		return false
	}

	admitted, isNew := s.tryPutRef(ref, maxRefs)
	if !admitted {
		return false
	}
	if !isNew {

		return true
	}

	if r.refOwners == nil {
		r.refOwners = make(map[SessionKey]map[string]int)
	}
	owners, ok := r.refOwners[s.Key]
	if !ok {
		owners = make(map[string]int)
		r.refOwners[s.Key] = owners
	}
	owners[ref]++
	return true
}

// OwnsRef reports whether ref was admitted via PutRef by ANY session sharing
// key — see refOwners's doc comment for why ownership is checked at the
// client-identity+profile granularity, not per individual connection.
func (r *SessionRegistry) OwnsRef(key SessionKey, ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refOwners[key][ref] > 0
}

// HasAdmittedSolve reports whether key has admitted at least one
// Control/Solve ref that is still owned (i.e. OwnsRef would return true for
// SOME ref under key). Phase 5's FileSend/DiffCopy mediation
// (filesend.go) uses this to enforce the #185 synthesis's "allow only when
// bound to an admitted Solve from the same SessionKey" rule: moby.filesync.
// v1.FileSend.DiffCopy's BytesMessage carries no ref (or any other
// identifying field) of its own to check with OwnsRef directly, so the only
// meaningful check available is "has this identity+profile solved anything
// at all yet."
func (r *SessionRegistry) HasAdmittedSolve(key SessionKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.refOwners[key]) > 0
}

// AdmitUploadKey registers id as a one-use Upload/Pull token for key,
// admitting it only if key currently holds fewer than maxKeys
// not-yet-consumed tokens (maxKeys <= 0 disables the bound). Returns false
// without recording anything once the bound is hit. A duplicate id already
// admitted-but-not-yet-consumed is a harmless no-op success (mirrors
// PutRef's tolerance of a repeated call) rather than a second, redundant
// bound check.
func (r *SessionRegistry) AdmitUploadKey(key SessionKey, id string, maxKeys int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.uploadKeys == nil {
		r.uploadKeys = make(map[SessionKey]map[string]struct{})
	}
	keys, ok := r.uploadKeys[key]
	if !ok {
		keys = make(map[string]struct{})
		r.uploadKeys[key] = keys
	}
	if _, exists := keys[id]; exists {
		return true
	}
	if maxKeys > 0 && len(keys) >= maxKeys {
		return false
	}
	keys[id] = struct{}{}
	return true
}

// ConsumeUploadKey reports whether id is a currently-valid, not-yet-consumed
// Upload/Pull token for key, and if so atomically removes it — the "one-use"
// half of the #185 synthesis's "one-use token bound to an admitted stdin/
// remote-context upload" requirement. A second call with the same id (or a
// call naming an id that was never admitted at all) returns false: both
// cases mean "this is not currently a valid token for a fresh Pull,"
// deliberately collapsed to one outcome — see upload.go's
// buildkit_upload_token_invalid audit reason.
func (r *SessionRegistry) ConsumeUploadKey(key SessionKey, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys, ok := r.uploadKeys[key]
	if !ok {
		return false
	}
	if _, exists := keys[id]; !exists {
		return false
	}
	delete(keys, id)
	if len(keys) == 0 {
		delete(r.uploadKeys, key)
	}
	return true
}

// decodeMediatedMessage unmarshals payload into msg and runs Phase 3's
// strict unknown-field check (hasUnknownFields) — the shared first two steps
// every Phase 4 credential-session RPC's evaluate function performs before
// any policy-specific field check, factored out here since solve.go's
// evaluateSolveRequest/evaluateStatusRequest only ever needed this sequence
// inline once each.
func decodeMediatedMessage(payload []byte, msg proto.Message) *mediationDenial {
	if err := proto.Unmarshal(payload, msg); err != nil {
		return deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed BuildKit gRPC request message")
	}
	if hasUnknownFields(msg) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	return nil
}

// normalizeAuthHost canonicalizes a moby.filesync.v1.Auth request's Host
// field to the same lowercase form solve.go's registryHostFromImageRef
// produces (including the index.docker.io -> docker.io alias), so it
// compares equal to the canonical form config.normalizeRegistryHostList
// stores AllowedRegistries entries in. Unlike registryHostFromImageRef, this
// does NOT parse an image reference: Auth's Host field is already a bare
// network authority (e.g. "registry-1.docker.io" for Docker Hub — see
// moby/buildkit's util/resolver/authorizer.go, which sets it from the
// resolved HTTP request's URL.Host, not from any image name), so there is no
// "first path segment" disambiguation to perform. ok is false only for an
// empty host.
func normalizeAuthHost(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", false
	}
	if host == "index.docker.io" {
		host = "docker.io"
	}
	return host, true
}

// checkAuthRegistryHost denies unless host normalizes and is a member of
// allowed — the shared gate every moby.filesync.v1.Auth RPC applies to its
// Host field. The denial message never echoes host, per this package's
// "never echo client-supplied content into a client-readable status"
// convention (mediationDenial's doc comment).
func checkAuthRegistryHost(host string, allowed []string) *mediationDenial {
	normalized, ok := normalizeAuthHost(host)
	if !ok || !slices.Contains(allowed, normalized) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "registry host is not permitted")
	}
	return nil
}

// evaluateCredentialsRequest decodes payload as an auth.CredentialsRequest
// and checks its Host against policy.AllowedRegistries. The response this
// RPC produces (CredentialsResponse.Username/Secret) carries the actual
// registry credentials — never decoded or logged on this path.
func evaluateCredentialsRequest(payload []byte, policy AuthPolicy) (*auth.CredentialsRequest, *mediationDenial) {
	req := &auth.CredentialsRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if d := checkAuthRegistryHost(req.GetHost(), policy.AllowedRegistries); d != nil {
		return nil, d
	}
	return req, nil
}

// evaluateGetTokenAuthorityRequest decodes payload as an
// auth.GetTokenAuthorityRequest and checks its Host against
// policy.AllowedRegistries. Salt is opaque (a nonce the client's token
// authority signs with) and has no policy-relevant content.
func evaluateGetTokenAuthorityRequest(payload []byte, policy AuthPolicy) (*auth.GetTokenAuthorityRequest, *mediationDenial) {
	req := &auth.GetTokenAuthorityRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if d := checkAuthRegistryHost(req.GetHost(), policy.AllowedRegistries); d != nil {
		return nil, d
	}
	return req, nil
}

// evaluateVerifyTokenAuthorityRequest decodes payload as an
// auth.VerifyTokenAuthorityRequest and checks its Host against
// policy.AllowedRegistries. Payload/Salt are opaque signature material with
// no policy-relevant content.
func evaluateVerifyTokenAuthorityRequest(payload []byte, policy AuthPolicy) (*auth.VerifyTokenAuthorityRequest, *mediationDenial) {
	req := &auth.VerifyTokenAuthorityRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if d := checkAuthRegistryHost(req.GetHost(), policy.AllowedRegistries); d != nil {
		return nil, d
	}
	return req, nil
}

// evaluateFetchTokenRequest decodes payload as an auth.FetchTokenRequest and
// checks Host, Realm, AND every entry of Scopes — the only one of Auth's
// four RPCs whose request carries Realm/Service/Scopes at all (Credentials/
// GetTokenAuthority/VerifyTokenAuthority only ever carry Host), which is why
// AuthPolicy.AllowedRealms/AllowedScopes exist as fields of their own
// distinct from AllowedRegistries.
//
// Design decision (researched against moby/buildkit v0.32.0's
// util/resolver/authorizer.go and session/auth/authprovider/
// authprovider.go): Host is gated the same as every other Auth RPC — it
// names the registry the daemon is trying to reach. Realm and Service come
// from that registry's own WWW-Authenticate Bearer challenge (buildkitd
// echoes them back verbatim in FetchTokenRequest; a registry's token realm
// commonly lives on a DIFFERENT host than the registry itself, e.g. Docker
// Hub's registry-1.docker.io challenges to a realm on auth.docker.io), so
// Host alone cannot bound where the resulting bearer token is minted for —
// an operator who allowlists a registry host but not its legitimate token
// realm would otherwise unknowingly also admit a FetchToken to ANY realm
// that registry's challenge names. Realm is therefore checked against its
// own AllowedRealms allowlist (exact match, not derived from
// AllowedRegistries), and every requested Scope must be a member of
// AllowedScopes (an empty Scopes list — unusual but not itself invalid in
// this wire format — passes trivially, the same "nothing to check"
// convention checkSolveEntitlements/checkCacheEntry use for their own empty
// repeated fields). Service (the token audience string, e.g. "registry")
// has no dedicated allowlist: it is Realm-derived metadata already
// constrained by the realm check above and is not itself a scope of
// access. ClientID is exchange bookkeeping with no policy-relevant content.
func evaluateFetchTokenRequest(payload []byte, policy AuthPolicy) (*auth.FetchTokenRequest, *mediationDenial) {
	req := &auth.FetchTokenRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if d := checkAuthRegistryHost(req.GetHost(), policy.AllowedRegistries); d != nil {
		return nil, d
	}
	if !slices.Contains(policy.AllowedRealms, req.GetRealm()) {
		return nil, deny(grpcCodePermissionDenied, "buildkit_policy_denied", "token realm is not permitted")
	}
	for _, scope := range req.GetScopes() {
		if !slices.Contains(policy.AllowedScopes, scope) {
			return nil, deny(grpcCodePermissionDenied, "buildkit_policy_denied", "token scope is not permitted")
		}
	}
	return req, nil
}

// evaluateGetSecretRequest decodes payload as a secrets.GetSecretRequest and
// checks its ID against policy.AllowedIDs.
//
// Annotations disposition (researched against moby/buildkit v0.32.0's
// session/secrets/secrets.go and session/secrets/secretsprovider/
// secretsprovider.go): the stock CALLER (secrets.GetSecret, invoked by
// buildkitd to request a secret) constructs `&GetSecretRequest{ID: id}` —
// Annotations is never populated. The stock HANDLER
// (secretsprovider.GetSecret, the client-side implementation buildx/docker
// register to answer this call) never reads req.Annotations either — only
// req.ID. The field exists in the wire schema but carries no operationally
// meaningful semantics in the real client/session flow this phase targets.
// With no reviewed config surface for annotation content and no concrete
// evidence buildx ever sends any, a non-empty Annotations map is denied
// outright — matching solve.go's "no enabling knob" posture for other
// unreviewed-but-structurally-known fields (checkSolveSourcePolicy,
// checkSolveRemainingFields) — rather than silently forwarded unexamined.
// The response (GetSecretResponse.data) carries the actual secret bytes —
// never decoded or logged on this path.
func evaluateGetSecretRequest(payload []byte, policy SecretsPolicy) (*secrets.GetSecretRequest, *mediationDenial) {
	req := &secrets.GetSecretRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if len(req.GetAnnotations()) > 0 {
		return nil, deny(grpcCodePermissionDenied, "buildkit_policy_denied", "secret annotations are not supported")
	}
	if req.GetID() == "" || !slices.Contains(policy.AllowedIDs, req.GetID()) {
		return nil, deny(grpcCodePermissionDenied, "buildkit_policy_denied", "secret ID is not permitted")
	}
	return req, nil
}

// checkSSHAgentID denies unless id is non-empty and a member of allowed —
// the shared gate both of SSH's RPCs apply to their agent ID, whether it
// arrives as a decoded message field (CheckAgent) or stream metadata
// (ForwardAgent — see evaluateForwardAgentID).
func checkSSHAgentID(id string, allowed []string) *mediationDenial {
	if id == "" || !slices.Contains(allowed, id) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "SSH agent ID is not permitted")
	}
	return nil
}

// evaluateCheckAgentRequest decodes payload as a
// sshforward.CheckAgentRequest and checks its ID against policy.AllowedIDs.
func evaluateCheckAgentRequest(payload []byte, policy SSHPolicy) (*sshforward.CheckAgentRequest, *mediationDenial) {
	req := &sshforward.CheckAgentRequest{}
	if d := decodeMediatedMessage(payload, req); d != nil {
		return nil, d
	}
	if d := checkSSHAgentID(req.GetID(), policy.AllowedIDs); d != nil {
		return nil, d
	}
	return req, nil
}

// sshForwardAgentIDMetadataKey is the gRPC metadata key moby/buildkit's
// session/sshforward package attaches to every ForwardAgent call — see
// `const KeySSHID = "buildkit.ssh.id"` in session/sshforward/ssh.go
// (v0.32.0): buildkitd sets exactly one value,
// `metadata.NewOutgoingContext(rpcCtx, map[string][]string{KeySSHID:
// {id}})`, before dialing the stream. gRPC-over-HTTP/2 carries outgoing
// metadata as ordinary request headers, so this arrives as an HTTP/2 header
// on the stream's *http.Request — net/http canonicalizes it to
// "Buildkit.ssh.id" on the way in, which http.Header.Values looks up
// case-insensitively regardless of the form it names the key in here.
const sshForwardAgentIDMetadataKey = "buildkit.ssh.id"

// evaluateForwardAgentID extracts and validates the ForwardAgent stream's
// agent ID from r's headers — BEFORE any byte of the stream itself is
// relayed. ForwardAgent(stream BytesMessage) returns (stream BytesMessage)
// is a bidirectional stream of raw SSH agent protocol bytes with no unary
// request message to frame/decode the way CheckAgent's is; the ID that
// gates it travels entirely in gRPC metadata (see
// sshForwardAgentIDMetadataKey), which is why this function's signature
// differs from every other evaluate* function in this file. Per the #185
// Phase 4 requirement that SSH agent protocol bytes are opaque and must
// never be decoded or logged, this is the ONLY inspection ForwardAgent ever
// receives.
//
// Exactly one metadata value is required: zero means a caller that never
// set the metadata BuildKit's own client always sets (a malformed/
// non-conformant request, not a policy question), and more than one is
// treated the same way rather than guessing which value should govern —
// both fail closed as a protocol error rather than a policy denial.
func evaluateForwardAgentID(r *http.Request, policy SSHPolicy) (id string, denial *mediationDenial) {
	values := r.Header.Values(sshForwardAgentIDMetadataKey)
	if len(values) != 1 || values[0] == "" {
		return "", deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "missing or malformed SSH agent ID metadata")
	}
	if d := checkSSHAgentID(values[0], policy.AllowedIDs); d != nil {
		return "", d
	}
	return values[0], nil
}

// auditIDSalt is generated once per process from crypto/rand: it keeps
// shortHash stable across log lines within one sockguard process (repeated
// audit events for the same secret/SSH-agent ID still correlate) while
// making the digest useless to an offline dictionary attack — real-world
// secret/SSH IDs are short, guessable operator labels ("default",
// "npm_token"), and an UNSALTED SHA-256 truncated to 48 bits is recovered
// from a candidate list of those in milliseconds, which would leak the very
// identifier shortHash exists to withhold. crypto/rand.Read never fails on
// any supported platform without panicking internally (its own documented
// contract since Go 1.24), so no error path exists here.
var auditIDSalt = func() [16]byte {
	var s [16]byte
	_, _ = rand.Read(s[:])
	return s
}()

// shortHash returns a fixed-length, non-reversible identifier for s derived
// from the SHA-256 sum of auditIDSalt||s, truncated to 12 hex characters
// (48 bits) — enough to correlate repeated audit events for the same
// secret/SSH-agent ID across log lines (within one process — the salt, and
// therefore the hash for a given ID, changes on restart) without ever
// reproducing the ID itself. Per CLAUDE.md's "never log secret contents"
// constraint (extended here to the IDENTIFIERS naming secrets/SSH agents,
// which may themselves be operator-chosen labels worth not exposing in
// plaintext logs), audit events carry this hash in place of the raw ID —
// see bridge_session.go's forwardSecretsMediated/forwardCheckAgent/
// forwardSSHAgentStream, the only callers.
func shortHash(s string) string {
	h := sha256.New()
	h.Write(auditIDSalt[:])
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil)[:6])
}

// mediationDenial carries the gRPC status code, audit reason code (one of
// the #185 synthesis's low-cardinality vocabulary — see bridge.go's audit),
// and human-readable message for a Solve/Status call Phase 3's per-message
// checks reject. message is sockguard's own fixed/templated text, or names
// only structural facts already validated as printable (a method/service
// name, a fixed field name) — never raw client-supplied content, per
// CLAUDE.md's "never log secret contents" constraint extended to gRPC status
// messages a client can read back.
type mediationDenial struct {
	code       int
	reasonCode string
	message    string
}

func deny(code int, reasonCode, message string) *mediationDenial {
	return &mediationDenial{code: code, reasonCode: reasonCode, message: message}
}

// BuildKit entitlement identifiers, as sent in SolveRequest.Entitlements.
// Reproduced as string constants rather than imported from moby/buildkit's
// util/entitlements package — this package must never import moby/buildkit's
// implementation graph (see registry.go's package doc).
const (
	entitlementNetworkHost      = "network.host"
	entitlementSecurityInsecure = "security.insecure"
)

// allowedSolveFrontends is Phase 3's fixed frontend allowlist — NOT an
// operator-facing config knob, matching registry.go's own fixed
// classification table convention for "no enabling knob" surfaces. "" is a
// raw LLB Solve with no external frontend image to resolve/execute at all;
// "dockerfile.v0" is BuildKit's built-in, in-process Dockerfile frontend.
// Every other frontend — most notably "gateway.v0", which lets a client name
// an arbitrary frontend IMAGE for buildkitd to pull and execute with control
// over the build via the moby.buildkit.v1.frontend.LLBBridge callback
// service — is denied: LLBBridge is hard-denied surface with no enabling
// knob (registry.go's DeniedExamples), so admitting the frontend that is
// LLBBridge's only way to get invoked would just relocate the same hole.
var allowedSolveFrontends = map[string]bool{
	"":              true,
	"dockerfile.v0": true,
}

// knownFrontendAttrKeys is Phase 3's fixed allowlist of FrontendAttrs keys
// sockguard recognizes well enough to have a policy opinion about. Per the
// #185 synthesis's strict divergence #3, any OTHER key denies the whole
// Solve (buildkit_schema_unsupported) rather than being silently forwarded
// unexamined — a permissive default here is exactly the silent-bypass
// channel divergence #3 rejects. Bumping this set for a new Buildx release
// is a reviewed, committed change, like registry.go's own table.
var knownFrontendAttrKeys = map[string]bool{
	"filename":           true,
	"context":            true,
	"target":             true,
	"platform":           true,
	"cmdline":            true,
	"no-cache":           true,
	"nocache":            true,
	"multi-platform":     true,
	"shm-size":           true,
	"ulimit":             true,
	"hostname":           true,
	"cgroup-parent":      true,
	"image-resolve-mode": true,
	"add-hosts":          true,
	"force-network-mode": true,
}

// knownFrontendAttrPrefixes are FrontendAttrs key FAMILIES rather than exact
// keys: build-arg:<name>, label:<name>, and context:<name> (additional named
// build contexts) each carry an operator-irrelevant suffix chosen by the
// build invocation, not sockguard's schema.
var knownFrontendAttrPrefixes = []string{
	"build-arg:",
	"label:",
	"context:",
}

// isKnownFrontendAttrKey reports whether key is in Phase 3's fixed
// FrontendAttrs allowlist — an exact match in knownFrontendAttrKeys, or a
// member of one of knownFrontendAttrPrefixes' families.
func isKnownFrontendAttrKey(key string) bool {
	if knownFrontendAttrKeys[key] {
		return true
	}
	for _, prefix := range knownFrontendAttrPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// scpLikeGitRefRegexp detects the scp-style git remote syntax —
// "<user>@<host>:<path>", the form `git clone` accepts with no "://" scheme
// at all (e.g. "bob@example.com:org/repo.git") — reproduced verbatim from
// moby/buildkit's util/sshutil.gitSSHRegex (this package must not import
// buildkit's implementation graph; see registry.go's package doc) so
// isRemoteContextRef classifies exactly the strings BuildKit's own gitutil
// would treat as a git remote, not a narrower or broader guess. A bare
// "user@host" with no colon, or any string with no "@" at all, never
// matches — this is deliberately the SAME ambiguity BuildKit's own detector
// has (a local path that happens to look like "user@host:path" is
// indistinguishable from a real scp-style remote), not a gap introduced
// here.
var scpLikeGitRefRegexp = regexp.MustCompile(`^([a-zA-Z0-9-_]+)@([a-zA-Z0-9-.]+):(.*?)(?:#(.*))?$`)

// isRemoteContextRef reports whether a "context" or "context:<name>"
// FrontendAttrs value names a remote location (a URL-shaped git/http(s)
// context, mirroring classic POST /build's remote-context detection, or an
// scp-style git remote — see scpLikeGitRefRegexp) rather than a path within
// the build context sockguard already treats as local.
func isRemoteContextRef(value string) bool {
	for _, prefix := range []string{"http://", "https://", "git://", "github.com/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	if strings.Contains(value, "://") {
		return true
	}
	return scpLikeGitRefRegexp.MatchString(value)
}

// isUploadSessionContextRef reports whether value is a BuildKit upload-session
// URL ("http://buildkit-session/<id>") — a local client-streamed upload, not a
// remote git/HTTP fetch. isRemoteContextRef matches these too (http:// prefix),
// so checkSolveFrontend uses this to exclude them from the RUN-inspection
// remote-context denial. Uses the same scheme/host recognition as upload.go's
// admitSolveUploadKeys so the two agree on exactly which values are uploads.
func isUploadSessionContextRef(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "http" && u.Host == uploadSessionHost
}

// registryHostFromImageRef extracts the registry authority from an
// image-like reference, using the same disambiguation rule Docker's own
// reference grammar uses: split on the first '/'; if that first component
// contains neither '.' nor ':' and isn't exactly "localhost", it is NOT a
// registry host at all (it's the first path segment of a repository name on
// the default registry, e.g. "library/alpine") — so the ref resolves to
// "docker.io". Duplicated here in miniature rather than imported from
// internal/filter or internal/config: this package is a dependency-light
// leaf that must not import either (see registry.go's package doc for the
// same constraint applied to grpc-go). ok is false only for an empty ref.
func registryHostFromImageRef(ref string) (host string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if idx := strings.Index(ref, "://"); idx >= 0 {
		ref = ref[idx+len("://"):]
	}

	first, _, hasSlash := strings.Cut(ref, "/")
	if !hasSlash || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return "docker.io", true
	}
	host = strings.ToLower(first)
	if host == "index.docker.io" {
		host = "docker.io"
	}
	return host, true
}

// evaluateSolveRequest decodes payload as a control.SolveRequest and runs
// every Phase 3 policy check against policy.Control.Solve, in the order the
// #185 synthesis lists them: unknown fields first (nothing else can be
// trusted to mean what it says otherwise), then entitlements, frontend +
// frontend attrs, cache, exporters, source policy, and every other field
// this file examines (checkSolveRemainingFields — see the file's header
// comment for the full field-by-field disposition). Ref presence is
// checked LAST, deliberately: it is a registration precondition ("this
// request is otherwise fully policy-clean, so does it actually name
// something the caller can register ownership of") rather than a content
// check in its own right, and checking it last lets every other check's
// own denial reason surface for a request that's simultaneously invalid in
// more than one way, instead of always short-circuiting on "no ref" first.
// Returns the decoded request (for the caller to read Ref off, for
// ref-registry admission) and a nil denial on success, or a nil request and
// non-nil denial on the first check that fails.
func evaluateSolveRequest(payload []byte, policy Policy) (*control.SolveRequest, *mediationDenial) {
	req := &control.SolveRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return nil, deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed SolveRequest")
	}
	if hasUnknownFields(req) {
		return nil, deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	solvePolicy := policy.Control.Solve
	if d := checkSolveEntitlements(req.GetEntitlements(), solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveFrontend(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveCache(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveExporters(req, solvePolicy); d != nil {
		return nil, d
	}
	if d := checkSolveSourcePolicy(req); d != nil {
		return nil, d
	}
	if d := checkSolveRemainingFields(req); d != nil {
		return nil, d
	}
	if req.GetRef() == "" {

		return nil, deny(grpcCodeInvalidArgument, "buildkit_invalid_ref", "solve request ref must not be empty")
	}

	return req, nil
}

// checkSolveEntitlements enforces the #185 synthesis's entitlement rules:
// network.host requires AllowHostNetwork, security.insecure is denied
// outright regardless of policy (no v1.7 enabling knob), and any entitlement
// string sockguard doesn't recognize is denied rather than silently admitted
// — an unknown entitlement is a signal sockguard cannot evaluate, and per
// this package's default-deny identity an unevaluable signal must not pass.
func checkSolveEntitlements(entitlements []string, solvePolicy SolvePolicy) *mediationDenial {
	for _, e := range entitlements {
		switch e {
		case entitlementSecurityInsecure:
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "the security.insecure entitlement is denied")
		case entitlementNetworkHost:
			if !solvePolicy.AllowHostNetwork {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "the network.host entitlement requires this profile's allow_host_network")
			}
		default:
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "unrecognized entitlement")
		}
	}
	return nil
}

// checkSolveFrontend enforces the frontend allowlist and, for each
// FrontendAttrs entry, the known-key allowlist plus the two attrs that map
// onto an existing request_body.build semantic: "context"/"context:<name>"
// naming a remote location requires AllowRemoteContext, and
// "force-network-mode" == "host" requires AllowHostNetwork (the frontend's
// own default-network-mode knob, independent of the Entitlements-level
// network.host check above — a Dockerfile build can request host networking
// for its RUN instructions this way without ever setting the SolveRequest
// entitlement itself).
func checkSolveFrontend(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	if !allowedSolveFrontends[req.GetFrontend()] {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "frontend is not permitted")
	}

	for key, value := range req.GetFrontendAttrs() {
		if !isKnownFrontendAttrKey(key) {
			return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
		}
		switch {
		case (key == "context" || strings.HasPrefix(key, "context:")) && isRemoteContextRef(value):
			if !solvePolicy.AllowRemoteContext {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "a remote build context requires this profile's allow_remote_context")
			}

			if !solvePolicy.AllowRunInstructions && !isUploadSessionContextRef(value) {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "a remote build context cannot be inspected while RUN instructions are restricted")
			}
		case key == "force-network-mode" && value == "host":
			if !solvePolicy.AllowHostNetwork {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "force-network-mode=host requires this profile's allow_host_network")
			}
		}
	}
	return nil
}

// checkSolveCache enforces the cache import/export allowlists. The
// deprecated pre-0.4.0 singular cache-ref fields (CacheOptions.
// ExportRefDeprecated/ImportRefsDeprecated/ExportAttrsDeprecated) are denied
// outright rather than translated into the modern Exports/Imports shape the
// way buildkitd itself would: sockguard's allowlist enforcement below only
// ever inspects Exports/Imports, so silently accepting the deprecated
// fields unenforced would be a real bypass channel for an ostensibly
// unknown-but-actually-just-old wire shape, not a compatibility nicety.
func checkSolveCache(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	if req.GetExporterDeprecated() != "" || len(req.GetExporterAttrsDeprecated()) > 0 {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	cache := req.GetCache()
	if cache == nil {
		return nil
	}
	if cache.GetExportRefDeprecated() != "" || len(cache.GetImportRefsDeprecated()) > 0 || len(cache.GetExportAttrsDeprecated()) > 0 {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}

	for _, entry := range cache.GetImports() {
		if d := checkCacheEntry(entry, solvePolicy.AllowedCacheImportTypes, solvePolicy.AllowedCacheRegistries); d != nil {
			return d
		}
	}
	for _, entry := range cache.GetExports() {
		if d := checkCacheEntry(entry, solvePolicy.AllowedCacheExportTypes, solvePolicy.AllowedCacheRegistries); d != nil {
			return d
		}
	}
	return nil
}

// checkCacheEntry validates one CacheOptionsEntry (an import or an export)
// against its direction's type allowlist and, for the "registry" type, the
// shared cache-registry allowlist. The denial message never includes
// entry.GetType() — that's raw client-supplied content, and this package's
// own mediationDenial doc comment forbids echoing it back into a
// client-readable Grpc-Message.
func checkCacheEntry(entry *control.CacheOptionsEntry, allowedTypes, allowedRegistries []string) *mediationDenial {
	if entry == nil {
		return nil
	}
	if !slices.Contains(allowedTypes, entry.GetType()) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "cache type is not permitted")
	}
	if entry.GetType() != "registry" {
		return nil
	}
	host, ok := registryHostFromImageRef(entry.GetAttrs()["ref"])
	if !ok || !slices.Contains(allowedRegistries, host) {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "cache registry is not permitted")
	}
	return nil
}

// checkSolveExporters enforces the exporter type allowlist, the exporter
// registry allowlist for an "image" exporter that pushes, and denies
// EnableSessionExporter outright: that flag opts into the session-based
// exporter negotiation handled by moby.exporter.v1.Exporter, which is
// hard-denied surface with no v1.7 enabling knob (registry.go's
// DeniedExamples) — admitting the flag here would just let a build declare
// intent to use a service the bridge only rejects once the daemon actually
// tries to call back into it.
//
// The "push" attr is parsed with strconv.ParseBool, matching BuildKit's own
// image exporter (which runs the identical attr through ParseBool) rather
// than a bare `== "true"` comparison — "1", "T", "TRUE", etc. all enable
// pushing in the real exporter and must not skip the registry check here. A
// value ParseBool can't evaluate is denied outright rather than treated as
// false: a push attribute sockguard cannot classify must not silently pass.
// "name" may hold multiple comma-separated image refs (BuildKit pushes each
// one), so every ref's registry — not just the first — must clear
// AllowedExporterRegistries; an empty name with push enabled is denied since
// there is nothing to validate.
func checkSolveExporters(req *control.SolveRequest, solvePolicy SolvePolicy) *mediationDenial {
	for _, exp := range req.GetExporters() {
		if exp == nil {
			continue
		}
		if !slices.Contains(solvePolicy.AllowedExporters, exp.GetType()) {
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "exporter type is not permitted")
		}
		if exp.GetType() != "image" {
			continue
		}

		attrs := exp.GetAttrs()
		push := false
		if raw, ok := attrs["push"]; ok {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "exporter push value is not a supported boolean")
			}
			push = parsed
		}
		if !push {
			continue
		}

		name := attrs["name"]
		if name == "" {
			return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "exporter push registry is not permitted")
		}
		for _, ref := range strings.Split(name, ",") {
			host, ok := registryHostFromImageRef(ref)
			if !ok || !slices.Contains(solvePolicy.AllowedExporterRegistries, host) {
				return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "exporter push registry is not permitted")
			}
		}
	}
	if req.GetEnableSessionExporter() {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "session-based exporter negotiation is not supported")
	}
	return nil
}

// checkSolveSourcePolicy denies any Solve carrying a non-empty source
// policy outright: source policy rules can rewrite image references at
// solve time, which could otherwise be used to route around sockguard's own
// registry allowlists elsewhere in the proxy, and no phase has added a
// config surface to review/allow specific rewrite rules — matching the
// "no enabling knob" posture registry.go's DeniedExamples uses for other
// unaudited surfaces. SourcePolicySession (field 15) gets the identical
// denial and rationale: it names a session that supplies source-policy
// rules out of band instead of inline, which would otherwise bypass the
// inline-rules check above entirely while achieving the exact same
// image-reference rewriting.
func checkSolveSourcePolicy(req *control.SolveRequest) *mediationDenial {
	if req.GetSourcePolicy() != nil && len(req.GetSourcePolicy().GetRules()) > 0 {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "source policy rules are not supported")
	}
	if req.GetSourcePolicySession() != "" {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "source policy rules are not supported")
	}
	return nil
}

// checkSolveRemainingFields disposes of the SolveRequest fields no other
// check function examines — see this file's header comment for the full
// field-by-field audit. FrontendInputs (client-supplied LLB input graphs
// substituted into the frontend's own inputs) and ProxyNetwork (opts the
// build into buildkitd forwarding its own host proxy configuration —
// potentially including credentials embedded in a proxy URL — into the
// build) are both denied outright: neither has a reviewed config surface,
// matching this file's "no enabling knob" posture for other unaudited
// surfaces. Every other remaining field (CompatibilityVersion, Internal,
// Session, Definition) needs no gate — see the header comment for why each
// is safe to forward unexamined.
func checkSolveRemainingFields(req *control.SolveRequest) *mediationDenial {
	if len(req.GetFrontendInputs()) > 0 {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "frontend inputs are not supported")
	}
	if req.GetProxyNetwork() {
		return deny(grpcCodePermissionDenied, "buildkit_policy_denied", "proxy network is not supported")
	}
	return nil
}

// evaluateStatusRequest decodes payload as a control.StatusRequest and
// checks it for unknown fields. Ref-ownership (the #185 synthesis's "belongs
// to an admitted Solve from the same client identity + profile" rule) is
// deliberately NOT checked here — it needs the bridge's SessionRegistry and
// SessionKey, which this decode-only, bridge-independent function has no
// access to and shouldn't: see bridge.go's forwardControlMediated, which
// calls this first and then separately consults
// SessionRegistry.OwnsRef(b.session.Key, req.GetRef()) before admitting.
func evaluateStatusRequest(payload []byte) (*control.StatusRequest, *mediationDenial) {
	req := &control.StatusRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return nil, deny(grpcCodeInvalidArgument, "buildkit_protocol_error", "malformed StatusRequest")
	}
	if hasUnknownFields(req) {
		return nil, deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	return req, nil
}

// errStreamFrameProtocolError is readGRPCFrame's framing-violation sentinel —
// the streaming-loop analog of errUnaryFrameProtocolError. A nonzero
// compression flag or a truncated frame both fail closed with this; a clean
// EOF at a frame boundary (no bytes at all read for the next header) is NOT
// an error at all — see readGRPCFrame's own doc comment.
var errStreamFrameProtocolError = errors.New("buildkitproxy: malformed gRPC stream message framing")

// readGRPCFrame reads exactly one gRPC length-prefixed message frame from r:
// the COMPLETE original frame (5-byte header + payload, byte-for-byte as
// read, returned so a caller can relay it verbatim on allow — the same "on
// allow forward the ORIGINAL bytes, never a re-encoded message" constraint
// framing.go's readUnaryGRPCMessage documents) and the payload alone,
// separately, for proto.Unmarshal to decode.
//
// Returns io.EOF (with nil frame/payload) when r is exhausted at a clean
// frame boundary — zero bytes read before the header's io.ReadFull fails —
// which callers must treat as "the stream ended normally," not a protocol
// violation: unlike a unary RPC's single buffered request, a streaming
// DiffCopy/Pull call's request or response stream legitimately ends after
// an arbitrary number of frames once its peer stops writing and closes its
// side. A truncated frame (some but not all of the header, or a short read
// on the payload) is a genuine protocol violation and fails closed with
// errStreamFrameProtocolError, same as a nonzero compression flag.
//
// maxLen bounds the payload length the frame's own header declares, exactly
// like readUnaryGRPCMessage's maxLen: a frame declaring more than maxLen
// fails closed with errMessageTooLarge BEFORE any attempt to read that many
// bytes, so an attacker-controlled length prefix can never itself force a
// large allocation. maxLen <= 0 disables the cap.
func readGRPCFrame(r io.Reader, maxLen int64) (frame, payload []byte, err error) {
	var header [grpcMessageHeaderLen]byte
	n, err := io.ReadFull(r, header[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return nil, nil, io.EOF
		}
		return nil, nil, fmt.Errorf("%w: reading message header: %w", errStreamFrameProtocolError, err)
	}
	if header[0] != 0 {
		return nil, nil, fmt.Errorf("%w: compressed message flag set", errStreamFrameProtocolError)
	}

	length := int64(binary.BigEndian.Uint32(header[1:5]))
	if maxLen > 0 && length > maxLen {
		return nil, nil, errMessageTooLarge
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("%w: reading message payload: %w", errStreamFrameProtocolError, err)
	}

	frame = make([]byte, grpcMessageHeaderLen+len(payload))
	copy(frame, header[:])
	copy(frame[grpcMessageHeaderLen:], payload)
	return frame, payload, nil
}

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

	resp, err := b.clientLeg.RoundTrip(outReq.WithContext(r.Context()))
	if err != nil {
		if d := reqRelay.Denial(); d != nil {
			writeGRPCStatus(w, d.code, d.message)
			b.audit(service, method, Deny, d.reasonCode)
			b.recordDeniedAndMaybeClose()
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

// h2cDialTimeout bounds sockguard's own dial-and-upgrade to the daemon side
// of a bridged tunnel. Matches internal/proxy's hijackDialTimeout convention
// (5s) — this package intentionally doesn't import internal/proxy (a leaf
// package should not depend on another leaf package's internals), so the
// value is restated rather than shared.
const h2cDialTimeout = 5 * time.Second

// sessionUUIDHeader is the client-supplied session correlation ID. Recorded
// on Session as advisory metadata only — see SessionKey's doc comment.
const sessionUUIDHeader = "X-Docker-Expose-Session-Uuid"

// sessionGRPCMethodHeader advertises, on a POST /session upgrade request,
// which gRPC services the client's session server has registered (e.g.
// "moby.filesync.v1.FileSync", "moby.filesync.v1.Auth") so buildkitd knows
// what it can call back into. rewriteSessionAdvertisement narrows this to
// the intersection of "advertised" and "permitted" before sockguard forwards
// the upgrade to the daemon.
const sessionGRPCMethodHeader = "X-Docker-Expose-Session-Grpc-Method"

var (
	// ErrNotUpgradeRequest is returned by ValidateUpgradeRequest when the
	// request isn't attempting an h2c upgrade at all.
	ErrNotUpgradeRequest = errors.New("buildkitproxy: not an h2c upgrade request")
	// ErrUpgradeHasBody is returned when the client sent body bytes on the
	// upgrade request itself — BuildKit's h2c upgrade (mirroring the
	// existing attach/exec hijack convention in internal/proxy) never
	// carries a request body; anything present is either a confused client
	// or an attempt to smuggle bytes past sockguard's inspection before the
	// connection becomes an opaque byte pipe.
	ErrUpgradeHasBody = errors.New("buildkitproxy: h2c upgrade request must not carry a body")
	// ErrConflictingFraming is returned when the request declares
	// Transfer-Encoding alongside an upgrade — a request can't simultaneously
	// be chunked-framed HTTP/1.1 and about to stop being HTTP/1.1 at all.
	ErrConflictingFraming = errors.New("buildkitproxy: h2c upgrade request must not declare Transfer-Encoding")
)

// ValidateUpgradeRequest strictly validates an incoming POST /session or
// POST /grpc request before sockguard attempts to bridge it: exactly
// method POST, a Connection header naming "Upgrade", an Upgrade header of
// exactly "h2c" (case-insensitive, no other protocol tokens), no request
// body, and no conflicting Transfer-Encoding. Per the #185 synthesis this
// strict validation happens BEFORE any dial to the daemon or hijack of the
// client connection — a request that fails here is rejected as an ordinary
// HTTP response, never partially bridged.
func ValidateUpgradeRequest(r *http.Request) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("%w: method %s", ErrNotUpgradeRequest, r.Method)
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") {
		return fmt.Errorf("%w: missing \"Connection: Upgrade\"", ErrNotUpgradeRequest)
	}
	upgrade := r.Header.Values("Upgrade")
	if len(upgrade) != 1 || !strings.EqualFold(strings.TrimSpace(upgrade[0]), "h2c") {
		return fmt.Errorf("%w: Upgrade header must be exactly \"h2c\", got %q", ErrNotUpgradeRequest, upgrade)
	}
	if r.ContentLength > 0 {
		return ErrUpgradeHasBody
	}
	if len(r.TransferEncoding) > 0 {
		return ErrConflictingFraming
	}
	return nil
}

// headerHasToken reports whether any comma-separated value of header h[name]
// contains token, matched case-insensitively per RFC 9110's list-header
// syntax. Mirrors internal/proxy's removeHopByHopHeaders parsing of the
// Connection header.
func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h[textproto.CanonicalMIMEHeaderKey(name)] {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(textproto.TrimString(part), token) {
				return true
			}
		}
	}
	return false
}

// rewriteSessionAdvertisement narrows the client's sessionGRPCMethodHeader
// advertisement (read from dst) down to services ServiceAdmittedByPolicy
// reports as having at least one method that is BOTH non-Deny per Classify
// AND allowed by p, replacing the header's values on dst in place. Consulting
// p here — not just the static registry — matters: a service can be
// registered Mediate/Passthrough in principle while this operator's resolved
// policy still leaves it off (e.g. Auth advertised while
// p.Session.Auth.Allow is false), and advertising it anyway would invite a
// daemon callback the bridge only rejects after the fact instead of the
// daemon never being told the service is available at all. If dst carries no
// advertisement at all, dst is left untouched.
func rewriteSessionAdvertisement(dst http.Header, p Policy) {
	advertised := dst.Values(sessionGRPCMethodHeader)
	if len(advertised) == 0 {
		return
	}
	dst.Del(sessionGRPCMethodHeader)
	for _, service := range advertised {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		if ServiceAdmittedByPolicy(EndpointSession, service, p) {
			dst.Add(sessionGRPCMethodHeader, service)
		}
	}
}

// bufferedConn wraps a net.Conn whose initial bytes were already consumed
// into a *bufio.Reader by HTTP/1.1 request/response parsing (the upgrade
// request/response itself), so any client or daemon bytes that arrived
// immediately after — e.g. a client that starts writing the HTTP/2 client
// preface without waiting a full round-trip for the 101 response bytes to
// drain — are read back out before falling through to the raw connection.
// Per the #185 synthesis: "preserve parser-buffered bytes via a bufferedConn
// wrapper." Every other net.Conn method (Write, Close, deadlines) passes
// through via the embedded net.Conn unchanged.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// dialDaemonH2C dials the Docker daemon via dialer and performs the SAME
// h2c-upgrade handshake sockguard's own client just performed against it:
// write a POST request to path with header carrying exactly one
// "Connection: Upgrade" / "Upgrade: h2c" pair, then read and validate a 101
// response. A 101 status code alone doesn't prove a genuine h2c upgrade — a
// daemon could send 101 without "Connection: Upgrade", or with an Upgrade
// header naming some other protocol — so the response headers are validated
// the same way ValidateUpgradeRequest validates the incoming request, before
// anything downstream (including clearing the dial-scoped deadline) treats
// the connection as a live h2c tunnel. Returns the raw (buffered-wrapped)
// connection and the daemon's 101 response so the caller can replay it
// verbatim to the hijacked client connection — required ordering per the
// synthesis: "require a valid upstream 101 before hijacking downstream."
func dialDaemonH2C(ctx context.Context, dialer Dialer, path string, header http.Header) (net.Conn, *http.Response, error) {
	conn, err := dialer.DialContext(ctx, "", "")
	if err != nil {
		return nil, nil, fmt.Errorf("buildkitproxy: dial daemon: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := &http.Request{
		Method:     http.MethodPost,
		URL:        &url.URL{Scheme: "http", Host: "docker", Path: path},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header.Clone(),
		Host:       "docker",
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	req.ContentLength = 0

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: write daemon upgrade request: %w", err)
	}

	br := bufio.NewReaderSize(conn, 64<<10)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: read daemon upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon refused h2c upgrade: status %d", resp.StatusCode)
	}
	if !headerHasToken(resp.Header, "Connection", "upgrade") {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon's 101 response missing \"Connection: Upgrade\": got Connection %q", resp.Header.Values("Connection"))
	}
	respUpgrade := resp.Header.Values("Upgrade")
	if len(respUpgrade) != 1 || !strings.EqualFold(strings.TrimSpace(respUpgrade[0]), "h2c") {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("buildkitproxy: daemon's 101 response Upgrade header must be exactly \"h2c\", got %q", respUpgrade)
	}

	_ = conn.SetDeadline(time.Time{})

	return &bufferedConn{Conn: conn, r: br}, resp, nil
}

// hijackClientH2C hijacks the client connection behind w and replays resp —
// the daemon's own 101 response, obtained via dialDaemonH2C — verbatim,
// INCLUDING its Connection/Upgrade headers, mirroring
// internal/proxy/hijack.go's finalizeHijackUpgrade: after a 101 the
// connection is a raw byte tunnel with no next hop those headers could
// confuse, and buildkitd's exact 101 status line/headers are what the
// client's own gRPC transport expects to see.
func hijackClientH2C(w http.ResponseWriter, resp *http.Response) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("buildkitproxy: response writer does not support hijacking")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("buildkitproxy: hijack client connection: %w", err)
	}
	if err := resp.Write(buf); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("buildkitproxy: write 101 to client: %w", err)
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("buildkitproxy: flush 101 to client: %w", err)
	}
	return &bufferedConn{Conn: conn, r: buf.Reader}, nil
}

// uploadSessionHost is the literal URL host moby/buildkit's
// session/upload/uploadprovider.Uploader.Add embeds in every upload URL it
// hands back to a Solve's FrontendAttrs ("http://buildkit-session/<id>") —
// see this file's package doc for the exact upstream source confirming it.
const uploadSessionHost = "buildkit-session"

// admitSolveUploadKeys scans an admitted SolveRequest's FrontendAttrs for
// "context" and "context:<name>" values shaped like an upload-session URL
// (isRemoteContextRef's own isKnownFrontendAttrKey/checkSolveFrontend gate
// in solve.go already allowed these keys through; this is a second,
// independent pass over the SAME already-admitted attrs, looking for a
// value shape neither of those functions specifically recognizes) and
// registers each one as a one-use Upload/Pull token for key. Called from
// bridge.go's forwardControlMediated once a Solve is fully admitted
// (post-PutRef) — see this file's package doc for why the id embedded in
// the URL, not the FrontendAttrs key or value string itself, is what later
// binds a specific Upload/Pull call back to this Solve.
//
// A malformed or non-"buildkit-session" URL value is silently skipped, not
// denied: FrontendAttrs' "context"/"context:<name>" values are already
// fully validated by checkSolveFrontend's own allowlist/remote-context gate
// before this ever runs (evaluateSolveRequest only reaches here on an
// admitted Solve), so a value that isn't an upload-session URL is simply a
// normal local or remote context reference this function has nothing to do
// with — not a new denial surface layered on top of an already-decided
// admission.
//
// Candidate ids are collected and sorted before admission so the outcome is
// independent of Go's randomized map-iteration order: when a Solve names more
// upload-session contexts than maxKeys allows, admission is deterministic and
// all-or-nothing. Returns false if any candidate cannot be admitted (the
// maxKeys bound is hit), so the caller denies the whole Solve rather than
// forwarding one whose Upload/Pull tokens would then succeed or fail at
// random.
func admitSolveUploadKeys(registry *SessionRegistry, key SessionKey, req *control.SolveRequest, maxKeys int) bool {
	if req == nil {
		return true
	}
	var ids []string
	for k, v := range req.GetFrontendAttrs() {
		if k != "context" && !isContextAttrKey(k) {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "http" || u.Host != uploadSessionHost {
			continue
		}
		id := path.Base(u.Path)
		if id == "" || id == "." || id == "/" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !registry.AdmitUploadKey(key, id, maxKeys) {
			return false
		}
	}
	return true
}

// isContextAttrKey reports whether k is a named-additional-build-context
// FrontendAttrs key ("context:<name>") — the same family
// knownFrontendAttrPrefixes' "context:" entry in solve.go recognizes, kept
// as its own tiny helper here rather than exported from solve.go so this
// file's dependency on solve.go's internals stays limited to the one
// string literal both already independently agree on.
func isContextAttrKey(k string) bool {
	return len(k) > len("context:") && k[:len("context:")] == "context:"
}

// forwardUploadMediated is bridge.go's dispatch target for
// moby.upload.v1.Upload/Pull (see streammediation.go's
// isStreamMediatedMethod/forwardStreamMediated). The one-use token check
// runs BEFORE any stream relay begins — a pre-condition on the whole call —
// mirroring provider.go's own upstream behavior of deleting its map entry
// immediately upon a Pull call starting, before any byte is streamed: see
// this file's package doc.
func (b *bridge) forwardUploadMediated(w http.ResponseWriter, r *http.Request, service, method string) {
	if r.Header.Get("urlhost") != uploadSessionHost {
		writeGRPCStatus(w, grpcCodePermissionDenied, "Upload/Pull target is not a recognized BuildKit upload session")
		b.audit(service, method, Deny, "buildkit_upload_token_invalid")
		b.recordDeniedAndMaybeClose()
		return
	}
	id := path.Base(r.Header.Get("urlpath"))
	if id == "" || id == "." || id == "/" || !b.registry.ConsumeUploadKey(b.session.Key, id) {
		writeGRPCStatus(w, grpcCodePermissionDenied, "Upload/Pull token is not a currently valid, admitted upload for this client/profile")
		b.audit(service, method, Deny, "buildkit_upload_token_invalid")
		b.recordDeniedAndMaybeClose()
		return
	}

	reqCap := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: b.limits.MaxUploadBytes}
	respCap := &bytesMessageCapValidator{newMsg: func() proto.Message { return &upload.BytesMessage{} }, maxTotalBytes: b.limits.MaxUploadBytes}

	b.forwardStreamRelay(w, r, service, method, reqCap.validate, func(w http.ResponseWriter, src io.Reader) (*mediationDenial, error) {
		return relayValidatedFrames(w, src, b.limits.MaxMessageBytes, respCap.validate)
	})
}
