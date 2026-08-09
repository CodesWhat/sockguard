package buildkitproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http2"

	"github.com/codeswhat/sockguard/internal/logging"
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
	legs    bridgeLegs
	session *Session
	policy  Policy
	limits  Limits
	logger  *slog.Logger
	guard   *streamAbuseGuard

	clientLeg clientLegConn

	closeOnce sync.Once
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
func runBridge(ctx context.Context, legs bridgeLegs, session *Session, policy Policy, limits Limits, logger *slog.Logger) error {
	b := &bridge{
		legs:    legs,
		session: session,
		policy:  policy,
		limits:  limits,
		logger:  logger,
		guard:   newStreamAbuseGuard(limits),
	}
	defer b.closeAll(nil)

	clientTransport := &http2.Transport{AllowHTTP: true}
	cc, err := clientTransport.NewClientConn(legs.clientConn)
	if err != nil {
		return fmt.Errorf("buildkitproxy: establish client leg: %w", err)
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

	return b.closeErr
}

// closeAll closes both legs of the tunnel exactly once. err, if non-nil, is
// recorded as runBridge's return value — used for genuine protocol/transport
// failures per the #185 Phase 2 scope's fail-closed requirement ("any error
// in the bridge... must terminate the tunnel, never fall back to opaque
// proxying"). A nil err (the normal path, via runBridge's deferred call)
// just performs cleanup after a graceful end.
func (b *bridge) closeAll(err error) {
	b.closeOnce.Do(func() {
		b.closeErr = err
		if b.clientLeg != nil {
			_ = b.clientLeg.Close()
		}
		_ = b.legs.clientConn.Close()
		_ = b.legs.serverConn.Close()
	})
}

// handleStream is the http.Handler golang.org/x/net/http2.Server invokes
// once per HTTP/2 stream on the server leg — one *http.Request per gRPC
// call, per the #185 synthesis's chosen bridging granularity (see
// registry.go's package doc). It classifies the call's fully-qualified
// method through the Phase 1 registry, then — for a Mediate or Passthrough
// category — checks whether this request's Policy actually turned that
// category on (Policy.Allowed; see its doc comment for why this is a
// separate, necessary gate). Only a call that clears BOTH checks is relayed,
// byte-for-byte, to the client leg; Phase 2 does not decode either
// disposition's message content differently (per-message mediation is
// Phases 3-5).
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
			// The method's CATEGORY is eligible for mediation (Classify), but
			// this operator's policy never turned it on (Policy.Allowed) —
			// see policy.go's Allowed doc comment for why this is a separate,
			// necessary gate rather than duplicate denial.
			writeGRPCStatus(w, grpcCodePermissionDenied, fmt.Sprintf("%s/%s is not enabled by this profile's request_body.buildkit policy", service, method))
			b.audit(service, method, Deny, "buildkit_policy_denied")
			b.recordDeniedAndMaybeClose()
			return
		}
		b.audit(service, method, disposition, "")
		b.forward(w, r, service, method)
	default:
		// Deny, and (defensively) anything Classify might ever return that
		// isn't Mediate/Passthrough — fail closed rather than assume a new
		// Disposition value is safe to forward.
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
// decode/re-encode on this path (Phase 2 scope). A genuine RoundTrip/
// transport failure tears the whole tunnel down (fail-closed); a size-cap
// trip on either direction ends only this stream with a RESOURCE_EXHAUSTED
// gRPC status, since an oversized single message is a per-RPC condition, not
// evidence the connection itself is compromised.
func (b *bridge) forward(w http.ResponseWriter, r *http.Request, service, method string) {
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

	resp, err := b.clientLeg.RoundTrip(outReq)
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

// audit emits the #185 synthesis's buildkit_rpc audit event: one line per
// gRPC call carried inside the mediated tunnel. reasonCode is empty for an
// admitted (Mediate/Passthrough) call — only denials and errors carry one of
// the synthesis's low-cardinality reason codes. Never logs message content,
// credentials, or secret/SSH identifiers — this event carries only method
// identity and the routing decision.
func (b *bridge) audit(service, method string, disposition Disposition, reasonCode string) {
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
// returning errMessageTooLarge once exceeded rather than silently
// truncating. A limit <= 0 disables the cap (returns r unchanged).
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
	if l.remaining <= 0 {
		return 0, errMessageTooLarge
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.r.Close()
}
