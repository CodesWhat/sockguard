package buildkitproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/auth"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/secrets"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/sshforward"
)

// sessionAuthPolicy admits Auth/Secrets/SSH with a fixed, realistic set of
// allowlist entries every test in this file reuses.
var sessionAuthPolicy = Policy{
	Session: SessionPolicy{
		Auth: AuthPolicy{
			Allow:             true,
			AllowedRegistries: []string{"registry-1.docker.io"},
			AllowedRealms:     []string{"https://auth.docker.io/token"},
			AllowedScopes:     []string{"repository:library/alpine:pull"},
		},
		Secrets: SecretsPolicy{Allow: true, AllowedIDs: []string{"my-secret"}},
		SSH:     SSHPolicy{Allow: true, AllowedIDs: []string{"default"}},
	},
}

// syncLogBuffer is a mutex-guarded bytes.Buffer for capturing slog output
// written from the bridge's handler goroutines while the test goroutine
// reads it — a bare bytes.Buffer would be a data race under -race.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestBridgeSessionMediatedAuth covers forwardAuthMediated end to end
// through a live bridge for all four moby.filesync.v1.Auth RPCs: framing/
// decode failures, policy denials, and the admitted case's byte-verbatim
// forward. Every denial case also asserts the daemon (here, the Docker
// client's session server standing in for EndpointSession's reversed roles)
// was never invoked.
func TestBridgeSessionMediatedAuth(t *testing.T) {
	const credentialsPath = "/moby.filesync.v1.Auth/Credentials"

	t.Run("malformed framing", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, credentialsPath, "not a valid gRPC frame"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeInvalidArgument {
			t.Fatalf("Grpc-Status = %d, want %d (INVALID_ARGUMENT)", code, grpcCodeInvalidArgument)
		}
		if daemonCalled.Load() {
			t.Fatal("malformed framing reached the client-leg session server")
		}
	})

	t.Run("message exceeds size cap", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		limits := DefaultLimits()
		limits.MaxMessageBytes = 4
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, limits, daemon)

		payload := mustMarshal(t, &auth.CredentialsRequest{Host: "registry-1.docker.io"})
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, credentialsPath, string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeResourceExhausted {
			t.Fatalf("Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", code, grpcCodeResourceExhausted)
		}
		if daemonCalled.Load() {
			t.Fatal("an oversized message reached the client-leg session server")
		}
	})

	t.Run("unknown fields", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		req := &auth.CredentialsRequest{Host: "registry-1.docker.io"}
		req.ProtoReflect().SetUnknown(unknownFieldBytes())
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, credentialsPath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeFailedPrecondition {
			t.Fatalf("Grpc-Status = %d, want %d (FAILED_PRECONDITION)", code, grpcCodeFailedPrecondition)
		}
		if daemonCalled.Load() {
			t.Fatal("a message with unknown fields reached the client-leg session server")
		}
	})

	t.Run("Credentials host not allowed", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, credentialsPath, &auth.CredentialsRequest{Host: "evil.example.com"}))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, msg := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
		}
		if strings.Contains(msg, "evil.example.com") {
			t.Fatalf("Grpc-Message %q echoes the denied host — must be a fixed message", msg)
		}
		if daemonCalled.Load() {
			t.Fatal("Credentials for a disallowed host reached the client-leg session server")
		}
	})

	t.Run("Credentials admitted forwards the exact frame", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())

		payload := mustMarshal(t, &auth.CredentialsRequest{Host: "registry-1.docker.io"})
		frame := grpcFrame(payload)
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, credentialsPath, string(frame)))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		if string(body) != string(frame) {
			t.Fatal("response body does not match the original frame verbatim (no re-encoding expected)")
		}
	})

	t.Run("admitted host with trailing whitespace audits the normalized host", func(t *testing.T) {
		// Regression: normalizeAuthHost trims surrounding whitespace before
		// the allowlist comparison, so "registry-1.docker.io\n" is admitted —
		// the audit event must carry the NORMALIZED host, not the raw field,
		// or the trailing CR/LF would forge audit log lines.
		logs := &syncLogBuffer{}
		logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		tb := newTestBridgeWithLogger(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler(), logger)

		payload := mustMarshal(t, &auth.CredentialsRequest{Host: "registry-1.docker.io\n"})
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, credentialsPath, string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (whitespace-padded allowed host should be admitted)", resp.StatusCode)
		}
		out := logs.String()
		if !strings.Contains(out, "registry_host=registry-1.docker.io") {
			t.Fatalf("audit log missing normalized registry_host attr:\n%s", out)
		}
		// slog's text handler quotes a value containing a newline as
		// "registry-1.docker.io\n" — its presence would mean the raw
		// client-supplied field leaked into the audit log.
		if strings.Contains(out, `"registry-1.docker.io\n"`) {
			t.Fatalf("audit log carries the raw un-normalized host:\n%s", out)
		}
	})

	t.Run("GetTokenAuthority admitted", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		req := &auth.GetTokenAuthorityRequest{Host: "registry-1.docker.io", Salt: []byte("s")}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.filesync.v1.Auth/GetTokenAuthority", req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("VerifyTokenAuthority denied host", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)
		req := &auth.VerifyTokenAuthorityRequest{Host: "evil.example.com", Payload: []byte("p"), Salt: []byte("s")}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.filesync.v1.Auth/VerifyTokenAuthority", req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
		if daemonCalled.Load() {
			t.Fatal("VerifyTokenAuthority for a disallowed host reached the client-leg session server")
		}
	})

	t.Run("FetchToken realm not allowed", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		req := &auth.FetchTokenRequest{Host: "registry-1.docker.io", Realm: "https://evil.example.com/token"}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.filesync.v1.Auth/FetchToken", req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
	})

	t.Run("VerifyTokenAuthority admitted", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		req := &auth.VerifyTokenAuthorityRequest{Host: "registry-1.docker.io", Payload: []byte("p"), Salt: []byte("s")}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.filesync.v1.Auth/VerifyTokenAuthority", req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("FetchToken admitted", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		req := &auth.FetchTokenRequest{
			Host: "registry-1.docker.io", Realm: "https://auth.docker.io/token",
			Scopes: []string{"repository:library/alpine:pull"},
		}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, "/moby.filesync.v1.Auth/FetchToken", req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}

// TestBridgeSessionMediatedSecrets covers forwardSecretsMediated end to end:
// framing failures, the annotations denial, ID allowlist denial, and the
// admitted byte-verbatim forward.
func TestBridgeSessionMediatedSecrets(t *testing.T) {
	const getSecretPath = "/moby.buildkit.secrets.v1.Secrets/GetSecret"

	t.Run("malformed framing", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, getSecretPath, "not a valid gRPC frame"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeInvalidArgument {
			t.Fatalf("Grpc-Status = %d, want %d (INVALID_ARGUMENT)", code, grpcCodeInvalidArgument)
		}
		if daemonCalled.Load() {
			t.Fatal("malformed framing reached the client-leg session server")
		}
	})

	t.Run("non-empty annotations denied", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		req := &secrets.GetSecretRequest{ID: "my-secret", Annotations: map[string]string{"a": "b"}}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, getSecretPath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
		if daemonCalled.Load() {
			t.Fatal("a GetSecret with annotations reached the client-leg session server")
		}
	})

	t.Run("ID not on allowlist", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		req := &secrets.GetSecretRequest{ID: "other-secret"}
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, getSecretPath, req))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, msg := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
		if strings.Contains(msg, "other-secret") {
			t.Fatalf("Grpc-Message %q echoes the denied secret ID — must be a fixed message", msg)
		}
	})

	t.Run("admitted forwards the exact frame", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		payload := mustMarshal(t, &secrets.GetSecretRequest{ID: "my-secret"})
		frame := grpcFrame(payload)
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, getSecretPath, string(frame)))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		if string(body) != string(frame) {
			t.Fatal("response body does not match the original frame verbatim")
		}
	})
}

// TestBridgeSessionMediatedSSHCheckAgent covers forwardCheckAgent end to
// end: ID allowlist denial and the admitted byte-verbatim forward.
func TestBridgeSessionMediatedSSHCheckAgent(t *testing.T) {
	const checkAgentPath = "/moby.sshforward.v1.SSH/CheckAgent"

	t.Run("malformed framing", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, checkAgentPath, "not a valid gRPC frame"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeInvalidArgument {
			t.Fatalf("Grpc-Status = %d, want %d (INVALID_ARGUMENT)", code, grpcCodeInvalidArgument)
		}
		if daemonCalled.Load() {
			t.Fatal("malformed framing reached the client-leg session server")
		}
	})

	t.Run("ID not on allowlist", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, checkAgentPath, &sshforward.CheckAgentRequest{ID: "not-listed"}))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
		if daemonCalled.Load() {
			t.Fatal("CheckAgent for a disallowed ID reached the client-leg session server")
		}
	})

	t.Run("admitted forwards the exact frame", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())
		payload := mustMarshal(t, &sshforward.CheckAgentRequest{ID: "default"})
		frame := grpcFrame(payload)
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, checkAgentPath, string(frame)))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		if string(body) != string(frame) {
			t.Fatal("response body does not match the original frame verbatim")
		}
	})
}

// TestBridgeSessionMediatedSSHForwardAgent covers forwardSSHAgentStream end
// to end: missing/malformed metadata, an ID the policy denies, and the
// admitted case relaying the raw byte stream verbatim with no framing at
// all (unlike every other RPC in this file, ForwardAgent's body is NOT a
// gRPC length-prefixed message).
func TestBridgeSessionMediatedSSHForwardAgent(t *testing.T) {
	const forwardAgentPath = "/moby.sshforward.v1.SSH/ForwardAgent"

	newForwardAgentRequest := func(t *testing.T, body string, ids ...string) *http.Request {
		t.Helper()
		req := newGRPCRequest(t, forwardAgentPath, body)
		for _, id := range ids {
			req.Header.Add(sshForwardAgentIDMetadataKey, id)
		}
		return req
	}

	t.Run("missing agent ID metadata", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newForwardAgentRequest(t, "opaque-ssh-bytes"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeInvalidArgument {
			t.Fatalf("Grpc-Status = %d, want %d (INVALID_ARGUMENT)", code, grpcCodeInvalidArgument)
		}
		if daemonCalled.Load() {
			t.Fatal("ForwardAgent with no ID metadata reached the client-leg session server")
		}
	})

	t.Run("ID not on allowlist", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), daemon)

		resp, err := tb.driver.RoundTrip(newForwardAgentRequest(t, "opaque-ssh-bytes", "not-listed"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodePermissionDenied {
			t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED)", code, grpcCodePermissionDenied)
		}
		if daemonCalled.Load() {
			t.Fatal("ForwardAgent for a disallowed ID reached the client-leg session server")
		}
	})

	t.Run("admitted relays the raw byte stream verbatim", func(t *testing.T) {
		tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, DefaultLimits(), echoDaemonHandler())

		const opaqueBytes = "this-looks-nothing-like-a-gRPC-frame-and-that-is-the-point"
		resp, err := tb.driver.RoundTrip(newForwardAgentRequest(t, opaqueBytes, "default"))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading response body: %v", err)
		}
		if string(body) != opaqueBytes {
			t.Fatalf("response body = %q, want the exact opaque bytes relayed with no framing/decoding", body)
		}
	})
}

// TestBridgeCredentialCallQuota confirms Limits.MaxCredentialCallsPerSession
// trips RESOURCE_EXHAUSTED once exceeded, and that a quota trip does NOT
// count against the connection-wide denied-stream abuse budget: a low
// DeniedStreamBudget survives several quota trips without the tunnel
// closing, proven by a subsequent unrelated Mediate call still succeeding.
func TestBridgeCredentialCallQuota(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCredentialCallsPerSession = 1
	limits.DeniedStreamBudget = 1
	tb := newTestBridge(t, EndpointSession, sessionAuthPolicy, limits, echoDaemonHandler())

	checkAgent := func() *http.Response {
		payload := mustMarshal(t, &sshforward.CheckAgentRequest{ID: "default"})
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.sshforward.v1.SSH/CheckAgent", string(grpcFrame(payload))))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		return resp
	}

	// First call consumes the quota (admitted: ID is on the allowlist).
	resp1 := checkAgent()
	if _, _ = io.Copy(io.Discard, resp1.Body); resp1.StatusCode != http.StatusOK {
		t.Fatalf("first CheckAgent status = %d, want 200", resp1.StatusCode)
	}
	_ = resp1.Body.Close()

	// Next several calls trip the quota, not the policy — RESOURCE_EXHAUSTED
	// with the dedicated reason, repeatedly, without the tunnel closing even
	// though DeniedStreamBudget is 1.
	for i := 0; i < 3; i++ {
		resp := checkAgent()
		code, _ := grpcStatusOf(t, resp)
		if code != grpcCodeResourceExhausted {
			t.Fatalf("call %d: Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", i, code, grpcCodeResourceExhausted)
		}
	}

	// The tunnel must still be alive: an unrelated Mediate/Passthrough call
	// (not subject to the credential-call quota) still gets a normal
	// response instead of a connection-closed error.
	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.FileSync/DiffCopy", "irrelevant-body"))
	if err != nil {
		t.Fatalf("RoundTrip after quota trips: %v (tunnel should still be open — quota trips must not spend the denied-stream abuse budget)", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestAdmitCredentialCallDisabled confirms a zero/negative
// MaxCredentialCallsPerSession disables the quota entirely.
func TestAdmitCredentialCallDisabled(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCredentialCallsPerSession = 0
	b := &bridge{limits: limits}

	for i := 0; i < 5; i++ {
		if !b.admitCredentialCall() {
			t.Fatalf("admitCredentialCall() = false on call %d, want true (quota disabled)", i)
		}
	}
}

// TestForwardSessionMediatedUnknownServiceFailsClosed exercises
// forwardSessionMediated's defensive switch default directly, mirroring
// TestForwardControlMediatedUnknownMethodFailsClosed: a service
// isSessionMediatedMethod would never actually route here in production
// proves the fallback fails CLOSED (Internal status, audited) rather than
// forwarding with zero policy evaluation if the two ever drift.
func TestForwardSessionMediatedUnknownServiceFailsClosed(t *testing.T) {
	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointSession, "")
	limits := DefaultLimits()
	b := &bridge{
		legs:     bridgeLegs{endpoint: EndpointSession},
		session:  session,
		policy:   sessionAuthPolicy,
		limits:   limits,
		logger:   noopLogger(),
		guard:    newStreamAbuseGuard(limits),
		registry: registry,
	}

	req := newGRPCRequest(t, "/moby.buildkit.v1.frontend.LLBBridge/Ping", "")
	rec := httptest.NewRecorder()

	b.forwardSessionMediated(rec, req, "moby.buildkit.v1.frontend.LLBBridge", "Ping")

	code, msg := grpcStatusOf(t, rec.Result())
	if code != grpcCodeInternal {
		t.Fatalf("Grpc-Status = %d, want %d (Internal)", code, grpcCodeInternal)
	}
	if msg == "" {
		t.Fatal("Grpc-Message is empty, want a fixed denial message")
	}
}

// TestForwardAuthMediatedUnknownMethodFailsClosed exercises
// forwardAuthMediated's defensive switch default directly.
func TestForwardAuthMediatedUnknownMethodFailsClosed(t *testing.T) {
	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointSession, "")
	limits := DefaultLimits()
	b := &bridge{
		legs:     bridgeLegs{endpoint: EndpointSession},
		session:  session,
		policy:   sessionAuthPolicy,
		limits:   limits,
		logger:   noopLogger(),
		guard:    newStreamAbuseGuard(limits),
		registry: registry,
	}

	req := newGRPCRequest(t, "/moby.filesync.v1.Auth/SomeFutureMethod", string(grpcFrame(nil)))
	rec := httptest.NewRecorder()

	b.forwardAuthMediated(rec, req, "moby.filesync.v1.Auth", "SomeFutureMethod")

	code, msg := grpcStatusOf(t, rec.Result())
	if code != grpcCodeInternal {
		t.Fatalf("Grpc-Status = %d, want %d (Internal)", code, grpcCodeInternal)
	}
	if msg == "" {
		t.Fatal("Grpc-Message is empty, want a fixed denial message")
	}
}

// TestForwardSSHMediatedUnknownMethodFailsClosed exercises
// forwardSSHMediated's defensive switch default directly.
func TestForwardSSHMediatedUnknownMethodFailsClosed(t *testing.T) {
	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "c", Profile: "p"}, EndpointSession, "")
	limits := DefaultLimits()
	b := &bridge{
		legs:     bridgeLegs{endpoint: EndpointSession},
		session:  session,
		policy:   sessionAuthPolicy,
		limits:   limits,
		logger:   noopLogger(),
		guard:    newStreamAbuseGuard(limits),
		registry: registry,
	}

	req := newGRPCRequest(t, "/moby.sshforward.v1.SSH/SomeFutureMethod", "")
	rec := httptest.NewRecorder()

	b.forwardSSHMediated(rec, req, "moby.sshforward.v1.SSH", "SomeFutureMethod")

	code, msg := grpcStatusOf(t, rec.Result())
	if code != grpcCodeInternal {
		t.Fatalf("Grpc-Status = %d, want %d (Internal)", code, grpcCodeInternal)
	}
	if msg == "" {
		t.Fatal("Grpc-Message is empty, want a fixed denial message")
	}
}

// TestIsSessionMediatedMethod pins the exact method set Phase 4 routes
// through forwardSessionMediated, and confirms EndpointGRPC and
// FileSync/FileSend/Upload (Phase 5's scope) are excluded.
func TestIsSessionMediatedMethod(t *testing.T) {
	cases := []struct {
		endpoint Endpoint
		service  string
		method   string
		want     bool
	}{
		{EndpointSession, "moby.filesync.v1.Auth", "Credentials", true},
		{EndpointSession, "moby.filesync.v1.Auth", "FetchToken", true},
		{EndpointSession, "moby.filesync.v1.Auth", "GetTokenAuthority", true},
		{EndpointSession, "moby.filesync.v1.Auth", "VerifyTokenAuthority", true},
		{EndpointSession, "moby.filesync.v1.Auth", "SomeFutureMethod", false},
		{EndpointSession, "moby.buildkit.secrets.v1.Secrets", "GetSecret", true},
		{EndpointSession, "moby.buildkit.secrets.v1.Secrets", "SomeFutureMethod", false},
		{EndpointSession, "moby.sshforward.v1.SSH", "CheckAgent", true},
		{EndpointSession, "moby.sshforward.v1.SSH", "ForwardAgent", true},
		{EndpointSession, "moby.sshforward.v1.SSH", "SomeFutureMethod", false},
		{EndpointSession, "moby.filesync.v1.FileSync", "DiffCopy", false},
		{EndpointSession, "moby.filesync.v1.FileSend", "DiffCopy", false},
		{EndpointSession, "moby.upload.v1.Upload", "Pull", false},
		{EndpointGRPC, "moby.filesync.v1.Auth", "Credentials", false},
	}

	for _, tc := range cases {
		t.Run(tc.service+"/"+tc.method, func(t *testing.T) {
			if got := isSessionMediatedMethod(tc.endpoint, tc.service, tc.method); got != tc.want {
				t.Fatalf("isSessionMediatedMethod(%v, %q, %q) = %v, want %v", tc.endpoint, tc.service, tc.method, got, tc.want)
			}
		})
	}
}
