// Package buildkitproxy — this file carries Phase 4 (issue #185)'s
// per-message policy decisions for the EndpointSession RPCs buildkitd calls
// BACK into the client for credential material: moby.filesync.v1.Auth's
// four RPCs, moby.buildkit.secrets.v1.Secrets/GetSecret, and
// moby.sshforward.v1.SSH's CheckAgent (SSH's ForwardAgent is a
// bidirectional byte stream with no unary request message to decode — see
// evaluateForwardAgentID below). Each evaluate* function takes an
// already-framed payload (or, for ForwardAgent, the stream's *http.Request)
// and a policy and returns nil (admit) or a *mediationDenial — the same
// pure-decision shape solve.go established for Control/Solve and
// Control/Status, kept free of any http/gRPC-wire concerns so it is unit
// testable without a live bridge. bridge_session.go is this file's HTTP-
// orchestration counterpart, mirroring how bridge.go's
// forwardControlMediated calls into solve.go.
//
// Every RPC mediated here either REQUESTS credential material (Auth,
// Secrets) or gates access to it (SSH) — the response side, where the
// actual secret content travels (CredentialsResponse.Secret,
// FetchTokenResponse.Token, GetSecretResponse.data, and the raw SSH agent
// protocol bytes ForwardAgent relays), is NEVER decoded on any of these
// paths: only the request identifies what is being asked for, and only the
// request is what policy has an opinion about. Per CLAUDE.md's "never log
// secret contents" constraint, nothing in this file ever reads a response
// body, and the identifiers it does examine (secret IDs, SSH agent IDs) are
// only ever surfaced to audit logs through shortHash, never raw.
package buildkitproxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/auth"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/secrets"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/sshforward"
)

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
