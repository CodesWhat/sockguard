// Package buildkitproxy holds the policy foundation for sockguard's
// BuildKit gRPC mediation (issue #185): a method-classification registry
// (this file) and the Policy type request_body.buildkit config translates
// into (see policy.go). Phase 1 intentionally ships no transport code — no
// h2c termination, no per-stream decode/re-encode — so nothing in this
// package changes how any request is actually proxied yet. Later phases
// wire a real h2c-terminating mediator that consults Classify before
// deciding whether to decode, forward, or reject a given RPC.
//
// This package must never import grpc-go or anything from
// app/internal/buildkitproto's generated code that would require it: the
// #185 sign-off's dependency exception is golang.org/x/net/http2 (phase 2)
// and google.golang.org/protobuf (buildkitproto), nothing else, and this
// package's job — classifying a (endpoint, service, method) triple — needs
// neither.
package buildkitproxy

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
	// content, but are still size-capped.
	//
	// This used to promise that "a rewritten/filtered response (e.g.
	// Info/ListWorkers advertising only the permitted method set) is
	// possible without a full mediation path" because Passthrough methods
	// are "typed". That was wrong on both halves. InfoResponse,
	// ListWorkersResponse and WorkerRecord are exactly the message types
	// buildkitproto's control.proto trim left UNVENDORED (PROVENANCE.md),
	// precisely because these two RPCs were Passthrough — so they were never
	// typed here at all. And rewriting a response IS a policy decision on
	// message content, which is what this disposition is defined as not
	// making. Both methods are Mediate below now, and controlinfo.go filters
	// their responses on protobuf wire bytes; the only methods left on this
	// disposition are the gRPC health checks, whose response carries a
	// serving status and nothing about the host.
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
	// moby.buildkit.v1.Control (EndpointGRPC, POST /grpc).
	{EndpointGRPC, "moby.buildkit.v1.Control", "Solve"}:  Mediate,
	{EndpointGRPC, "moby.buildkit.v1.Control", "Status"}: Mediate,
	// Info and ListWorkers are Mediate on their RESPONSE only: their
	// requests carry nothing policy-relevant (InfoRequest is empty,
	// ListWorkersRequest carries a client-chosen worker filter) and are
	// forwarded byte-for-byte, but the daemon's reply describes the host
	// rather than the caller and is rewritten against a field allowlist
	// before the client sees it — see controlinfo.go.
	{EndpointGRPC, "moby.buildkit.v1.Control", "Info"}:        Mediate,
	{EndpointGRPC, "moby.buildkit.v1.Control", "ListWorkers"}: Mediate,

	// grpc.health.v1.Health, served locally per the synthesis ("gRPC
	// health, advertising only the rewritten permitted method set") —
	// reached over the same POST /grpc tunnel as Control.
	{EndpointGRPC, "grpc.health.v1.Health", "Check"}: Passthrough,
	{EndpointGRPC, "grpc.health.v1.Health", "Watch"}: Passthrough,

	// moby.filesync.v1.Auth (EndpointSession, POST /session): registry/
	// realm/scope allowlists gate every method — "Auth/*" in the synthesis.
	{EndpointSession, "moby.filesync.v1.Auth", "Credentials"}:          Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "FetchToken"}:           Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "GetTokenAuthority"}:    Mediate,
	{EndpointSession, "moby.filesync.v1.Auth", "VerifyTokenAuthority"}: Mediate,

	// moby.buildkit.secrets.v1.Secrets (EndpointSession): exact secret-ID
	// allowlist.
	{EndpointSession, "moby.buildkit.secrets.v1.Secrets", "GetSecret"}: Mediate,

	// moby.sshforward.v1.SSH (EndpointSession): exact SSH-ID allowlist —
	// "SSH/{CheckAgent,ForwardAgent}" in the synthesis.
	{EndpointSession, "moby.sshforward.v1.SSH", "CheckAgent"}:   Mediate,
	{EndpointSession, "moby.sshforward.v1.SSH", "ForwardAgent"}: Mediate,

	// moby.filesync.v1.FileSync/FileSend (EndpointSession): fsutil packet
	// validation, path/file/byte caps, Dockerfile hold-and-inspect.
	// FileSync.TarStream is NOT listed — it is Deny-by-default, see
	// DeniedExamples.
	{EndpointSession, "moby.filesync.v1.FileSync", "DiffCopy"}: Mediate,
	{EndpointSession, "moby.filesync.v1.FileSend", "DiffCopy"}: Mediate,

	// moby.upload.v1.Upload (EndpointSession): one-use token bound to an
	// admitted stdin context — "Upload/Pull" in the synthesis.
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

// ServiceAdmittedByPolicy reports whether service has at least one method
// registered under endpoint that is BOTH non-Deny per Classify AND allowed by
// p (Policy.Allowed). A service can carry a Mediate/Passthrough method the
// registry admits in principle that this operator's policy still leaves off
// (see Policy.Allowed's doc comment on why Classify and Allowed are separate,
// necessary gates). A session advertisement rewrite must never keep such a
// service and invite a daemon callback the bridge only rejects after the fact.
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
	// moby.buildkit.v1.frontend.LLBBridge — every method, per "LLBBridge/*".
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

	// Nested Control/Session and the rest of the Control service the
	// synthesis names explicitly.
	{EndpointGRPC, "moby.buildkit.v1.Control", "Session"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "Prune"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "DiskUsage"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "ListenBuildHistory"},
	{EndpointGRPC, "moby.buildkit.v1.Control", "UpdateBuildHistory"},

	// containerd's content-store service, exposed to a build's LLB
	// executor context in some configurations — method names are the
	// stable, well-known containerd.services.content.v1.Content RPCs.
	{EndpointGRPC, "containerd.services.content.v1.Content", "Info"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Update"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "List"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Delete"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Read"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Write"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Status"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "ListStatuses"},
	{EndpointGRPC, "containerd.services.content.v1.Content", "Abort"},

	// OTLP trace export.
	{EndpointGRPC, "opentelemetry.proto.collector.trace.v1.TraceService", "Export"},

	// Exporter negotiation.
	{EndpointSession, "moby.exporter.v1.Exporter", "FindExporters"},
	{EndpointSession, "moby.exporter.v1.Exporter", "FinalizeExport"},

	// Source-policy verifier.
	{EndpointSession, "moby.buildkit.v1.sourcepolicy.policysession.PolicyVerifier", "CheckPolicy"},

	// FileSync/TarStream specifically (FileSync/DiffCopy is Mediate; see
	// registry above).
	{EndpointSession, "moby.filesync.v1.FileSync", "TarStream"},
}
