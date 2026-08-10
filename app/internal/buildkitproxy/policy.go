package buildkitproxy

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
			// Health is served over POST /grpc (registry.go's comment on the
			// grpc.health.v1.Health entries) but its switch lives on
			// SessionPolicy as Health — a Phase 1 struct-shape choice this
			// phase inherits rather than revisits.
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
			// Only DiffCopy is registered Mediate for this service —
			// FileSync/TarStream is a named Deny example (registry.go's
			// DeniedExamples) that must never be admitted even if this
			// function is ever consulted independently of Classify's own
			// Deny short-circuit in bridge.go.
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

// FileSyncPolicy gates moby.filesync.v1.FileSync/DiffCopy.
type FileSyncPolicy struct {
	Allow bool
}

// FileSendPolicy gates moby.filesync.v1.FileSend/DiffCopy.
type FileSendPolicy struct {
	Allow bool
}

// UploadPolicy gates moby.upload.v1.Upload/Pull.
type UploadPolicy struct {
	Allow bool
}
