package buildkitproxy

import "reflect"

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

// Configured reports whether p differs from the zero-value Policy — i.e.
// whether request_body.buildkit was set to anything other than every field
// left at its secure (false/empty) default. Because every Buildkit sub-field
// defaults to false or an empty slice (there is no default-true field the
// way e.g. network.endpoint_config.allow_aliases has), a zero-value Policy
// is behaviorally indistinguishable from "the block was never written" —
// both deny everything — so a plain reflect.DeepEqual against the zero
// value is sufficient here without needing #186's Viper-provenance-tracking
// pattern (which exists specifically to handle a default-true field zero
// value could not represent).
func (p Policy) Configured() bool {
	return !reflect.DeepEqual(p, Policy{})
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
// its own.
type SolvePolicy struct {
	Allow bool
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
