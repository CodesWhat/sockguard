package config

import "github.com/codeswhat/sockguard/internal/buildkitproxy"

// ToPolicy converts BuildkitRequestBodyConfig into buildkitproxy.Policy,
// mirroring how RequestBodyConfig.ToFilterOptions translates into the filter
// package's options types: buildkitproxy defines the destination type and
// never imports this package back — translation flows one direction only.
//
// Phase 1 has no runtime mediator to hand this Policy to yet (see
// filter.BuildkitOptions's doc comment); ToPolicy exists now so later
// phases translate against a stable, already-reviewed shape, and so
// Policy.Configured can back both cmd/rules.go's startup admission check
// and the mutual-exclusion validation against
// InsecureAcceptOpaqueBuildkitTunnels.
func (c BuildkitRequestBodyConfig) ToPolicy() buildkitproxy.Policy {
	return buildkitproxy.Policy{
		Control: c.Control.toPolicy(),
		Session: c.Session.toPolicy(),
	}
}

func (c BuildkitControlRequestBodyConfig) toPolicy() buildkitproxy.ControlPolicy {
	return buildkitproxy.ControlPolicy{
		AllowInfo:        c.AllowInfo,
		AllowListWorkers: c.AllowListWorkers,
		AllowStatus:      c.AllowStatus,
		Solve:            buildkitproxy.SolvePolicy{Allow: c.Solve.Allow},
	}
}

func (c BuildkitSessionRequestBodyConfig) toPolicy() buildkitproxy.SessionPolicy {
	return buildkitproxy.SessionPolicy{
		Health: c.Health,
		Auth: buildkitproxy.AuthPolicy{
			Allow:             c.Auth.Allow,
			AllowedRegistries: c.Auth.AllowedRegistries,
			AllowedRealms:     c.Auth.AllowedRealms,
			AllowedScopes:     c.Auth.AllowedScopes,
		},
		Secrets: buildkitproxy.SecretsPolicy{
			Allow:      c.Secrets.Allow,
			AllowedIDs: c.Secrets.AllowedIDs,
		},
		SSH: buildkitproxy.SSHPolicy{
			Allow:      c.SSH.Allow,
			AllowedIDs: c.SSH.AllowedIDs,
		},
		FileSync: buildkitproxy.FileSyncPolicy{Allow: c.FileSync.Allow},
		FileSend: buildkitproxy.FileSendPolicy{Allow: c.FileSend.Allow},
		Upload:   buildkitproxy.UploadPolicy{Allow: c.Upload.Allow},
	}
}
