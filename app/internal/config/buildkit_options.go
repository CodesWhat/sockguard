package config

import "github.com/codeswhat/sockguard/internal/buildkitproxy"

// ToPolicy converts BuildkitRequestBodyConfig into buildkitproxy.Policy,
// mirroring how RequestBodyConfig.ToFilterOptions translates into the filter
// package's options types: buildkitproxy defines the destination type and
// never imports this package back — translation flows one direction only.
//
// build is the SIBLING request_body.build block (RequestBodyConfig.Build /
// ClientProfileConfig's own RequestBody.Build), threaded through so
// BuildkitSolveRequestBodyConfig.toPolicy can reuse its AllowHostNetwork/
// AllowRemoteContext verbatim into buildkitproxy.SolvePolicy — see
// BuildkitSolveRequestBodyConfig's doc comment for why those two fields are
// not duplicated on this struct. Every call site passes the RequestBodyConfig
// this BuildkitRequestBodyConfig itself came from (never a different scope's
// Build block) so the reused flags stay scoped to the same profile/top-level
// config the Buildkit block itself belongs to.
//
// Phase 1 shipped no runtime mediator to hand this Policy to (see
// filter.BuildkitOptions's doc comment); Phase 3 (issue #185) is the first
// phase whose mediator (bridge.go's forwardControlMediated) actually reads
// SolvePolicy's new fields. Policy.Configured backs both cmd/rules.go's
// startup admission check and the mutual-exclusion validation against
// InsecureAcceptOpaqueBuildkitTunnels.
func (c BuildkitRequestBodyConfig) ToPolicy(build BuildRequestBodyConfig) buildkitproxy.Policy {
	return buildkitproxy.Policy{
		Control: c.Control.toPolicy(build),
		Session: c.Session.toPolicy(),
	}
}

func (c BuildkitControlRequestBodyConfig) toPolicy(build BuildRequestBodyConfig) buildkitproxy.ControlPolicy {
	return buildkitproxy.ControlPolicy{
		AllowInfo:        c.AllowInfo,
		AllowListWorkers: c.AllowListWorkers,
		AllowStatus:      c.AllowStatus,
		Solve:            c.Solve.toPolicy(build),
	}
}

func (c BuildkitSolveRequestBodyConfig) toPolicy(build BuildRequestBodyConfig) buildkitproxy.SolvePolicy {
	return buildkitproxy.SolvePolicy{
		Allow:                     c.Allow,
		AllowHostNetwork:          build.AllowHostNetwork,
		AllowRemoteContext:        build.AllowRemoteContext,
		AllowRunInstructions:      build.AllowRunInstructions,
		AllowedCacheImportTypes:   c.AllowedCacheImportTypes,
		AllowedCacheExportTypes:   c.AllowedCacheExportTypes,
		AllowedCacheRegistries:    normalizeRegistryHostList(c.AllowedCacheRegistries),
		AllowedExporters:          c.AllowedExporters,
		AllowedExporterRegistries: normalizeRegistryHostList(c.AllowedExporterRegistries),
	}
}

// normalizeRegistryHostList normalizes every entry through
// normalizeAllowedRegistryHost so buildkitproxy's runtime registry-host
// comparisons — solve.go's registryHostFromImageRef (which always lowercases
// and canonicalizes the host it extracts from a client-supplied image ref)
// AND, since issue #185 phase 4, session_mediation.go's normalizeAuthHost
// (which applies the identical lowercase/index.docker.io normalization to
// moby.filesync.v1.Auth's bare Host field) — are compared against the SAME
// canonical form an operator's config-side allowlist entries are stored in —
// otherwise "Registry:5000" in config would never match "registry:5000"
// extracted at runtime. This mirrors internal/filter's
// newImagePullPolicy/normalizeRegistryHost precedent for the exact same
// registry-host allowlist shape (buildkitproxy must not import
// internal/filter or vice versa — see registry.go's package doc — so each
// side keeps its own copy of the same normalization rule).
// validateRegistryHostEntries already rejects any entry that fails to
// normalize, so the skip-on-!ok below is only a defensive no-op against
// what should be unreachable in a Validate()-passed Config.
func normalizeRegistryHostList(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if normalized, ok := normalizeAllowedRegistryHost(v); ok {
			out = append(out, normalized)
		}
	}
	return out
}

func (c BuildkitSessionRequestBodyConfig) toPolicy() buildkitproxy.SessionPolicy {
	return buildkitproxy.SessionPolicy{
		Health: c.Health,
		Auth: buildkitproxy.AuthPolicy{
			Allow:             c.Auth.Allow,
			AllowedRegistries: normalizeRegistryHostList(c.Auth.AllowedRegistries),
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
		FileSync: buildkitproxy.FileSyncPolicy{
			Allow:         c.FileSync.Allow,
			MaxFiles:      c.FileSync.MaxFiles,
			MaxTotalBytes: c.FileSync.MaxTotalBytes,
			MaxPathLength: c.FileSync.MaxPathLength,
			MaxFileBytes:  c.FileSync.MaxFileBytes,
		},
		FileSend: buildkitproxy.FileSendPolicy{Allow: c.FileSend.Allow, MaxBytes: c.FileSend.MaxBytes},
		Upload:   buildkitproxy.UploadPolicy{Allow: c.Upload.Allow, MaxBytes: c.Upload.MaxBytes},
	}
}
