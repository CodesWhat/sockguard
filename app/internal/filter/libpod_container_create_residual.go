package filter

// libpod_container_create_residual.go holds the gates for the SpecGenerator
// fields that had none: "unified" and "env_host". Field names and types are
// pinned against Podman pkg/specgen/specgen.go (v5.8.1, checked against 6.1).
//
// Three other fields were reviewed alongside them and need nothing here:
//
//   - "r_limits" (POSIX rlimits) is left ungated. The Docker-compat create
//     gates no HostConfig.Ulimits either, and rlimits only cap the
//     container's own processes against limits the runtime already bounds.
//   - "pod" and "dependencyContainers" name other resources, so they are
//     owner-checked by internal/ownership (libpod.go and
//     libpod_create_references.go) when owner isolation is on. There is
//     nothing for a body inspector to add.

// denyResidualFieldsReason runs the gates in this file.
func (p libpodContainerCreatePolicy) denyResidualFieldsReason(req libpodContainerCreateRequest) string {
	if reason := p.denyUnifiedCgroupReason(req.Unified); reason != "" {
		return reason
	}
	return p.denyEnvHostReason(req.EnvHost)
}

// denyUnifiedCgroupReason refuses a non-empty "unified" map unless
// allowUnifiedCgroupSettings is set. Podman writes each entry as a raw
// cgroup v2 control file value (CgroupConf), so it can lift limits the other
// resource gates look for in resource_limits. Docker-compat has no analog.
func (p libpodContainerCreatePolicy) denyUnifiedCgroupReason(unified map[string]string) string {
	if p.allowUnifiedCgroupSettings || len(unified) == 0 {
		return ""
	}
	return "libpod container create denied: raw cgroup v2 settings (unified) are not allowed (set allow_unified_cgroup_settings: true)"
}

// denyEnvHostReason refuses "env_host": true unless allowEnvHost is set.
// It copies the daemon's own environment into the container, which can hold
// credentials the caller never named, and no allowed_env_vars check sees it.
// While an environment restriction is configured the launch policy already
// refuses env_host whatever this option says. The Docker-compat create has
// no analog, because its Env is only what the body lists.
func (p libpodContainerCreatePolicy) denyEnvHostReason(envHost bool) string {
	if p.allowEnvHost || !envHost {
		return ""
	}
	return "libpod container create denied: inheriting the host environment (env_host) is not allowed (set allow_env_host: true)"
}
