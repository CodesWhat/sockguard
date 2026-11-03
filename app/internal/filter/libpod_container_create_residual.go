package filter

import "strings"

// libpod_container_create_residual.go holds the gates for the SpecGenerator
// fields that had none: "unified" and "env_host". Field names and types are
// pinned against Podman pkg/specgen/specgen.go (v5.8.1, checked against 6.1).
//
// Three other fields were reviewed alongside them and need nothing here:
//
//   - "r_limits" (POSIX rlimits) is left ungated. The Docker-compat create
//     gates no HostConfig.Ulimits either, and rlimits only cap the
//     container's own processes against limits the runtime already bounds.
//   - "dependencyContainers" only orders startup, so it is left ungated here.
//     When owner isolation is enabled, internal/ownership owner-checks it
//     (libpod_create_references.go).
//   - "pod" joins the pod's infra namespaces, so denyPodJoinReason holds it to
//     restrictNamespaceSharing, the same switch that governs container:<ref>
//     namespace joins. When owner isolation is enabled it is also owner-checked
//     (libpod.go).

// denyResidualFieldsReason runs the gates in this file.
func (p libpodContainerCreatePolicy) denyResidualFieldsReason(req libpodContainerCreateRequest) string {
	if reason := p.denyUnifiedCgroupReason(req.Unified); reason != "" {
		return reason
	}
	if reason := p.denyPodJoinReason(req.Pod); reason != "" {
		return reason
	}
	return p.denyEnvHostReason(req.EnvHost)
}

// denyPodJoinReason refuses a non-empty "pod" while restrictNamespaceSharing
// is on. Joining a pod shares its infra container's namespaces, which is the
// same exposure as a {"nsmode":"container"} join, and a pod name can't be
// vouched for by allowedNamespaceSharingContainers, which lists containers.
// With the option off it passes, as container joins do.
func (p libpodContainerCreatePolicy) denyPodJoinReason(pod string) string {
	if !p.restrictNamespaceSharing || strings.TrimSpace(pod) == "" {
		return ""
	}
	return "libpod container create denied: joining a pod is not allowed while namespace sharing is restricted"
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
