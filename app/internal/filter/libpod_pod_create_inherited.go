package filter

import (
	"strings"
)

// libpod_pod_create_inherited.go holds the pod create gates for the fields
// Podman copies onto the pod's infra container and that the pod's members then
// inherit: mounts, pod_devices, security_opt and sysctl, plus a namespace
// joined by container reference. Without them a rule that allows
// POST /libpod/pods/create got around the container block's
// allowed_bind_mounts, allowed_devices, allow_sysctls, seccomp, AppArmor and
// SELinux gates, because the infra container is built from the pod body and
// never passes through the container create inspector.
//
// Podman references (5.8.6, checked against 6.1): the handler copies the
// pod's Mounts, Devices (JSON "pod_devices"), SecurityOpt and Sysctl onto the
// infra container's spec (pkg/api/handlers/libpod/pods.go:46-47, 60-65;
// pkg/specgen/generate/pod_create.go:280-282), and members inherit the
// infra container's mounts, devices, seccomp, AppArmor, SELinux and
// capabilities (pkg/specgen/generate/container_create.go:717-756,
// libpod/container_config.go:471-488).
//
// Nothing here has its own lists. Each check calls the libpod container
// create policy built from request_body.libpod_container_create, so the pod
// is held to what a container is, and only the subject of the reason is
// rewritten.

// denyInheritedFieldsReason runs the container create gates over the pod's
// inherited fields.
func (p libpodPodCreatePolicy) denyInheritedFieldsReason(req libpodPodCreateRequest) string {
	if reason := p.container.denyBindMountReason(req.Mounts); reason != "" {
		return podCreateReason(reason)
	}
	if len(req.Devices) > 0 {
		devices := make([]libpodDevice, 0, len(req.Devices))
		for _, path := range req.Devices {
			devices = append(devices, libpodDevice{Path: path})
		}
		if reason := p.container.denyDeviceReason(devices); reason != "" {
			return podCreateReason(reason)
		}
	}
	if reason := p.denySecurityOptReason(req.SecurityOpt); reason != "" {
		return podCreateReason(reason)
	}
	if !p.container.allowSysctls && len(req.Sysctl) > 0 {
		return "libpod pod create denied: setting sysctls is not allowed"
	}
	return podCreateReason(p.container.denyNamespaceSharingReason(libpodContainerCreateRequest{
		NetNS:  req.NetNS,
		PidNS:  req.PidNS,
		IpcNS:  req.IpcNS,
		UserNS: req.UserNS,
		UtsNS:  req.UtsNS,
	}))
}

// denySecurityOptReason maps the pod's security_opt strings, the CLI
// --security-opt spelling, onto the container create gates for the fields
// they set: seccomp= onto the seccomp gate, apparmor= onto the AppArmor gate,
// label= onto the SELinux gate and unmask= onto the unconfined system paths
// gate. Podman accepts "key=value" and the older "key:value" for these. An
// entry for any other option (no-new-privileges, proc-opts, ...) is not a
// confinement the container gates cover and passes.
func (p libpodPodCreatePolicy) denySecurityOptReason(opts []string) string {
	for _, opt := range opts {
		key, value, ok := splitSecurityOpt(opt)
		if !ok {
			continue
		}
		switch key {
		case "seccomp":
			if reason := p.container.denySeccompReason(value); reason != "" {
				return reason
			}
		case "apparmor":
			if reason := p.container.denyAppArmorReason(value); reason != "" {
				return reason
			}
		case "label":
			if reason := p.container.denySelinuxReason([]string{value}); reason != "" {
				return reason
			}
		case "unmask":
			if p.container.denyUnconfinedSystemPaths {
				return "libpod container create denied: unmask (systempaths=unconfined equivalent) is not allowed"
			}
		}
	}
	return ""
}

// splitSecurityOpt splits one security_opt entry at the first "=" or ":" and
// returns the lowercased key and the value.
func splitSecurityOpt(opt string) (key, value string, ok bool) {
	i := strings.IndexAny(opt, "=:")
	if i < 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(opt[:i])), strings.TrimSpace(opt[i+1:]), true
}

// podCreateReason re-subjects a container create refusal as a pod create one.
func podCreateReason(reason string) string {
	return strings.Replace(reason, "libpod container create", "libpod pod create", 1)
}
