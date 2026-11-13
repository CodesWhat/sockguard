package filter

import (
	"fmt"
	"slices"
	"strings"
)

// libpod_container_create_residual.go holds the gates for the SpecGenerator
// fields that had none: "unified", "env_host", "storage_opts" and the
// run.oci.* keys of "annotations". Field names and types are
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
	if reason := p.denyStorageOptsReason(req.StorageOpts); reason != "" {
		return reason
	}
	if reason := p.denyRuntimeAnnotationsReason(req.Annotations); reason != "" {
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

// denyStorageOptsReason refuses a non-empty "storage_opts" map unless
// allowStorageOpts is set. Podman hands it to the container's storage as
// written (WithStorageOpts, pkg/specgen/generate/container_create.go:530-531),
// where it sets per-container driver options such as the rootfs size quota,
// which the operator's containers.conf default would otherwise decide. The
// Docker-compat create has no inspected analog (HostConfig.StorageOpt is
// forwarded as is), so this is native-only.
func (p libpodContainerCreatePolicy) denyStorageOptsReason(storageOpts map[string]string) string {
	if p.allowStorageOpts || len(storageOpts) == 0 {
		return ""
	}
	return "libpod container create denied: storage_opts is not allowed (set allow_storage_opts: true)"
}

// runtimeAnnotationPrefix is the annotation namespace that changes what the
// container runs with. SpecGenerator.Annotations is "key-value options passed
// into the container runtime that can be used to trigger special behavior"
// (pkg/specgen/specgen.go:74-77): crun reads its behavior switches from
// run.oci.* (keep_original_groups, handler, systemd.force_cgroup_v1, and the
// like). Any other key is plain metadata and passes.
//
// Most of io.podman.annotations.* is deliberately not gated (podmanActedAnnotations
// holds the exceptions). Podman writes those keys
// itself as descriptive markers of options the create already carries
// (userns, pids-limit, seccomp, apparmor, label, init, autoremove, ...) and
// reads them back for inspect, and podman-remote sends them on ordinary
// creates (testdata/libpod/idmappings.json, resource_limits.json,
// security_opts_seccomp_apparmor_selinux.json). Gating them would refuse
// normal client traffic and add no control: what the container is confined
// with comes from the fields those markers describe, which have their own
// gates.
const runtimeAnnotationPrefix = "run.oci."

// podmanActedAnnotations are the io.podman.annotations.* keys Podman acts on
// instead of only reading back. cid-file names a host path Podman removes
// with os.Remove when the container is removed, and autoremove and
// autoremove-image make Podman remove the container, and its image, when it
// exits. They are refused with the run.oci. keys; the rest of
// io.podman.annotations.* passes.
var podmanActedAnnotations = [...]string{
	"io.podman.annotations.cid-file",
	"io.podman.annotations.autoremove",
	"io.podman.annotations.autoremove-image",
}

// denyRuntimeAnnotationsReason refuses an annotation key under
// runtimeAnnotationPrefix unless allowRuntimeAnnotations is set. The
// prefix is matched in any letter case, so a spelling the runtime would not
// act on is refused too. Keys are checked in sorted order so the reason is
// stable.
func (p libpodContainerCreatePolicy) denyRuntimeAnnotationsReason(annotations map[string]string) string {
	if p.allowRuntimeAnnotations || len(annotations) == 0 {
		return ""
	}
	keys := make([]string, 0, len(annotations))
	for key := range annotations {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		folded := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(folded, runtimeAnnotationPrefix) || slices.Contains(podmanActedAnnotations[:], folded) {
			return fmt.Sprintf("libpod container create denied: runtime annotation %q is not allowed (set allow_runtime_annotations: true)", key)
		}
	}
	return ""
}
