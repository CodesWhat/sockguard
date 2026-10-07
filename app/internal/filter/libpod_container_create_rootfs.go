package filter

import (
	"fmt"
)

// libpod_container_create_rootfs.go gates the host-filesystem fields of
// POST /libpod/containers/create that are neither a "mounts" bind entry nor a
// "devices" entry, so denyBindMountReason and denyDeviceReason never saw them:
// rootfs, overlay_volumes sources, init_path and conmon_pid_file. Before these
// gates a create with default options and {"rootfs":"/"} ran a container whose
// root filesystem was the host's /, and {"overlay_volumes":[{"source":"/"}]}
// mounted the host's / inside it, both sidestepping allowed_bind_mounts.
//
// rootfs, every overlay_volumes source, and init_path are host paths the
// container reads or executes, so they're held to the same allowed_bind_mounts
// allowlist bind sources already are (bindPathAllowed), and fail closed: a
// non-empty value that doesn't normalize to an allowlisted absolute path is
// denied, including a relative or otherwise malformed path. conmon_pid_file is
// a host path the daemon writes conmon's PID to, not one the container reads,
// so no allowlist of readable paths fits it; it's refused outright whenever
// it's set.
//
// What Podman 5.8.6 does with each, so the "not a mount" reasoning is checked
// against source rather than assumed:
//
//   - rootfs (ContainerStorageConfig.Rootfs, specgen.go:263) is mounted
//     directly as the container's root with no modification
//     (libpod.WithRootFS at pkg/specgen/generate/container_create.go:159 and
//     616, mounted at libpod/container_internal.go:1750). rootfs_overlay and
//     rootfs_mapping only change how that one path is mounted, so gating rootfs
//     covers them.
//   - overlay_volumes[].source (OverlayVolume.Source, volumes.go:40) is
//     overlay-mounted at the entry's destination (libpod.WithOverlayVolumes at
//     container_create.go:494, mounted at
//     libpod/container_internal_common.go:465-481).
//   - init_path (ContainerStorageConfig.InitPath, specgen.go:291), when the
//     create also sets init, is a host binary bind-mounted read-only at
//     /run/podman-init and run as the container's PID 1
//     (pkg/specgen/generate/storage.go:134 and 387-392). It's gated whenever
//     it's set: Podman ignores it without init, so holding it to the allowlist
//     regardless is strictly fail-closed and never refuses a create init would
//     have let through.
//   - conmon_pid_file (ContainerBasicConfig.ConmonPidFile, specgen.go:105) is
//     written by conmon as the daemon's user (libpod.WithConmonPidFile at
//     container_create.go:602, used at libpod/oci_conmon_common.go:1045),
//     cleared only when it sits under the storage run root
//     (libpod/runtime_ctr.go:104), so an arbitrary host path is kept and
//     written to.

// denyHostPathReason holds rootfs, every overlay_volumes source and init_path
// to allowedBindMounts, and refuses conmon_pid_file outright. It returns the
// first deny reason, or "" when every host-path field is allowed. Malformed
// shapes of these fields fail the single json.Unmarshal in inspect before this
// runs, so they're already denied as malformed.
func (p libpodContainerCreatePolicy) denyHostPathReason(req libpodContainerCreateRequest) string {
	if denyReason := p.denyRootfsReason(req.Rootfs); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyOverlayVolumeReason(req.OverlayVolumes); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyInitPathReason(req.InitPath); denyReason != "" {
		return denyReason
	}
	return p.denyConmonPidFileReason(req.ConmonPidFile)
}

// denyRootfsReason holds a non-empty rootfs to allowedBindMounts. An empty
// rootfs is the image-based create's default and does nothing, so it passes; a
// non-empty one that doesn't normalize to an allowlisted absolute path is
// denied, so a relative or malformed path fails closed.
func (p libpodContainerCreatePolicy) denyRootfsReason(rootfs string) string {
	if rootfs == "" {
		return ""
	}
	if source, ok := normalizeBindMount(rootfs); !ok || !bindPathAllowed(source, p.allowedBindMounts) {
		return fmt.Sprintf("libpod container create denied: rootfs path %q is not allowlisted (add it to allowed_bind_mounts)", rootfs)
	}
	return ""
}

// denyOverlayVolumeReason holds every overlay_volumes source to
// allowedBindMounts. An overlay volume always carries a host-path source
// (Podman builds one only from a host directory), so an empty or otherwise
// non-allowlisted source fails closed.
func (p libpodContainerCreatePolicy) denyOverlayVolumeReason(volumes []libpodOverlayVolume) string {
	for _, volume := range volumes {
		if source, ok := normalizeBindMount(volume.Source); !ok || !bindPathAllowed(source, p.allowedBindMounts) {
			return fmt.Sprintf("libpod container create denied: overlay volume source %q is not allowlisted (add it to allowed_bind_mounts)", volume.Source)
		}
	}
	return ""
}

// denyInitPathReason holds a non-empty init_path to allowedBindMounts, since
// it's a host binary the container runs as PID 1.
func (p libpodContainerCreatePolicy) denyInitPathReason(initPath string) string {
	if initPath == "" {
		return ""
	}
	if source, ok := normalizeBindMount(initPath); !ok || !bindPathAllowed(source, p.allowedBindMounts) {
		return fmt.Sprintf("libpod container create denied: init_path %q is not allowlisted (add it to allowed_bind_mounts)", initPath)
	}
	return ""
}

// denyConmonPidFileReason refuses a non-empty conmon_pid_file. It's a host
// path the daemon writes to rather than one the container reads, so the
// allowed_bind_mounts allowlist doesn't fit it; Podman acts on any non-empty
// value (len > 0), so that's the test here too.
func (p libpodContainerCreatePolicy) denyConmonPidFileReason(pidFile string) string {
	if pidFile == "" {
		return ""
	}
	return "libpod container create denied: setting conmon_pid_file is not allowed"
}
