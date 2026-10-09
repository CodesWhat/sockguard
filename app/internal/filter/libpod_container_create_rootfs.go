package filter

import (
	"fmt"
)

// libpod_container_create_rootfs.go gates the host-filesystem fields of
// POST /libpod/containers/create that are neither a "mounts" bind entry nor a
// "devices" entry, so denyBindMountReason and denyDeviceReason never saw them:
// rootfs, overlay_volumes sources, the overlay upper and work directories an
// overlay_volumes or volumes entry names in its options, init_path and
// conmon_pid_file, and the two log destinations, log_configuration.path and
// healthLogDestination. Before these gates a create with default options and
// {"rootfs":"/"} ran a container whose root filesystem was the host's /, and
// {"overlay_volumes":[{"source":"/"}]} mounted the host's / inside it, both
// sidestepping allowed_bind_mounts.
//
// rootfs, every overlay_volumes source, every overlay upper and work
// directory, and init_path are host paths the container reads, writes or
// executes, so they're held to the same allowed_bind_mounts allowlist bind
// sources already are (bindPathAllowed), and fail closed: a non-empty value
// that doesn't normalize to an allowlisted absolute path is denied, including a
// relative or otherwise malformed path. conmon_pid_file is a host path the
// daemon writes conmon's PID to, not one the container reads, so no allowlist
// of readable paths fits it; it's refused outright whenever it's set. The log
// destinations are host paths the daemon writes too, and they're refused
// unless allow_log_path is on.
//
// What Podman 5.8.6 does with each, so the "not a mount" reasoning is checked
// against source rather than assumed:
//
//   - rootfs (ContainerStorageConfig.Rootfs, specgen.go:263) is mounted
//     directly as the container's root with no modification
//     (libpod.WithRootFS at pkg/specgen/generate/container_create.go:159 and
//     616, mounted at libpod/container_internal.go:1750). rootfs_mapping only
//     changes how that one path is mounted, so gating rootfs covers it.
//     rootfs_overlay does the same and one thing more: it writes the path into
//     an overlay option string as the lowerdir (overlay.Mount at
//     container_internal.go:1792), so a rootfs mounted that way also can't
//     carry an overlay metacharacter. See overlay_mount_options.go.
//   - overlay_volumes[].source (OverlayVolume.Source, volumes.go:40) is
//     overlay-mounted at the entry's destination (libpod.WithOverlayVolumes at
//     container_create.go:494, mounted at
//     libpod/container_internal_common.go:465-481). It's a lowerdir too.
//   - overlay_volumes[].options and volumes[].Options can each name the
//     overlay's upper and work directory, which Podman takes off the host as
//     written (getOverlayUpperAndWorkDir at container_internal_common.go:153-180,
//     called for an overlay volume at 467 and for a named volume mounted with
//     "O" at 327). See overlay_mount_options.go.
//   - init_path (ContainerStorageConfig.InitPath, specgen.go:291), when the
//     create also sets init, is a host binary bind-mounted read-only at
//     /run/podman-init and run as the container's PID 1
//     (pkg/specgen/generate/storage.go:134 and 387-392). It's gated whenever
//     it's set: Podman ignores it without init, so holding it to the allowlist
//     regardless is strictly fail-closed and never refuses a create init would
//     have let through.
//   - conmon_pid_file (ContainerBasicConfig.ConmonPidFile, specgen.go:105) is
//     written by conmon as the daemon's user (libpod.WithConmonPidFile at
//     container_create.go:602, used at libpod/oci_conmon_common.go:1045). A
//     create only fills in a default when the field is empty
//     (libpod/runtime_ctr.go:486-487), so an arbitrary host path is kept and
//     written to.
//   - log_configuration.path (LogConfig.Path, specgen.go:25) goes to
//     libpod.WithLogPath whenever it's non-empty, under any driver
//     (container_create.go:555-556). A path that is a directory gets a
//     directory named for the container made under it, and any other path is
//     kept as the log file (libpod/options.go:1033-1050), which conmon writes
//     the container's output to under the k8s-file and json-file drivers
//     (libpod/oci_conmon_common.go:1325-1345). The rest of the object names
//     no host path: MakeContainer reads only "tag" out of
//     log_configuration.options (container_create.go:561-563), and the
//     "--log-opt path=" handling the compat create goes through is CLI-side
//     code the native handler never runs. Podman 6.1.3 is the same
//     (container_create.go:568-584, options.go:1016-1032).
//   - healthLogDestination (ContainerHealthCheckConfig.HealthLogDestination,
//     specgen.go:609) is "local" unless the body sets it
//     (pkg/api/handlers/libpod/containers_create.go:58). "local" and
//     "events_logger" keep healthcheck results in the container's own state.
//     Any other value has to be a directory on the daemon host
//     (libpod/define/healthchecks.go:295-314, compared exactly), and each
//     healthcheck run writes <dir>/<container id>-healthcheck.log there
//     (libpod/healthcheck.go:410-422). Podman 6.1.3 is the same
//     (healthcheck.go:416-428). The update inspector refuses its
//     health_log_destination twin outright; see libpod_container_update.go.

// denyHostPathReason holds rootfs, every overlay_volumes source, every overlay
// upper and work directory and init_path to allowedBindMounts, refuses
// conmon_pid_file outright, and refuses the two log destinations unless
// allowLogPath is set. It returns the first deny reason, or "" when every
// host-path field is allowed. Malformed shapes of these fields fail the single
// json.Unmarshal in inspect before this runs, so they're already denied as
// malformed.
func (p libpodContainerCreatePolicy) denyHostPathReason(req libpodContainerCreateRequest) string {
	if denyReason := p.denyRootfsReason(req.Rootfs, req.RootfsOverlay); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyOverlayVolumeReason(req.OverlayVolumes); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyNamedVolumeOverlayReason(req.Volumes); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyInitPathReason(req.InitPath); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyConmonPidFileReason(req.ConmonPidFile); denyReason != "" {
		return denyReason
	}
	return p.denyLogPathReason(req.LogConfiguration.Path, req.HealthLogDestination)
}

// denyRootfsReason holds a non-empty rootfs to allowedBindMounts. An empty
// rootfs is the image-based create's default and does nothing, so it passes; a
// non-empty one that doesn't normalize to an allowlisted absolute path is
// denied, so a relative or malformed path fails closed. With rootfs_overlay the
// path is an overlay lowerdir, so it also can't carry an overlay
// metacharacter. Without it the path is only ever handed over as a path, where
// a comma or a backslash is just a character in a name.
func (p libpodContainerCreatePolicy) denyRootfsReason(rootfs string, overlay bool) string {
	if rootfs == "" {
		return ""
	}
	if source, ok := normalizeBindMount(rootfs); !ok || !bindPathAllowed(source, p.allowedBindMounts) {
		return fmt.Sprintf("libpod container create denied: rootfs path %q is not allowlisted (add it to allowed_bind_mounts)", rootfs)
	}
	if overlay && hasOverlayOptionMetacharacter(rootfs) {
		return fmt.Sprintf("libpod container create denied: rootfs path %q contains a comma or backslash, which rootfs_overlay can't mount safely", rootfs)
	}
	return ""
}

// denyOverlayVolumeReason holds every overlay_volumes source, and every upper
// and work directory in its options, to allowedBindMounts. An overlay volume
// always carries a host-path source (Podman builds one only from a host
// directory), so an empty or otherwise non-allowlisted source fails closed.
// The source is the overlay's lowerdir, so it can't carry an overlay
// metacharacter either.
func (p libpodContainerCreatePolicy) denyOverlayVolumeReason(volumes []libpodOverlayVolume) string {
	for _, volume := range volumes {
		if source, ok := normalizeBindMount(volume.Source); !ok || !bindPathAllowed(source, p.allowedBindMounts) {
			return fmt.Sprintf("libpod container create denied: overlay volume source %q is not allowlisted (add it to allowed_bind_mounts)", volume.Source)
		}
		if hasOverlayOptionMetacharacter(volume.Source) {
			return fmt.Sprintf("libpod container create denied: overlay volume source %q contains a comma or backslash", volume.Source)
		}
		if denyReason := denyOverlayDirOptionsReason(volume.Options, p.allowedBindMounts, "libpod container create"); denyReason != "" {
			return denyReason
		}
	}
	return ""
}

// denyNamedVolumeOverlayReason holds every upper and work directory a volumes
// entry names in its Options to allowedBindMounts. The volume itself is named,
// not a host path, and stays unchecked here, but Podman overlays it when one of
// its options is "O" and then takes the upper and work directory off the host.
// The options are checked whether or not "O" is among them: without it Podman
// refuses an upperdir or workdir option as unknown, so no working create is
// lost, and nothing here depends on reading "O" the way Podman does.
func (p libpodContainerCreatePolicy) denyNamedVolumeOverlayReason(volumes []libpodVolume) string {
	for _, volume := range volumes {
		if denyReason := denyOverlayDirOptionsReason(volume.Options, p.allowedBindMounts, "libpod container create"); denyReason != "" {
			return denyReason
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

// denyLogPathReason refuses a non-empty log_configuration.path, and a
// healthLogDestination that names a directory, unless allowLogPath is set.
// Both are host paths the daemon writes to, so allowed_bind_mounts doesn't fit
// them any better than it fits conmon_pid_file.
//
// The path test is Podman's own: it acts on any non-empty value (len > 0).
// The destination test is the other way round. "local" and "events_logger"
// keep healthcheck results in the container's own state, Podman compares the
// two exactly (define.GetValidHealthCheckDestination), and whatever isn't one
// of them is refused. So a name in another case or padded with a space, which
// Podman reads as a directory under its working directory, is refused with
// the absolute paths. An empty destination passes: Podman refuses it itself,
// because it isn't a directory, and it's what a body that leaves the field
// out decodes to here.
func (p libpodContainerCreatePolicy) denyLogPathReason(logPath, healthLogDestination string) string {
	if p.allowLogPath {
		return ""
	}
	if logPath != "" {
		return "libpod container create denied: setting log_configuration.path is not allowed (set allow_log_path: true)"
	}
	switch healthLogDestination {
	case "", "local", "events_logger":
		return ""
	default:
		return `libpod container create denied: setting healthLogDestination to a host directory is not allowed (set allow_log_path: true, or use "local" or "events_logger")`
	}
}
