package filter

import (
	"encoding/json"
	"strconv"
	"strings"
)

// libpod_container_create_types.go holds the on-wire JSON shapes that the
// POST /libpod/containers/create inspector decodes from request bodies.
// Field names and shapes here are pinned against real captures in
// testdata/libpod/*.json (see that directory's README for provenance) rather
// than either #148 design draft's guessed schema — see design doc C4. Mirrors
// the container_create_types.go / container_create.go split: this file is
// schema only, libpod_container_create.go is policy logic.
//
// SpecGenerator's wire format is its own thing, not a re-derivation of the
// Docker Engine API shape: field names are snake_case, namespace fields are
// uniformly {"nsmode": "...", "value": "..."} objects instead of Docker's
// single "host"/"container:<ref>" strings, and — confirmed by the
// mounts_bind_tmpfs.json vs volumes_named.json fixtures — "mounts" and
// "volumes" are two separate top-level arrays with DIFFERENT key casing
// (lowercase vs capitalized). None of that is accidental convergence with
// container_create_types.go, so nothing is shared between the two files
// beyond the package-level helpers in container_create.go
// (normalizeBindMount, bindPathAllowed, normalizeContainerCreateDevicePath,
// capabilityAddDenyReason, isNonRootUser, normalizeCapabilityList,
// normalizeStringList) that are shape-independent.

// libpodContainerCreateRequest is the top-level POST /libpod/containers/create
// body. Only the fields this inspector's gates read are modeled; SpecGenerator
// sends many more (health checks, DNS, working dir, ...) that pass through
// unread and therefore unvalidated by sockguard — matching container_create's
// own posture of only modeling fields it has an explicit gate for.
type libpodContainerCreateRequest struct {
	Command    []string          `json:"command"`
	Entrypoint []string          `json:"entrypoint"`
	Env        map[string]string `json:"env"`
	EnvHost    bool              `json:"env_host"`
	HTTPProxy  *bool             `json:"httpproxy"`
	EnvSecrets json.RawMessage   `json:"secret_env"`
	EnvMerge   []string          `json:"envmerge"`

	Name         string            `json:"name"`
	Image        string            `json:"image"`
	ImageVolumes []json.RawMessage `json:"image_volumes"`
	// ImageVolumeMode is how the image's declared VOLUMEs are mounted:
	// "bind" (default), "tmpfs" or "ignore". "tmpfs" mounts them executable.
	ImageVolumeMode string            `json:"image_volume_mode"`
	User            string            `json:"user"`
	Labels          map[string]string `json:"labels"`
	Privileged      bool              `json:"privileged"`

	NetNS     libpodNamespace  `json:"netns"`
	PidNS     libpodNamespace  `json:"pidns"`
	IpcNS     libpodNamespace  `json:"ipcns"`
	UserNS    libpodNamespace  `json:"userns"`
	UtsNS     libpodNamespace  `json:"utsns"`
	CgroupNS  libpodNamespace  `json:"cgroupns"`
	IDMapping libpodIDMappings `json:"idmappings"`

	Mounts  []libpodMount  `json:"mounts"`
	Volumes []libpodVolume `json:"volumes"`
	Devices []libpodDevice `json:"devices"`

	// HostDeviceList is SpecGenerator.HostDeviceList (specgen.go:324). When
	// the container joins a pod with an infra container and Devices is empty,
	// Podman uses this list as the device list (generate/oci_linux.go:283 →
	// DevicesFromPath), so it is checked exactly like Devices. DevicesFrom is
	// inert in Podman today; any value is refused as hardening.
	HostDeviceList []libpodDevice `json:"host_device_list"`
	DevicesFrom    []string       `json:"devices_from"`

	// Rootfs, OverlayVolumes and InitPath each give the container a host
	// filesystem path that neither mounts[] nor devices[] covers, so each has
	// its own host-path gate; ConmonPidFile is a host path the daemon writes
	// conmon's PID to. RootfsOverlay is read only to know whether Rootfs ends
	// up in an overlay option string. See libpod_container_create_rootfs.go
	// for the gates and the specgen references that pin what Podman does with
	// each.
	Rootfs         string                `json:"rootfs"`
	RootfsOverlay  bool                  `json:"rootfs_overlay"`
	OverlayVolumes []libpodOverlayVolume `json:"overlay_volumes"`
	InitPath       string                `json:"init_path"`
	ConmonPidFile  string                `json:"conmon_pid_file"`
	BaseHostsFile  string                `json:"base_hosts_file"`

	// LogConfiguration and HealthLogDestination are the two places a create
	// names a host path for the daemon to write logs to: the container's log
	// file, and the directory healthcheck results go into. See
	// denyLogPathReason in libpod_container_create_rootfs.go.
	LogConfiguration     libpodLogConfiguration `json:"log_configuration"`
	HealthLogDestination string                 `json:"healthLogDestination"`

	CapAdd  []string `json:"cap_add"`
	CapDrop []string `json:"cap_drop"`

	SeccompProfilePath string   `json:"seccomp_profile_path"`
	ApparmorProfile    string   `json:"apparmor_profile"`
	SelinuxOpts        []string `json:"selinux_opts"`

	ResourceLimits libpodResourceLimits `json:"resource_limits"`

	Sysctl             map[string]string `json:"sysctl"`
	ReadOnlyFilesystem bool              `json:"read_only_filesystem"`
	Systemd            string            `json:"systemd"`

	// The libpod spellings of fields container_create gates or denies on the
	// Docker side: volumes_from (HostConfig.VolumesFrom), cgroup_parent
	// (CgroupParent), groups (GroupAdd), hostadd (ExtraHosts), oci_runtime
	// (Runtime), device_cgroup_rule (DeviceCgroupRules), gpus (the
	// DeviceRequests a GPU passthrough rides on) and unmask (the
	// MaskedPaths/ReadonlyPaths half of systempaths=unconfined). Names and
	// shapes are pinned to Podman v5.8.1 and v6.1.4 pkg/specgen/specgen.go;
	// gpus exists from v6 only. See denyDockerParityReason.
	VolumesFrom      []string                 `json:"volumes_from"`
	CgroupParent     string                   `json:"cgroup_parent"`
	Groups           []string                 `json:"groups"`
	HostAdd          []string                 `json:"hostadd"`
	OCIRuntime       string                   `json:"oci_runtime"`
	DeviceCgroupRule []libpodDeviceCgroupRule `json:"device_cgroup_rule"`
	GPUs             []string                 `json:"gpus"`
	Unmask           []string                 `json:"unmask"`

	// Unified is SpecGenerator's "unified" map: raw cgroup v2 controller
	// knobs Podman writes into the container's cgroup. See
	// denyUnifiedCgroupReason in libpod_container_create_residual.go.
	Unified map[string]string `json:"unified"`

	// Pod is the pod this container joins. It shares the pod's infra
	// namespaces, so it follows restrictNamespaceSharing. See
	// denyPodJoinReason.
	Pod string `json:"pod"`
}

// libpodDeviceCgroupRule is one entry of "device_cgroup_rule", the OCI
// runtime-spec LinuxDeviceCgroup object. Podman ignores allow and always
// grants (oci_linux.go AddLinuxResourcesDevice(true, ...)), so every entry is
// treated as an allow rule. A nil major or minor is the wildcard.
type libpodDeviceCgroupRule struct {
	Type   string `json:"type"`
	Major  *int64 `json:"major"`
	Minor  *int64 `json:"minor"`
	Access string `json:"access"`
}

// docker renders the rule in Docker's "<type> <major>:<minor> <perms>" string
// form so it can be checked by the same code as HostConfig.DeviceCgroupRules.
// An empty type is the runtime spec's "all".
func (r libpodDeviceCgroupRule) docker() string {
	devType := strings.TrimSpace(r.Type)
	if devType == "" {
		devType = "a"
	}
	num := func(n *int64) string {
		if n == nil {
			return "*"
		}
		return strconv.FormatInt(*n, 10)
	}
	return devType + " " + num(r.Major) + ":" + num(r.Minor) + " " + strings.TrimSpace(r.Access)
}

// libpodLogConfiguration mirrors SpecGenerator's "log_configuration" object
// (specgen.LogConfig), narrowed to the field the policy inspects. driver,
// size, labels and options aren't decoded: none of them names a host path.
// podman-remote sends the object empty unless --log-driver or --log-opt was
// passed, and reads "--log-opt path=" into the path field itself; see
// basic_create.json and log_path.json.
type libpodLogConfiguration struct {
	Path string `json:"path"`
}

// libpodNamespace is the uniform shape SpecGenerator uses for every
// namespace-mode field (netns, pidns, ipcns, userns, utsns, cgroupns):
// {"nsmode": "host"} for the host namespace, {"nsmode": "container",
// "value": "<name-or-id>"} to join another container's namespace,
// {"nsmode": "path", "value": "<path>"} to join the namespace at a path on
// the daemon host, {} (both fields absent/empty) for the daemon's default.
// Confirmed by host_network.json (nsmode only) and
// namespace_share_container_ref.json (nsmode+value) — see
// testdata/libpod/README.md. libpod_namespace.go holds the full list of
// modes and the host gate.
type libpodNamespace struct {
	NSMode string `json:"nsmode"`
	Value  string `json:"value"`
}

// isHost reports whether this namespace object selects the host namespace.
func (n libpodNamespace) isHost() bool {
	return isHostNamespaceMode(n.NSMode)
}

// containerRef reports whether this namespace object joins another
// container's namespace ({"nsmode":"container","value":"<ref>"}) and, if so,
// returns the trimmed ref.
func (n libpodNamespace) containerRef() (ref string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(n.NSMode), "container") {
		return "", false
	}
	ref = strings.TrimSpace(n.Value)
	if ref == "" {
		return "", false
	}
	return ref, true
}

// libpodMount is one entry of the top-level "mounts" array (bind/tmpfs/image
// mounts routed through --mount or -v <host>:<container> on the CLI).
// Lowercase field names — see volumes_named.json for the contrasting
// capitalized shape of libpodVolume, a genuine SpecGenerator inconsistency
// between the two arrays.
type libpodMount struct {
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Options     []string `json:"options"`
}

// libpodOverlayVolume is one entry of the top-level "overlay_volumes" array
// (podman -v <host>:<dest>:O). Unlike a named "volumes" entry, its source is a
// host filesystem path, overlay-mounted at destination inside the container
// (Podman 5.8.6 pkg/specgen/volumes.go:36-43, mounted at
// libpod/container_internal_common.go:465-481). Its options can name two more
// host paths, the overlay's upper and work directory. Lowercase field names,
// matching the specgen OverlayVolume JSON tags encoding/json decodes.
type libpodOverlayVolume struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Options     []string `json:"options"`
}

// libpodVolume is one entry of the top-level "volumes" array (named-volume
// mounts routed through -v <volume-name>:<container> on the CLI). Capitalized
// field names, unlike libpodMount — see volumes_named.json. Options is the one
// field that can reach the host: with "O" among them Podman overlays the
// volume and reads an upper and work directory out of the rest.
type libpodVolume struct {
	Name        string   `json:"Name"`
	Dest        string   `json:"Dest"`
	Options     []string `json:"Options"`
	SubPath     string   `json:"SubPath"`
	IsAnonymous bool     `json:"IsAnonymous"`
}

// libpodDevice is one entry of the top-level "devices" array. Unlike Docker's
// HostConfig.Devices (which the client splits into PathOnHost/PathInContainer
// before sending), SpecGenerator sends the raw, unsplit "host[:container[:perms]]"
// CLI argument verbatim in Path — see devices.json and splitLibpodDevicePath.
type libpodDevice struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Major int64  `json:"major"`
	Minor int64  `json:"minor"`
}

// libpodResourceLimits mirrors the OCI runtime-spec-shaped "resource_limits"
// object SpecGenerator sends for --memory/--cpus/--cpu-shares/--pids-limit.
// All fields are plain values, not pointers: an absent JSON key and an
// explicit zero both mean "no limit" for every RequireX gate this inspector
// implements, so the pointer/value distinction that matters elsewhere in this
// package (e.g. containerCreateHostConfig.PidsLimit) carries no policy
// meaning here.
type libpodResourceLimits struct {
	CPU    libpodCPUResourceLimit    `json:"cpu"`
	Memory libpodMemoryResourceLimit `json:"memory"`
	Pids   libpodPidsResourceLimit   `json:"pids"`

	// Devices is the OCI LinuxDeviceCgroup list. Podman copies it over
	// Linux.Resources.Devices, so an allow entry grants the same access as
	// device_cgroup_rule and is gated by the same policy.
	Devices []libpodResourceDeviceRule `json:"devices"`
}

// libpodResourceDeviceRule is one resource_limits.devices entry. Unlike
// device_cgroup_rule, allow is honored here, so an allow:false entry is a
// deny rule and is always fine.
type libpodResourceDeviceRule struct {
	Allow  bool   `json:"allow"`
	Type   string `json:"type"`
	Major  *int64 `json:"major"`
	Minor  *int64 `json:"minor"`
	Access string `json:"access"`
}

// docker renders the entry in Docker's "<type> <major>:<minor> <perms>" form.
func (r libpodResourceDeviceRule) docker() string {
	return libpodDeviceCgroupRule{Type: r.Type, Major: r.Major, Minor: r.Minor, Access: r.Access}.docker()
}

// libpodCPUResourceLimit mirrors resource_limits.cpu. period/quota come from
// --cpus (both set together); shares comes from --cpu-shares independently —
// see resource_limits.json vs resource_limits_cpu_shares.json.
type libpodCPUResourceLimit struct {
	Period uint64 `json:"period"`
	Quota  int64  `json:"quota"`
	Shares uint64 `json:"shares"`
}

// libpodMemoryResourceLimit mirrors resource_limits.memory.
type libpodMemoryResourceLimit struct {
	Limit int64 `json:"limit"`
	Swap  int64 `json:"swap"`
}

// libpodPidsResourceLimit mirrors resource_limits.pids.
type libpodPidsResourceLimit struct {
	Limit int64 `json:"limit"`
}

// libpodIDMappings mirrors the top-level "idmappings" object SpecGenerator
// always sends (present, but with nil UIDMap/GIDMap and
// HostUIDMapping/HostGIDMapping true, when no custom mapping was requested —
// see basic_create.json). AutoUserNs/AutoUserNsOpts (podman --userns=auto)
// are read only for the "any custom mapping requested" test, not modeled
// field-by-field — see denyIDMappingsReason.
type libpodIDMappings struct {
	UIDMap         []libpodIDMap `json:"UIDMap"`
	GIDMap         []libpodIDMap `json:"GIDMap"`
	HostUIDMapping bool          `json:"HostUIDMapping"`
	HostGIDMapping bool          `json:"HostGIDMapping"`
	AutoUserNs     bool          `json:"AutoUserNs"`
}

// libpodIDMap is one entry of idmappings.UIDMap/GIDMap.
type libpodIDMap struct {
	ContainerID int `json:"container_id"`
	HostID      int `json:"host_id"`
	Size        int `json:"size"`
}

// splitLibpodDevicePath splits a libpodDevice.Path value into its host-side
// path. SpecGenerator does not pre-split the "host[:container[:perms]]" CLI
// form the way Docker's client does — see devices.json — so the inspector
// must do it here. A path with no ":" is the single-argument --device form
// (host path only, container path defaults to the same path).
func splitLibpodDevicePath(raw string) (hostPath string, ok bool) {
	if idx := strings.IndexByte(raw, ':'); idx >= 0 {
		return raw[:idx], true
	}
	return raw, raw != ""
}
