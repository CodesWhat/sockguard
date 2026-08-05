package filter

import "strings"

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
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	User       string            `json:"user"`
	Labels     map[string]string `json:"labels"`
	Privileged bool              `json:"privileged"`

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

	CapAdd  []string `json:"cap_add"`
	CapDrop []string `json:"cap_drop"`

	SeccompProfilePath string   `json:"seccomp_profile_path"`
	ApparmorProfile    string   `json:"apparmor_profile"`
	SelinuxOpts        []string `json:"selinux_opts"`

	ResourceLimits libpodResourceLimits `json:"resource_limits"`

	Sysctl             map[string]string `json:"sysctl"`
	ReadOnlyFilesystem bool              `json:"read_only_filesystem"`
	Systemd            string            `json:"systemd"`
}

// libpodNamespace is the uniform shape SpecGenerator uses for every
// namespace-mode field (netns, pidns, ipcns, userns, utsns, cgroupns):
// {"nsmode": "host"} for the host namespace, {"nsmode": "container",
// "value": "<name-or-id>"} to join another container's namespace, {} (both
// fields absent/empty) for the private per-container default. Confirmed by
// host_network.json (nsmode only) and namespace_share_container_ref.json
// (nsmode+value) — see testdata/libpod/README.md.
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

// libpodVolume is one entry of the top-level "volumes" array (named-volume
// mounts routed through -v <volume-name>:<container> on the CLI). Capitalized
// field names, unlike libpodMount — see volumes_named.json.
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
