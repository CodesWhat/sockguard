package filter

import "sync"

// container_create_types.go holds the on-wire JSON shapes that the
// /containers/create inspector decodes from request bodies. The split keeps
// container_create.go focused on policy logic and ensures schema additions
// (new HostConfig fields, new Mount kinds, etc.) land in one obvious place.
// A schema addition also has to be added to resetForReuse below, which
// TestContainerCreateRequestResetForReuseClearsEveryField enforces.

// AllowedDeviceRequestEntry is the public wire type that operators populate
// in YAML to allowlist GPU/accelerator HostConfig.DeviceRequests entries.
type AllowedDeviceRequestEntry struct {
	Driver              string
	AllowedCapabilities [][]string
	MaxCount            *int
}

// allowedDeviceRequestEntry is the pre-processed form stored in
// containerCreatePolicy after canonicalization.
type allowedDeviceRequestEntry struct {
	driver              string     // lowercase
	allowedCapabilities [][]string // each inner slice sorted + deduped
	maxCount            *int
}

// dockerDeviceRequest mirrors the Docker API HostConfig.DeviceRequests element.
type dockerDeviceRequest struct {
	Driver       string            `json:"Driver"`
	Count        int               `json:"Count"`
	DeviceIDs    []string          `json:"DeviceIDs"`
	Capabilities [][]string        `json:"Capabilities"`
	Options      map[string]string `json:"Options"`
}

type containerCreateRequest struct {
	Image      string                    `json:"Image"`
	HostConfig containerCreateHostConfig `json:"HostConfig"`
	User       string                    `json:"User"`
	Labels     map[string]string         `json:"Labels"`
	// MacAddress is the deprecated, top-level (pre-API-1.44) container-wide
	// MAC address field. The daemon still honors it, applying it to the
	// container's primary network endpoint exactly like
	// NetworkingConfig.EndpointsConfig[*].MacAddress does — see
	// denyRootMacAddressReason in container_create.go for why it is gated
	// identically to that field rather than left as an unchecked bypass.
	MacAddress       string                          `json:"MacAddress"`
	NetworkingConfig containerCreateNetworkingConfig `json:"NetworkingConfig"`
}

// containerCreateNetworkingConfig mirrors the Docker API
// NetworkingConfig object POST /containers/create accepts alongside
// HostConfig: a per-network-name map of endpoint settings applied when the
// container is attached to each network at create time. The daemon connects
// every entry here the same way POST /networks/*/connect does, so it carries
// the identical endpoint-config attack surface (static IP, MAC, links,
// driver opts) — see denyNetworkingConfigReason.
type containerCreateNetworkingConfig struct {
	EndpointsConfig map[string]*networkEndpointConfig `json:"EndpointsConfig"`
}

type containerCreateHostConfig struct {
	Privileged        bool                    `json:"Privileged"`
	NetworkMode       string                  `json:"NetworkMode"`
	PidMode           string                  `json:"PidMode"`
	IpcMode           string                  `json:"IpcMode"`
	UsernsMode        string                  `json:"UsernsMode"`
	CgroupnsMode      string                  `json:"CgroupnsMode"`
	Binds             []string                `json:"Binds"`
	Mounts            []containerCreateMount  `json:"Mounts"`
	Devices           []containerCreateDevice `json:"Devices"`
	DeviceRequests    []dockerDeviceRequest   `json:"DeviceRequests"`
	DeviceCgroupRules []string                `json:"DeviceCgroupRules"`
	SecurityOpt       []string                `json:"SecurityOpt"`
	CapAdd            []string                `json:"CapAdd"`
	CapDrop           []string                `json:"CapDrop"`
	ReadonlyRootfs    bool                    `json:"ReadonlyRootfs"`
	Memory            int64                   `json:"Memory"`
	MemoryReservation int64                   `json:"MemoryReservation"`
	NanoCpus          int64                   `json:"NanoCpus"`
	CpuQuota          int64                   `json:"CpuQuota"`
	CpuPeriod         int64                   `json:"CpuPeriod"`
	CpuShares         int64                   `json:"CpuShares"`
	PidsLimit         *int64                  `json:"PidsLimit"`
	Sysctls           map[string]string       `json:"Sysctls"`
	VolumesFrom       []string                `json:"VolumesFrom"`
	UTSMode           string                  `json:"UTSMode"`
	CgroupParent      string                  `json:"CgroupParent"`
	GroupAdd          []string                `json:"GroupAdd"`
	ExtraHosts        []string                `json:"ExtraHosts"`
	Runtime           string                  `json:"Runtime"`
	// MaskedPaths overrides the default set of paths that Docker masks inside
	// the container. An empty slice signals systempaths=unconfined intent
	// delivered via the direct API path (the Docker CLI converts
	// --security-opt systempaths=unconfined to MaskedPaths=[] client-side).
	// The pointer distinguishes "not set" (nil) from "explicitly set to empty"
	// (non-nil, zero length).
	MaskedPaths   *[]string `json:"MaskedPaths"`
	ReadonlyPaths *[]string `json:"ReadonlyPaths"`
}

type containerCreateMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
	// VolumeOptions.Subpath (Engine API 1.45+) mounts a subdirectory of the
	// named volume instead of its root. ImageOptions.Subpath (Engine API
	// 1.55+) does the same for image-type mounts. Both are validated by
	// denyMountSubpathReason against a path-traversal escape.
	VolumeOptions *containerCreateMountVolumeOptions `json:"VolumeOptions"`
	ImageOptions  *containerCreateMountImageOptions  `json:"ImageOptions"`
	// TmpfsOptions.Options (Engine API 1.46+) is a nested [][]string of raw
	// tmpfs mount option tokens (e.g. ["mode","1770"], ["exec"]), validated
	// by denyTmpfsOptionsReason.
	TmpfsOptions *containerCreateMountTmpfsOptions `json:"TmpfsOptions"`
}

// containerCreateMountVolumeOptions mirrors the Docker API Mount.VolumeOptions
// object, narrowed to the fields the policy inspects.
type containerCreateMountVolumeOptions struct {
	Subpath string `json:"Subpath"`
	// DriverConfig creates the named volume with a driver and a driver
	// options map when it does not already exist. With the built-in local
	// driver those options are forwarded to mount(2), so a volume-type mount
	// carrying {"type":"none","o":"bind","device":"/host/path"} is a bind
	// mount of an arbitrary host path — see denyLocalVolumeBindDeviceReason,
	// which checks the device against the same allowlist a Type: "bind"
	// mount is checked against.
	DriverConfig *containerCreateMountVolumeDriverConfig `json:"DriverConfig"`
}

// containerCreateMountVolumeDriverConfig mirrors the Docker API
// Mount.VolumeOptions.DriverConfig object. An empty Name selects the daemon's
// default driver, which is the local one.
type containerCreateMountVolumeDriverConfig struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
}

// containerCreateMountImageOptions mirrors the Docker API Mount.ImageOptions
// object, narrowed to the field the policy inspects.
type containerCreateMountImageOptions struct {
	Subpath string `json:"Subpath"`
}

// containerCreateMountTmpfsOptions mirrors the Docker API Mount.TmpfsOptions
// object, narrowed to the field the policy inspects.
type containerCreateMountTmpfsOptions struct {
	Options [][]string `json:"Options"`
}

// knownContainerCreateMountTypes is the set of Mount.Type values Sockguard's
// policy has an explicit posture for: "bind" (allowlist-checked),
// "volume"/"tmpfs" (pass through, checked for subpath/options above), and
// "image" (image-trust-checked in enforce mode, see denyImageMountReason).
// Any other value — including future Docker Mount types this proxy has never
// seen — is denied fail-closed by denyUnknownMountTypeReason rather than
// silently passing through unchecked the way an unrecognized Type used to
// (extractAndValidateBindSource returns ok=false for it, which the bind-mount
// loop above treated as "nothing to check" rather than "deny").
var knownContainerCreateMountTypes = map[string]bool{
	"bind":   true,
	"volume": true,
	"tmpfs":  true,
	"image":  true,
}

type containerCreateDevice struct {
	PathOnHost string `json:"PathOnHost"`
}

// containerCreateRequestPool recycles the decode target for
// POST /containers/create. The inspector decodes one containerCreateRequest
// per request and drops it again before it returns, so the ~600-byte struct,
// the backing arrays behind every list field the body carried, and the
// buckets behind Labels/Sysctls are all garbage the moment the policy has
// finished reading them. Recycling them costs nothing in fidelity: the
// decode is still the same json.Unmarshal against the same type, so every
// field the policy reads and every type error a malformed body produces are
// exactly what they were before — only the allocation is removed.
var containerCreateRequestPool = sync.Pool{
	New: func() any { return new(containerCreateRequest) },
}

// containerCreateReuseCap bounds what a recycled decode target is allowed to
// keep hold of. Bodies are already capped at maxContainerCreateBodyBytes, but
// a single 1 MiB create with tens of thousands of Binds entries would
// otherwise leave its backing array parked in the pool for the lifetime of
// the process, once per P. A target that grew past this is dropped on release
// and the next request allocates a fresh one.
const containerCreateReuseCap = 64

// acquireContainerCreateRequest returns a decode target with every field at
// its zero value. The reset happens here rather than on release so the
// invariant holds for whatever comes out of the pool: a caller can never
// observe a previous request's Binds, Labels or PidsLimit, which would be a
// policy decision made against another client's body.
func acquireContainerCreateRequest() *containerCreateRequest {
	req, _ := containerCreateRequestPool.Get().(*containerCreateRequest)
	if req == nil {
		return new(containerCreateRequest)
	}
	req.resetForReuse()
	return req
}

// releaseContainerCreateRequest returns req to the pool unless it is holding
// more memory than it is worth recycling.
func releaseContainerCreateRequest(req *containerCreateRequest) {
	if req == nil || req.oversizedForReuse() {
		return
	}
	containerCreateRequestPool.Put(req)
}

// resetForReuse puts every field back to the value a freshly allocated
// containerCreateRequest would have, while keeping the capacity of the
// []string fields and the buckets of the map fields so the next decode can
// reuse them.
//
// Three rules, and each one is a correctness rule rather than a style choice:
//
//   - []string fields are truncated, not dropped. encoding/json overwrites
//     element i before it is reachable and truncates the slice to the number
//     of elements it decoded, so nothing left over past the new length can be
//     read back through the field.
//   - Slices of structs (Mounts, Devices, DeviceRequests) are dropped, not
//     truncated. encoding/json decodes into the existing element without
//     zeroing it first, so a reused element would keep the previous request's
//     VolumeOptions pointer or Capabilities for any key the new body omits.
//   - Maps are cleared and pointer fields are nil'd. A surviving PidsLimit
//     would satisfy a required-limit check the new body never asked for, and
//     a surviving MaskedPaths pointer reads as "explicitly set to empty",
//     which is the exact signal denySystemPathsReason denies on.
func (r *containerCreateRequest) resetForReuse() {
	r.Image = ""
	r.User = ""
	r.MacAddress = ""
	clear(r.Labels)
	clear(r.NetworkingConfig.EndpointsConfig)

	h := &r.HostConfig
	h.Privileged = false
	h.NetworkMode = ""
	h.PidMode = ""
	h.IpcMode = ""
	h.UsernsMode = ""
	h.CgroupnsMode = ""
	h.Binds = h.Binds[:0]
	h.Mounts = nil
	h.Devices = nil
	h.DeviceRequests = nil
	h.DeviceCgroupRules = h.DeviceCgroupRules[:0]
	h.SecurityOpt = h.SecurityOpt[:0]
	h.CapAdd = h.CapAdd[:0]
	h.CapDrop = h.CapDrop[:0]
	h.ReadonlyRootfs = false
	h.Memory = 0
	h.MemoryReservation = 0
	h.NanoCpus = 0
	h.CpuQuota = 0
	h.CpuPeriod = 0
	h.CpuShares = 0
	h.PidsLimit = nil
	clear(h.Sysctls)
	h.VolumesFrom = h.VolumesFrom[:0]
	h.UTSMode = ""
	h.CgroupParent = ""
	h.GroupAdd = h.GroupAdd[:0]
	h.ExtraHosts = h.ExtraHosts[:0]
	h.Runtime = ""
	h.MaskedPaths = nil
	h.ReadonlyPaths = nil
}

// oversizedForReuse reports whether req grew past containerCreateReuseCap in
// any of the containers resetForReuse keeps, which is the point at which
// recycling it costs more memory than the allocation it saves.
func (r *containerCreateRequest) oversizedForReuse() bool {
	h := &r.HostConfig
	return overContainerCreateReuseCap(h.Binds) ||
		overContainerCreateReuseCap(h.DeviceCgroupRules) ||
		overContainerCreateReuseCap(h.SecurityOpt) ||
		overContainerCreateReuseCap(h.CapAdd) ||
		overContainerCreateReuseCap(h.CapDrop) ||
		overContainerCreateReuseCap(h.VolumesFrom) ||
		overContainerCreateReuseCap(h.GroupAdd) ||
		overContainerCreateReuseCap(h.ExtraHosts) ||
		len(r.Labels) > containerCreateReuseCap ||
		len(h.Sysctls) > containerCreateReuseCap ||
		len(r.NetworkingConfig.EndpointsConfig) > containerCreateReuseCap
}

func overContainerCreateReuseCap(values []string) bool {
	return cap(values) > containerCreateReuseCap
}
