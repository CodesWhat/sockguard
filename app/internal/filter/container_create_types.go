package filter

// container_create_types.go holds the on-wire JSON shapes that the
// /containers/create inspector decodes from request bodies. The split keeps
// container_create.go focused on policy logic and ensures schema additions
// (new HostConfig fields, new Mount kinds, etc.) land in one obvious place.

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
}

type containerCreateDevice struct {
	PathOnHost string `json:"PathOnHost"`
}
