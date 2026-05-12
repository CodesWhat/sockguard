package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
)

// maxContainerCreateBodyBytes caps the request body Sockguard will read when
// inspecting POST /containers/create. Docker's own container-create payloads
// are at most a few KiB even for complex specs, so a 1 MiB ceiling is
// generous while still preventing a malicious or misbehaving client from
// OOMing the proxy with an unbounded body.
const maxContainerCreateBodyBytes = 1 << 20 // 1 MiB

// ContainerCreateOptions configures request-body policy checks for
// POST /containers/create.
type ContainerCreateOptions struct {
	AllowPrivileged        bool
	AllowHostNetwork       bool
	AllowHostPID           bool
	AllowHostIPC           bool
	AllowedBindMounts      []string
	AllowAllDevices        bool
	AllowedDevices         []string
	AllowDeviceRequests         bool
	AllowedDeviceRequests       []AllowedDeviceRequestEntry
	AllowDeviceCgroupRules      bool
	AllowedDeviceCgroupRules    []string

	// 0.6.0 secure-container rails.
	RequireNoNewPrivileges     bool
	RequireNonRootUser         bool
	RequireReadonlyRootfs      bool
	RequireDropAllCapabilities bool
	AllowAllCapabilities       bool
	AllowedCapabilities        []string
	RequireMemoryLimit         bool
	RequireCPULimit            bool
	RequirePidsLimit           bool
	AllowedSeccompProfiles     []string
	DenyUnconfinedSeccomp      bool
	AllowedAppArmorProfiles    []string
	DenyUnconfinedAppArmor     bool
	AllowHostUserNS            bool
	RequiredLabels             []string
}

type containerCreatePolicy struct {
	allowPrivileged        bool
	allowHostNetwork       bool
	allowHostPID           bool
	allowHostIPC           bool
	allowedBindMounts      []string
	allowAllDevices        bool
	allowedDevices         []string
	allowDeviceRequests         bool
	allowedDeviceRequests       []allowedDeviceRequestEntry
	allowDeviceCgroupRules      bool
	allowedDeviceCgroupRules    []string

	requireNoNewPrivileges     bool
	requireNonRootUser         bool
	requireReadonlyRootfs      bool
	requireDropAllCapabilities bool
	allowAllCapabilities       bool
	allowedCapabilities        []string
	requireMemoryLimit         bool
	requireCPULimit            bool
	requirePidsLimit           bool
	allowedSeccompProfiles     []string
	denyUnconfinedSeccomp      bool
	allowedAppArmorProfiles    []string
	denyUnconfinedAppArmor     bool
	allowHostUserNS            bool
	requiredLabels             []string
}

// AllowedDeviceRequestEntry is the public form of a device request allowlist
// entry, used in ContainerCreateOptions.
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
	HostConfig containerCreateHostConfig `json:"HostConfig"`
	User       string                    `json:"User"`
	Labels     map[string]string         `json:"Labels"`
}

type containerCreateHostConfig struct {
	Privileged        bool                    `json:"Privileged"`
	NetworkMode       string                  `json:"NetworkMode"`
	PidMode           string                  `json:"PidMode"`
	IpcMode           string                  `json:"IpcMode"`
	UsernsMode        string                  `json:"UsernsMode"`
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
}

type containerCreateMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

type containerCreateDevice struct {
	PathOnHost string `json:"PathOnHost"`
}

func newContainerCreatePolicy(opts ContainerCreateOptions) containerCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeContainerCreateBindMount(bindMount)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	allowedDevices := make([]string, 0, len(opts.AllowedDevices))
	for _, device := range opts.AllowedDevices {
		normalized, ok := normalizeContainerCreateDevicePath(device)
		if !ok || slices.Contains(allowedDevices, normalized) {
			continue
		}
		allowedDevices = append(allowedDevices, normalized)
	}

	allowedDeviceCgroupRules := make([]string, 0, len(opts.AllowedDeviceCgroupRules))
	for _, rule := range opts.AllowedDeviceCgroupRules {
		canonical, ok := canonicalizeDeviceCgroupRule(rule)
		if !ok || slices.Contains(allowedDeviceCgroupRules, canonical) {
			continue
		}
		allowedDeviceCgroupRules = append(allowedDeviceCgroupRules, canonical)
	}

	allowedDeviceRequests := make([]allowedDeviceRequestEntry, 0, len(opts.AllowedDeviceRequests))
	for _, entry := range opts.AllowedDeviceRequests {
		driver := strings.ToLower(strings.TrimSpace(entry.Driver))
		if driver == "" {
			continue
		}
		canonCaps := canonicalizeAllowedCapabilitySets(entry.AllowedCapabilities)
		allowedDeviceRequests = append(allowedDeviceRequests, allowedDeviceRequestEntry{
			driver:              driver,
			allowedCapabilities: canonCaps,
			maxCount:            entry.MaxCount,
		})
	}

	return containerCreatePolicy{
		allowPrivileged:             opts.AllowPrivileged,
		allowHostNetwork:            opts.AllowHostNetwork,
		allowHostPID:                opts.AllowHostPID,
		allowHostIPC:                opts.AllowHostIPC,
		allowedBindMounts:           allowed,
		allowAllDevices:             opts.AllowAllDevices,
		allowedDevices:              allowedDevices,
		allowDeviceRequests:         opts.AllowDeviceRequests,
		allowedDeviceRequests:       allowedDeviceRequests,
		allowDeviceCgroupRules:      opts.AllowDeviceCgroupRules,
		allowedDeviceCgroupRules:    allowedDeviceCgroupRules,
		requireNoNewPrivileges:     opts.RequireNoNewPrivileges,
		requireNonRootUser:         opts.RequireNonRootUser,
		requireReadonlyRootfs:      opts.RequireReadonlyRootfs,
		requireDropAllCapabilities: opts.RequireDropAllCapabilities,
		allowAllCapabilities:       opts.AllowAllCapabilities,
		allowedCapabilities:        normalizeCapabilityList(opts.AllowedCapabilities),
		requireMemoryLimit:         opts.RequireMemoryLimit,
		requireCPULimit:            opts.RequireCPULimit,
		requirePidsLimit:           opts.RequirePidsLimit,
		allowedSeccompProfiles:     normalizeStringList(opts.AllowedSeccompProfiles),
		denyUnconfinedSeccomp:      opts.DenyUnconfinedSeccomp,
		allowedAppArmorProfiles:    normalizeStringList(opts.AllowedAppArmorProfiles),
		denyUnconfinedAppArmor:     opts.DenyUnconfinedAppArmor,
		allowHostUserNS:            opts.AllowHostUserNS,
		requiredLabels:             normalizeStringList(opts.RequiredLabels),
	}
}

func (p containerCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" || r.Body == nil {
		return "", nil
	}
	if p.allowsAllContainerCreateBodies() {
		return "", nil
	}

	body, err := readBoundedBody(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var createReq containerCreateRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		// Let Docker return its native validation error when the create payload
		// is malformed; Sockguard only overrides known-dangerous valid requests.
		if logger != nil {
			logger.DebugContext(r.Context(), "container create request body is not valid JSON; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	if !p.allowPrivileged && createReq.HostConfig.Privileged {
		return "container create denied: privileged containers are not allowed", nil
	}
	if !p.allowHostNetwork && isHostNamespaceMode(createReq.HostConfig.NetworkMode) {
		return "container create denied: host network mode is not allowed", nil
	}
	if !p.allowHostPID && isHostNamespaceMode(createReq.HostConfig.PidMode) {
		return "container create denied: host PID mode is not allowed", nil
	}
	if !p.allowHostIPC && isHostNamespaceMode(createReq.HostConfig.IpcMode) {
		return "container create denied: host IPC mode is not allowed", nil
	}
	if !p.allowHostUserNS && isHostNamespaceMode(createReq.HostConfig.UsernsMode) {
		return "container create denied: host user namespace mode is not allowed", nil
	}
	if denyReason := p.denyDeviceReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyBindMountReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySecurityOptReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyCapabilityReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyHardeningReason(createReq); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyResourceLimitReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyRequiredLabelsReason(createReq); denyReason != "" {
		return denyReason, nil
	}

	return "", nil
}

func (p containerCreatePolicy) allowsAllContainerCreateBodies() bool {
	if p.requireNoNewPrivileges ||
		p.requireNonRootUser ||
		p.requireReadonlyRootfs ||
		p.requireDropAllCapabilities ||
		p.requireMemoryLimit ||
		p.requireCPULimit ||
		p.requirePidsLimit ||
		p.denyUnconfinedSeccomp ||
		p.denyUnconfinedAppArmor ||
		len(p.allowedSeccompProfiles) > 0 ||
		len(p.allowedAppArmorProfiles) > 0 ||
		len(p.requiredLabels) > 0 ||
		len(p.allowedDeviceCgroupRules) > 0 ||
		len(p.allowedDeviceRequests) > 0 ||
		!p.allowAllCapabilities {
		return false
	}
	return p.allowPrivileged &&
		p.allowHostNetwork &&
		p.allowHostPID &&
		p.allowHostIPC &&
		p.allowHostUserNS &&
		bindPathAllowed("/", p.allowedBindMounts) &&
		(p.allowAllDevices || bindPathAllowed("/", p.allowedDevices)) &&
		p.allowDeviceRequests &&
		p.allowDeviceCgroupRules
}

func isHostNamespaceMode(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "host")
}

func (p containerCreatePolicy) denyDeviceReason(hostConfig containerCreateHostConfig) string {
	if len(hostConfig.DeviceRequests) > 0 {
		if denyReason := p.denyDeviceRequestsReason(hostConfig.DeviceRequests); denyReason != "" {
			return denyReason
		}
	}
	if len(hostConfig.DeviceCgroupRules) > 0 {
		if denyReason := p.denyCgroupRulesReason(hostConfig.DeviceCgroupRules); denyReason != "" {
			return denyReason
		}
	}
	if p.allowAllDevices {
		return ""
	}
	for _, device := range hostConfig.Devices {
		rawPath := strings.TrimSpace(device.PathOnHost)
		hostPath, ok := normalizeContainerCreateDevicePath(rawPath)
		if !ok || !bindPathAllowed(hostPath, p.allowedDevices) {
			return fmt.Sprintf("container create denied: device %q is not allowlisted", rawPath)
		}
	}
	return ""
}

// denyDeviceRequestsReason checks each DeviceRequest against the policy.
// If allowDeviceRequests is true, all requests pass without inspection (escape
// hatch). If allowedDeviceRequests is non-empty, every request must match an
// entry by driver (exact, lowercase) and capabilities (each request capability
// set must be a subset of at least one allowlisted set), and optionally by
// count (max_count). Empty Driver in the request is rejected as malformed.
// If neither flag nor allowlist is set, all requests are denied (default-deny).
func (p containerCreatePolicy) denyDeviceRequestsReason(reqs []dockerDeviceRequest) string {
	if p.allowDeviceRequests {
		return ""
	}
	if len(p.allowedDeviceRequests) == 0 {
		return "container create denied: device requests are not allowed"
	}
	for i, req := range reqs {
		driver := strings.ToLower(strings.TrimSpace(req.Driver))
		if driver == "" {
			return fmt.Sprintf("container create denied: device request %d has an empty Driver field", i)
		}
		if !deviceRequestAllowed(req, driver, p.allowedDeviceRequests) {
			return fmt.Sprintf("container create denied: device request %d (driver %q) is not permitted by the allowlist", i, req.Driver)
		}
	}
	return ""
}

// deviceRequestAllowed reports whether a single DeviceRequest is permitted by
// at least one allowlist entry. The caller already computed the lowercased
// driver string.
func deviceRequestAllowed(req dockerDeviceRequest, driver string, allowlist []allowedDeviceRequestEntry) bool {
	for _, entry := range allowlist {
		if entry.driver != driver {
			continue
		}
		if !countAllowed(req.Count, entry.maxCount) {
			continue
		}
		if !capabilitySetsAllowed(req.Capabilities, entry.allowedCapabilities) {
			continue
		}
		return true
	}
	return false
}

// countAllowed reports whether the request Count is permitted by maxCount.
// If maxCount is nil, any count is allowed. Count -1 means "all devices"; it
// is only permitted when maxCount is also -1.
func countAllowed(reqCount int, maxCount *int) bool {
	if maxCount == nil {
		return true
	}
	if reqCount == -1 {
		return *maxCount == -1
	}
	return reqCount <= *maxCount
}

// capabilitySetsAllowed reports whether all capability sets in the request are
// covered by the allowlist. Each request set must be a subset of at least one
// allowlisted set (OR-of-subsets).
func capabilitySetsAllowed(reqSets [][]string, allowedSets [][]string) bool {
	for _, reqSet := range reqSets {
		canonReq := canonicalizeCapabilitySet(reqSet)
		if !capabilitySetCoveredByAny(canonReq, allowedSets) {
			return false
		}
	}
	return true
}

// capabilitySetCoveredByAny reports whether the request capability set is a
// subset of at least one entry in the allowlisted sets.
func capabilitySetCoveredByAny(reqSet []string, allowedSets [][]string) bool {
	for _, allowed := range allowedSets {
		if isSubset(reqSet, allowed) {
			return true
		}
	}
	return false
}

// isSubset reports whether every element of sub is present in super.
func isSubset(sub, super []string) bool {
	for _, s := range sub {
		if !slices.Contains(super, s) {
			return false
		}
	}
	return true
}

// canonicalizeCapabilitySet sorts and deduplicates a capability set in-place
// (returns a new slice). Capabilities are lowercased.
func canonicalizeCapabilitySet(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		lower := strings.ToLower(strings.TrimSpace(c))
		if lower == "" || slices.Contains(out, lower) {
			continue
		}
		out = append(out, lower)
	}
	sort.Strings(out)
	return out
}

// canonicalizeAllowedCapabilitySets canonicalizes each set in the allowlist.
func canonicalizeAllowedCapabilitySets(sets [][]string) [][]string {
	out := make([][]string, 0, len(sets))
	for _, set := range sets {
		canonical := canonicalizeCapabilitySet(set)
		out = append(out, canonical)
	}
	return out
}

// denyCgroupRulesReason checks each requested DeviceCgroupRule against the
// policy. If allowDeviceCgroupRules is true, all rules are allowed without
// inspection. If allowedDeviceCgroupRules is non-empty, each rule must
// canonicalize successfully and match an entry in the allowlist. Otherwise all
// rules are denied.
func (p containerCreatePolicy) denyCgroupRulesReason(rules []string) string {
	if p.allowDeviceCgroupRules {
		return ""
	}
	if len(p.allowedDeviceCgroupRules) == 0 {
		return "container create denied: device cgroup rules are not allowed"
	}
	for _, raw := range rules {
		canonical, ok := canonicalizeDeviceCgroupRule(raw)
		if !ok {
			return fmt.Sprintf("container create denied: device cgroup rule %q is malformed", raw)
		}
		if !deviceCgroupRuleAllowed(canonical, p.allowedDeviceCgroupRules) {
			return fmt.Sprintf("container create denied: device cgroup rule %q is not in the allowed list", raw)
		}
	}
	return ""
}

// deviceCgroupRuleAllowed reports whether the canonicalized request rule is
// permitted by at least one entry in the allowlist. Each allowlist entry is
// already in canonical form. Wildcards in the allowlist match any numeric
// value; wildcards in the request rule are only permitted when the matching
// allowlist entry also uses a wildcard at the same position.
func deviceCgroupRuleAllowed(canonical string, allowlist []string) bool {
	reqType, reqMajor, reqMinor, reqPerms, ok := splitDeviceCgroupRule(canonical)
	if !ok {
		return false
	}
	for _, allowEntry := range allowlist {
		alType, alMajor, alMinor, alPerms, alOK := splitDeviceCgroupRule(allowEntry)
		if !alOK {
			continue
		}
		if alType != reqType {
			continue
		}
		if alPerms != reqPerms {
			continue
		}
		// Major matching: allowlist wildcard accepts any request value (numeric
		// or wildcard). Request wildcard only allowed if allowlist is also wildcard.
		if !cgroupFieldMatches(alMajor, reqMajor) {
			continue
		}
		if !cgroupFieldMatches(alMinor, reqMinor) {
			continue
		}
		return true
	}
	return false
}

// cgroupFieldMatches reports whether a request field value is permitted by an
// allowlist field value. Allowlist "*" matches any request value. Request "*"
// is only accepted when the allowlist is also "*".
func cgroupFieldMatches(allowlistField, requestField string) bool {
	if allowlistField == "*" {
		return true // wildcard in allowlist matches anything
	}
	if requestField == "*" {
		return false // wildcard in request denied unless allowlist is also wildcard
	}
	return allowlistField == requestField
}

// canonicalizeDeviceCgroupRule parses and normalises a Docker cgroup device
// rule string. Docker's canonical form is "<type> <major>:<minor> <perms>"
// where type is one of 'a', 'b', or 'c'; major and minor are decimal numbers
// or '*'; and perms is a non-empty subset of 'r', 'w', 'm'. Canonicalization
// normalizes whitespace and sorts the permission characters so that "rwm",
// "mrw", etc. all produce the same canonical string.
func canonicalizeDeviceCgroupRule(raw string) (string, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return "", false
	}
	devType := fields[0]
	if devType != "a" && devType != "b" && devType != "c" {
		return "", false
	}
	majorMinor := fields[1]
	major, minor, cut := strings.Cut(majorMinor, ":")
	if !cut {
		return "", false
	}
	if !isDeviceCgroupNumber(major) || !isDeviceCgroupNumber(minor) {
		return "", false
	}
	perms := fields[2]
	if !isValidDeviceCgroupPerms(perms) {
		return "", false
	}
	sortedPerms := sortDeviceCgroupPerms(perms)
	return fmt.Sprintf("%s %s:%s %s", devType, major, minor, sortedPerms), true
}

// splitDeviceCgroupRule splits a canonical cgroup rule into its components.
func splitDeviceCgroupRule(canonical string) (devType, major, minor, perms string, ok bool) {
	fields := strings.Fields(canonical)
	if len(fields) != 3 {
		return "", "", "", "", false
	}
	devType = fields[0]
	majorMinor := fields[1]
	var cut bool
	major, minor, cut = strings.Cut(majorMinor, ":")
	if !cut {
		return "", "", "", "", false
	}
	perms = fields[2]
	return devType, major, minor, perms, true
}

// isDeviceCgroupNumber reports whether s is a valid major/minor number: a
// sequence of decimal digits or the wildcard '*'.
func isDeviceCgroupNumber(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isValidDeviceCgroupPerms reports whether perms is a non-empty string
// consisting only of 'r', 'w', and 'm' characters.
func isValidDeviceCgroupPerms(perms string) bool {
	if perms == "" {
		return false
	}
	for _, c := range perms {
		if c != 'r' && c != 'w' && c != 'm' {
			return false
		}
	}
	return true
}

// sortDeviceCgroupPerms returns the permission characters in canonical order:
// r, w, m (deduplicated). This ensures "mrw" and "rwm" both produce "rwm".
func sortDeviceCgroupPerms(perms string) string {
	chars := []byte(perms)
	sort.Slice(chars, func(i, j int) bool {
		return cgroupPermOrder(chars[i]) < cgroupPermOrder(chars[j])
	})
	// deduplicate
	deduped := chars[:0]
	seen := make(map[byte]bool)
	for _, c := range chars {
		if !seen[c] {
			seen[c] = true
			deduped = append(deduped, c)
		}
	}
	return string(deduped)
}

func cgroupPermOrder(c byte) int {
	switch c {
	case 'r':
		return 0
	case 'w':
		return 1
	case 'm':
		return 2
	default:
		return 3
	}
}

func (p containerCreatePolicy) denyBindMountReason(hostConfig containerCreateHostConfig) string {
	for _, bind := range hostConfig.Binds {
		source, ok := extractAndValidateBindSource(bind, containerCreateMount{})
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	for _, mount := range hostConfig.Mounts {
		source, ok := extractAndValidateBindSource("", mount)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	return ""
}

// denyHardeningReason enforces the simple boolean "rails": no-new-privileges,
// non-root execution, and read-only root filesystem.
func (p containerCreatePolicy) denyHardeningReason(req containerCreateRequest) string {
	if p.requireNoNewPrivileges && !hasNoNewPrivileges(req.HostConfig.SecurityOpt) {
		return "container create denied: no-new-privileges is required (set HostConfig.SecurityOpt to include \"no-new-privileges:true\")"
	}
	if p.requireNonRootUser && !isNonRootUser(req.User) {
		return "container create denied: non-root user is required (set Config.User to a non-zero UID or non-root username)"
	}
	if p.requireReadonlyRootfs && !req.HostConfig.ReadonlyRootfs {
		return "container create denied: read-only root filesystem is required (set HostConfig.ReadonlyRootfs to true)"
	}
	if p.requireDropAllCapabilities && !capDropContainsAll(req.HostConfig.CapDrop) {
		return "container create denied: HostConfig.CapDrop must include \"ALL\""
	}
	return ""
}

// denyCapabilityReason enforces the CapAdd allowlist. RequireDropAll is
// handled by denyHardeningReason.
func (p containerCreatePolicy) denyCapabilityReason(hostConfig containerCreateHostConfig) string {
	if p.allowAllCapabilities {
		return ""
	}
	for _, raw := range hostConfig.CapAdd {
		capability := normalizeCapability(raw)
		if capability == "" {
			continue
		}
		if !slices.Contains(p.allowedCapabilities, capability) {
			return fmt.Sprintf("container create denied: capability %q is not in the allowed list", capability)
		}
	}
	return ""
}

// denyResourceLimitReason enforces the resource limit requirements.
func (p containerCreatePolicy) denyResourceLimitReason(hostConfig containerCreateHostConfig) string {
	if p.requireMemoryLimit && hostConfig.Memory <= 0 {
		return "container create denied: a memory limit is required (set HostConfig.Memory)"
	}
	if p.requireCPULimit && !hasCPULimit(hostConfig) {
		return "container create denied: a CPU limit is required (set HostConfig.NanoCpus, CpuQuota, CpuPeriod, or CpuShares)"
	}
	if p.requirePidsLimit {
		if hostConfig.PidsLimit == nil || *hostConfig.PidsLimit <= 0 {
			return "container create denied: a PIDs limit is required (set HostConfig.PidsLimit to a positive value)"
		}
	}
	return ""
}

// denySecurityOptReason inspects each HostConfig.SecurityOpt entry for
// seccomp= / apparmor= / label= directives and enforces allowlists.
func (p containerCreatePolicy) denySecurityOptReason(hostConfig containerCreateHostConfig) string {
	seenSeccomp := false
	seenAppArmor := false
	for _, raw := range hostConfig.SecurityOpt {
		kind, value, ok := parseSecurityOpt(raw)
		if !ok {
			continue
		}
		switch kind {
		case "seccomp":
			seenSeccomp = true
			if len(p.allowedSeccompProfiles) > 0 {
				if !slices.Contains(p.allowedSeccompProfiles, value) {
					return fmt.Sprintf("container create denied: seccomp profile %q is not in the allowed list", value)
				}
			} else if p.denyUnconfinedSeccomp && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined seccomp profile is not allowed"
			}
		case "apparmor":
			seenAppArmor = true
			if len(p.allowedAppArmorProfiles) > 0 {
				if !slices.Contains(p.allowedAppArmorProfiles, value) {
					return fmt.Sprintf("container create denied: apparmor profile %q is not in the allowed list", value)
				}
			} else if p.denyUnconfinedAppArmor && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined apparmor profile is not allowed"
			}
		}
	}

	if len(p.allowedSeccompProfiles) > 0 && !seenSeccomp {
		if !slices.Contains(p.allowedSeccompProfiles, "default") {
			return "container create denied: a seccomp profile is required (set HostConfig.SecurityOpt to include seccomp=<profile>)"
		}
	}
	if len(p.allowedAppArmorProfiles) > 0 && !seenAppArmor {
		if !slices.Contains(p.allowedAppArmorProfiles, "default") &&
			!slices.Contains(p.allowedAppArmorProfiles, "docker-default") &&
			!slices.Contains(p.allowedAppArmorProfiles, "runtime/default") {
			return "container create denied: an apparmor profile is required (set HostConfig.SecurityOpt to include apparmor=<profile>)"
		}
	}
	return ""
}

func (p containerCreatePolicy) denyRequiredLabelsReason(req containerCreateRequest) string {
	for _, key := range p.requiredLabels {
		value, ok := req.Labels[key]
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Sprintf("container create denied: required label %q is missing or empty", key)
		}
	}
	return ""
}

func bindPathAllowed(source string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		if allowed == "/" || source == allowed || strings.HasPrefix(source, allowed+"/") {
			return true
		}
	}
	return false
}

func containerCreateBindSource(bind string) (string, bool) {
	return extractAndValidateBindSource(bind, containerCreateMount{})
}

func extractAndValidateBindSource(bind string, mount containerCreateMount) (string, bool) {
	if bind != "" {
		source, _, ok := strings.Cut(bind, ":")
		if !ok {
			return "", false
		}
		return normalizeContainerCreateBindMount(source)
	}

	if !strings.EqualFold(mount.Type, "bind") {
		return "", false
	}

	return normalizeContainerCreateBindMount(mount.Source)
}

func normalizeContainerCreateBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}

func normalizeContainerCreateDevicePath(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}

// hasNoNewPrivileges returns true when SecurityOpt contains an entry that
// turns on Docker's no-new-privileges flag. Docker accepts both
// "no-new-privileges" (treated as true) and "no-new-privileges:true".
func hasNoNewPrivileges(securityOpt []string) bool {
	for _, raw := range securityOpt {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		key, value, hasValue := splitSecurityOptKV(entry)
		if !strings.EqualFold(key, "no-new-privileges") {
			continue
		}
		if !hasValue {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(value), "true") {
			return true
		}
	}
	return false
}

// isNonRootUser returns true when the Config.User value clearly references a
// non-root identity. Empty values default to the image's user, which Sockguard
// treats as root for safety. Numeric "0" / "0:N" or the literal name "root"
// are also rejected.
func isNonRootUser(user string) bool {
	trimmed := strings.TrimSpace(user)
	if trimmed == "" {
		return false
	}
	userPart, _, _ := strings.Cut(trimmed, ":")
	userPart = strings.TrimSpace(userPart)
	if userPart == "" {
		return false
	}
	if strings.EqualFold(userPart, "root") {
		return false
	}
	if userPart == "0" {
		return false
	}
	return true
}

// capDropContainsAll returns true when CapDrop includes the literal "ALL"
// token (case-insensitive). Docker treats "ALL" specially to drop every
// default capability.
func capDropContainsAll(capDrop []string) bool {
	for _, raw := range capDrop {
		if strings.EqualFold(strings.TrimSpace(raw), "ALL") {
			return true
		}
	}
	return false
}

// hasCPULimit returns true when at least one of Docker's CPU-budget knobs is
// set. NanoCpus, CpuQuota, and CpuPeriod each individually carve out a CFS
// budget; CpuShares only sets relative weight, but operators sometimes use
// it for the same purpose, so we accept it as evidence of intent.
func hasCPULimit(h containerCreateHostConfig) bool {
	return h.NanoCpus > 0 || h.CpuQuota > 0 || h.CpuPeriod > 0 || h.CpuShares > 0
}

// parseSecurityOpt extracts the (key, value) tuple from a Docker SecurityOpt
// entry like "seccomp=unconfined" or "apparmor=docker-default". Returns ok=false
// for entries that don't follow the key=value shape (e.g. "no-new-privileges"),
// which the caller handles separately.
func parseSecurityOpt(raw string) (kind, value string, ok bool) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", "", false
	}
	key, val, hasValue := splitSecurityOptKV(entry)
	if !hasValue {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val), true
}

// splitSecurityOptKV splits a SecurityOpt token on the first '=' or ':'
// character. Docker accepts both separators in practice.
func splitSecurityOptKV(entry string) (key, value string, hasValue bool) {
	if idx := strings.IndexAny(entry, "=:"); idx >= 0 {
		return entry[:idx], entry[idx+1:], true
	}
	return entry, "", false
}

func normalizeCapability(value string) string {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	return strings.TrimPrefix(trimmed, "CAP_")
}

func normalizeCapabilityList(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeCapability(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func normalizeStringList(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}
