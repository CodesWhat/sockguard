package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/internal/imagefetch"
	"github.com/codeswhat/sockguard/internal/imagetrust"
)

// libpod_container_create.go implements the POST /libpod/containers/create
// inspector: Podman's native SpecGenerator-shaped create endpoint, distinct
// from the Docker-compat POST /containers/create this package already gates
// (container_create.go). Routing between the two is structural — the
// isLibpodContainerCreatePath / matchesContainerCreateInspection predicates
// are mutually exclusive by construction (see libpod_normalize.go and
// TestInspectorRoutingIsPathExclusive) — so a Docker-shaped body can never
// reach this inspector's gates and vice versa. See design doc #148 "Agreed
// core" item 2: fail-open body-shape confusion between the two families is
// the #1 risk this split guards against.
//
// Gate coverage is deliberately a SUBSET of container_create.go's: only the
// fields #148 PR2's scope calls out (see the design doc's "Scope of Tier-1
// inspectors" and "New libpod-only gates" sections). Fields SpecGenerator
// sends that have no gate here (DNS, health checks, working dir, ...) pass
// through unread, matching container_create.go's own posture for fields it
// has never modeled.

// LibpodContainerCreateOptions configures request-body policy checks for
// POST /libpod/containers/create. Field names mirror ContainerCreateOptions
// where the underlying semantics map onto a libpod equivalent, so operator
// knowledge transfers between the Docker-compat and native surfaces; two
// fields (AllowSystemdMode, AllowCustomIDMappings) have no Docker analog.
type LibpodContainerCreateOptions struct {
	AllowPrivileged   bool
	AllowHostNetwork  bool
	AllowHostPID      bool
	AllowHostIPC      bool
	AllowHostUserNS   bool
	AllowedBindMounts []string
	AllowAllDevices   bool
	AllowedDevices    []string

	// RestrictNamespaceSharing gates netns/pidns/ipcns/userns/utsns objects
	// of the form {"nsmode":"container","value":"<ref>"} (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: such values pass through unchecked, mirroring
	// ContainerCreateOptions.RestrictNamespaceSharing's default exactly.
	RestrictNamespaceSharing          bool
	AllowedNamespaceSharingContainers []string

	AllowAllCapabilities   bool
	AllowedCapabilities    []string
	AllowedSeccompProfiles []string
	DenyUnconfinedSeccomp  bool

	AllowedAppArmorProfiles []string
	DenyUnconfinedAppArmor  bool

	DenySelinuxDisable bool

	RequireNonRootUser    bool
	RequireReadonlyRootfs bool
	RequireMemoryLimit    bool
	RequireCPULimit       bool
	// RequireCPULimitHard narrows RequireCPULimit to accept only a genuine
	// CPU-time cap (resource_limits.cpu.quota); shares alone does not
	// satisfy it — mirrors ContainerCreateOptions.RequireCPULimitHard.
	RequireCPULimitHard bool
	RequirePidsLimit    bool

	AllowSysctls bool

	// ImageTrust configures cosign-backed signature verification, reusing
	// the identical machinery container_create.go uses against the "image"
	// field.
	ImageTrust ImageTrustOptions

	// AllowSystemdMode permits POST /libpod/containers/create with a
	// "systemd" value other than "false" (SpecGenerator's own default, sent
	// even when --systemd was never passed on the CLI — see
	// testdata/libpod/basic_create.json — is "true"). systemd=true/always
	// enables Podman's systemd-aware mount/cgroup elevation for the
	// container's init process; there is no Docker Engine API analog.
	// Default false: every create is denied unless the body explicitly
	// carries "false" or this is set.
	AllowSystemdMode bool

	// AllowCustomIDMappings permits a non-default idmappings.UIDMap/GIDMap
	// or AutoUserNs (podman --uidmap/--gidmap/--userns=auto). A blunt gate
	// for v1.6 — no range-overlap or host-UID-collision analysis; see the
	// design doc's "Deferred past v1.6" list. Default false.
	AllowCustomIDMappings bool
}

type libpodContainerCreatePolicy struct {
	allowPrivileged   bool
	allowHostNetwork  bool
	allowHostPID      bool
	allowHostIPC      bool
	allowHostUserNS   bool
	allowedBindMounts []string
	allowAllDevices   bool
	allowedDevices    []string

	restrictNamespaceSharing          bool
	allowedNamespaceSharingContainers []string

	allowAllCapabilities   bool
	allowedCapabilities    []string
	allowedSeccompProfiles []string
	denyUnconfinedSeccomp  bool

	allowedAppArmorProfiles []string
	denyUnconfinedAppArmor  bool

	denySelinuxDisable bool

	requireNonRootUser    bool
	requireReadonlyRootfs bool
	requireMemoryLimit    bool
	requireCPULimit       bool
	requireCPULimitHard   bool
	requirePidsLimit      bool

	allowSysctls bool

	allowSystemdMode      bool
	allowCustomIDMappings bool

	imageTrustVerifier imageVerifier
	imageFetcher       signatureFetcher
	imageTrustCfg      imagetrust.Config
	imageTrustTimeout  time.Duration
	imageTrustInitErr  error
}

func newLibpodContainerCreatePolicy(opts LibpodContainerCreateOptions) libpodContainerCreatePolicy {
	allowedBindMounts := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowedBindMounts, normalized) {
			continue
		}
		allowedBindMounts = append(allowedBindMounts, normalized)
	}

	allowedDevices := make([]string, 0, len(opts.AllowedDevices))
	for _, device := range opts.AllowedDevices {
		normalized, ok := normalizeContainerCreateDevicePath(device)
		if !ok || slices.Contains(allowedDevices, normalized) {
			continue
		}
		allowedDevices = append(allowedDevices, normalized)
	}

	p := libpodContainerCreatePolicy{
		allowPrivileged:                   opts.AllowPrivileged,
		allowHostNetwork:                  opts.AllowHostNetwork,
		allowHostPID:                      opts.AllowHostPID,
		allowHostIPC:                      opts.AllowHostIPC,
		allowHostUserNS:                   opts.AllowHostUserNS,
		allowedBindMounts:                 allowedBindMounts,
		allowAllDevices:                   opts.AllowAllDevices,
		allowedDevices:                    allowedDevices,
		restrictNamespaceSharing:          opts.RestrictNamespaceSharing,
		allowedNamespaceSharingContainers: normalizeStringList(opts.AllowedNamespaceSharingContainers),
		allowAllCapabilities:              opts.AllowAllCapabilities,
		allowedCapabilities:               normalizeCapabilityList(opts.AllowedCapabilities),
		allowedSeccompProfiles:            normalizeStringList(opts.AllowedSeccompProfiles),
		denyUnconfinedSeccomp:             opts.DenyUnconfinedSeccomp,
		allowedAppArmorProfiles:           normalizeStringList(opts.AllowedAppArmorProfiles),
		denyUnconfinedAppArmor:            opts.DenyUnconfinedAppArmor,
		denySelinuxDisable:                opts.DenySelinuxDisable,
		requireNonRootUser:                opts.RequireNonRootUser,
		requireReadonlyRootfs:             opts.RequireReadonlyRootfs,
		requireMemoryLimit:                opts.RequireMemoryLimit,
		requireCPULimit:                   opts.RequireCPULimit,
		requireCPULimitHard:               opts.RequireCPULimitHard,
		requirePidsLimit:                  opts.RequirePidsLimit,
		allowSysctls:                      opts.AllowSysctls,
		allowSystemdMode:                  opts.AllowSystemdMode,
		allowCustomIDMappings:             opts.AllowCustomIDMappings,
	}

	itf := buildImageTrustFields(opts.ImageTrust)
	p.imageTrustVerifier = itf.verifier
	p.imageFetcher = itf.fetcher
	p.imageTrustCfg = itf.cfg
	p.imageTrustTimeout = itf.timeout
	p.imageTrustInitErr = itf.initErr

	return p
}

func (p libpodContainerCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodContainerCreatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}
	if p.imageTrustInitErr != nil {
		return fmt.Sprintf("libpod container create denied: image trust policy initialization error: %s", p.imageTrustInitErr.Error()), nil
	}
	body, err := readBoundedBody(r, maxContainerCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var createReq libpodContainerCreateRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod container create request body is not valid JSON; denying", err)
		return "libpod container create denied: malformed JSON request body", nil
	}

	if !p.allowPrivileged && createReq.Privileged {
		return "libpod container create denied: privileged containers are not allowed", nil
	}
	if !p.allowHostNetwork && createReq.NetNS.isHost() {
		return "libpod container create denied: host network namespace is not allowed", nil
	}
	if !p.allowHostPID && createReq.PidNS.isHost() {
		return "libpod container create denied: host PID namespace is not allowed", nil
	}
	if !p.allowHostIPC && createReq.IpcNS.isHost() {
		return "libpod container create denied: host IPC namespace is not allowed", nil
	}
	if !p.allowHostUserNS && createReq.UserNS.isHost() {
		return "libpod container create denied: host user namespace is not allowed", nil
	}
	if denyReason := p.denyNamespaceSharingReason(createReq); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyBindMountReason(createReq.Mounts); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyDeviceReason(createReq.Devices); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := capabilityAddDenyReason(createReq.CapAdd, p.allowAllCapabilities, p.allowedCapabilities, "libpod container create"); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySeccompReason(createReq.SeccompProfilePath); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyAppArmorReason(createReq.ApparmorProfile); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denySelinuxReason(createReq.SelinuxOpts); denyReason != "" {
		return denyReason, nil
	}
	if p.requireNonRootUser && !isNonRootUser(createReq.User) {
		return "libpod container create denied: non-root user is required (set User to a non-zero UID or non-root username)", nil
	}
	if p.requireReadonlyRootfs && !createReq.ReadOnlyFilesystem {
		return "libpod container create denied: read-only root filesystem is required (set read_only_filesystem to true)", nil
	}
	if denyReason := p.denyResourceLimitReason(createReq.ResourceLimits); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowSysctls && len(createReq.Sysctl) > 0 {
		return "libpod container create denied: setting sysctls is not allowed", nil
	}
	if denyReason := p.denySystemdModeReason(createReq.Systemd); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyIDMappingsReason(createReq.IDMapping); denyReason != "" {
		return denyReason, nil
	}

	if p.imageTrustVerifier != nil {
		imageRef := strings.TrimSpace(createReq.Image)
		fields := imageTrustFields{
			verifier: p.imageTrustVerifier,
			fetcher:  p.imageFetcher,
			cfg:      p.imageTrustCfg,
			timeout:  p.imageTrustTimeout,
		}
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, fields, imageRef, "libpod container create")
		if denyReason != "" {
			return denyReason, nil
		}
		if verifiedDigest != "" {
			pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest)
			if perr != nil {
				return "", fmt.Errorf("pin verified image digest: %w", perr)
			}
			if pinned != imageRef {
				rewritten, rerr := rewriteLibpodJSONImageField(body, pinned)
				if rerr != nil {
					return "", fmt.Errorf("pin verified image digest: %w", rerr)
				}
				r.Body = io.NopCloser(bytes.NewReader(rewritten))
				r.ContentLength = int64(len(rewritten))
			}
		}
	}

	return "", nil
}

// denyNamespaceSharingReason enforces restrictNamespaceSharing against every
// namespace field that can join another container's namespace via
// {"nsmode":"container","value":"<ref>"}: netns, pidns, ipcns, userns, utsns.
// Mirrors containerCreatePolicy.denyNamespaceSharingReason's field coverage
// (cgroupns is intentionally excluded there too).
func (p libpodContainerCreatePolicy) denyNamespaceSharingReason(req libpodContainerCreateRequest) string {
	if !p.restrictNamespaceSharing {
		return ""
	}
	fields := [...]struct {
		label string
		ns    libpodNamespace
	}{
		{"network", req.NetNS},
		{"PID", req.PidNS},
		{"IPC", req.IpcNS},
		{"user", req.UserNS},
		{"UTS", req.UtsNS},
	}
	for _, f := range fields {
		ref, ok := f.ns.containerRef()
		if !ok {
			continue
		}
		if len(p.allowedNamespaceSharingContainers) == 0 {
			return fmt.Sprintf("libpod container create denied: %s namespace sharing with another container is not allowed", f.label)
		}
		if !slices.Contains(p.allowedNamespaceSharingContainers, ref) {
			return fmt.Sprintf("libpod container create denied: namespace-sharing target %q is not in the allowed list", ref)
		}
	}
	return ""
}

// denyBindMountReason enforces allowedBindMounts against every "bind"-typed
// entry of the top-level "mounts" array. Named-volume mounts (the "volumes"
// array) reference a volume by name, not a host filesystem path, so they
// carry no bind-mount attack surface and are not checked here.
func (p libpodContainerCreatePolicy) denyBindMountReason(mounts []libpodMount) string {
	for _, mount := range mounts {
		if !strings.EqualFold(mount.Type, "bind") {
			continue
		}
		source, ok := normalizeBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("libpod container create denied: bind mount source %q is not allowlisted", source)
	}
	return ""
}

// denyDeviceReason enforces allowAllDevices/allowedDevices against every
// entry of the top-level "devices" array.
func (p libpodContainerCreatePolicy) denyDeviceReason(devices []libpodDevice) string {
	if p.allowAllDevices {
		return ""
	}
	for _, device := range devices {
		rawHostPath, ok := splitLibpodDevicePath(device.Path)
		hostPath, normOK := normalizeContainerCreateDevicePath(rawHostPath)
		if !ok || !normOK || !bindPathAllowed(hostPath, p.allowedDevices) {
			return fmt.Sprintf("libpod container create denied: device %q is not allowlisted", device.Path)
		}
	}
	return ""
}

// denySeccompReason gates seccomp_profile_path. An empty path is
// SpecGenerator's "default profile" sentinel (see basic_create.json), mapped
// onto the allowlist's "default" entry the same way container_create.go's
// denySecurityOptReason treats an unset seccomp= SecurityOpt.
func (p libpodContainerCreatePolicy) denySeccompReason(profilePath string) string {
	profilePath = strings.TrimSpace(profilePath)
	if p.denyUnconfinedSeccomp && strings.EqualFold(profilePath, "unconfined") {
		return "libpod container create denied: unconfined seccomp profile is not allowed"
	}
	if len(p.allowedSeccompProfiles) == 0 {
		return ""
	}
	effective := profilePath
	if effective == "" {
		effective = "default"
	}
	if !slices.Contains(p.allowedSeccompProfiles, effective) {
		return fmt.Sprintf("libpod container create denied: seccomp profile %q is not in the allowed list", effective)
	}
	return ""
}

// denyAppArmorReason gates apparmor_profile. An empty profile is
// SpecGenerator's "container-default confinement" sentinel, mapped onto the
// allowlist's "default" entry — mirrors container_create.go's
// denySecurityOptReason treatment of the analogous Docker default synonyms.
func (p libpodContainerCreatePolicy) denyAppArmorReason(profile string) string {
	profile = strings.TrimSpace(profile)
	if p.denyUnconfinedAppArmor && strings.EqualFold(profile, "unconfined") {
		return "libpod container create denied: unconfined apparmor profile is not allowed"
	}
	if len(p.allowedAppArmorProfiles) == 0 {
		return ""
	}
	effective := profile
	if effective == "" {
		effective = "default"
	}
	if !slices.Contains(p.allowedAppArmorProfiles, effective) {
		return fmt.Sprintf("libpod container create denied: apparmor profile %q is not in the allowed list", effective)
	}
	return ""
}

// denySelinuxReason gates selinux_opts. The only libpod-specific SELinux
// posture PR2 scopes is "disable" (see design doc "Scope" item 2); per-field
// label overrides (user:/role:/type:/level:) are not gated here, matching
// container_create.go's DenySelinuxLabelOverride being a separate,
// independently-scoped flag this inspector does not carry.
func (p libpodContainerCreatePolicy) denySelinuxReason(opts []string) string {
	if !p.denySelinuxDisable {
		return ""
	}
	for _, raw := range opts {
		if strings.EqualFold(strings.TrimSpace(raw), "disable") {
			return "libpod container create denied: selinux disable is not allowed"
		}
	}
	return ""
}

// denyResourceLimitReason enforces requireMemoryLimit/requireCPULimit/
// requireCPULimitHard/requirePidsLimit against resource_limits. Mirrors
// container_create.go's resourceLimitDenyReason semantics: requireCPULimit
// accepts any of quota/period/shares as evidence of intent; requireCPULimitHard
// only accepts quota (a genuine CFS time cap — shares/period alone enforce
// nothing on an uncontended host).
func (p libpodContainerCreatePolicy) denyResourceLimitReason(limits libpodResourceLimits) string {
	if p.requireMemoryLimit && limits.Memory.Limit <= 0 {
		return "libpod container create denied: a memory limit is required (set resource_limits.memory.limit)"
	}
	if p.requireCPULimit && limits.CPU.Quota <= 0 && limits.CPU.Period == 0 && limits.CPU.Shares == 0 {
		return "libpod container create denied: a CPU limit is required (set resource_limits.cpu.quota, period, or shares)"
	}
	if p.requireCPULimitHard && limits.CPU.Quota <= 0 {
		return "libpod container create denied: a hard CPU cap is required (set resource_limits.cpu.quota; shares is a relative priority weight, not a cap, and does not satisfy this check)"
	}
	if p.requirePidsLimit && limits.Pids.Limit <= 0 {
		return "libpod container create denied: a PIDs limit is required (set resource_limits.pids.limit to a positive value)"
	}
	return ""
}

// denySystemdModeReason denies any "systemd" value other than the literal
// "false" unless allowSystemdMode is set. SpecGenerator sends a non-empty
// default ("true") even when --systemd was never passed on the CLI — see
// basic_create.json — so this gate denies the common case by default; that
// is the intended, deliberately strict posture for a libpod-only gate with
// no Docker Engine API analog (see LibpodContainerCreateOptions.AllowSystemdMode).
func (p libpodContainerCreatePolicy) denySystemdModeReason(systemd string) string {
	if p.allowSystemdMode {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(systemd), "false") {
		return ""
	}
	return fmt.Sprintf("libpod container create denied: systemd mode %q is not allowed (set allow_systemd_mode: true, or use systemd=false)", systemd)
}

// denyIDMappingsReason is the "blunt gate" (design doc term) on
// idmappings: any non-default UID/GID mapping or --userns=auto request is
// denied unless allowCustomIDMappings is set. No range-overlap or
// host-UID-collision analysis — see the design doc's "Deferred past v1.6"
// list.
func (p libpodContainerCreatePolicy) denyIDMappingsReason(idm libpodIDMappings) string {
	if p.allowCustomIDMappings {
		return ""
	}
	if len(idm.UIDMap) > 0 || len(idm.GIDMap) > 0 || idm.AutoUserNs {
		return "libpod container create denied: custom UID/GID mappings are not allowed (set allow_custom_id_mappings: true)"
	}
	return ""
}

// foldedRawKeysLibpod returns every key in m that case-folds to canonical.
// Podman's own client never emits case-variant keys, but a crafted body
// could — see rewriteLibpodJSONImageField's doc comment for why this must be
// checked before pinning a verified image reference into the forwarded body.
func foldedRawKeysLibpod(m map[string]json.RawMessage, canonical string) []string {
	var out []string
	for k := range m {
		if strings.EqualFold(k, canonical) {
			out = append(out, k)
		}
	}
	return out
}

// rewriteLibpodJSONImageField returns body with its (case-insensitive)
// "image" field replaced by pinned, closing the same verify->pull TOCTOU
// rewriteJSONImageField closes for Docker-shaped bodies (container_create.go)
// — here for libpod's lowercase "image" field instead of "Image". Other
// fields are preserved byte-for-byte (RawMessage).
func rewriteLibpodJSONImageField(body []byte, pinned string) ([]byte, error) {
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	variants := foldedRawKeysLibpod(fields, "image")
	if len(variants) > 1 {
		return nil, fmt.Errorf("ambiguous libpod container image: %d case-variant \"image\" keys", len(variants))
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return nil, err
	}
	for _, k := range variants {
		delete(fields, k)
	}
	fields["image"] = encoded
	return json.Marshal(fields)
}
