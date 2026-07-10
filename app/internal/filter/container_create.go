package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/codeswhat/sockguard/internal/imagefetch"
	"github.com/codeswhat/sockguard/internal/imagetrust"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// maxContainerCreateBodyBytes caps the request body Sockguard will read when
// inspecting POST /containers/create. Docker's own container-create payloads
// are at most a few KiB even for complex specs, so a 1 MiB ceiling is
// generous while still preventing a malicious or misbehaving client from
// OOMing the proxy with an unbounded body.
const maxContainerCreateBodyBytes = 1 << 20 // 1 MiB

// ImageTrustOptions configures cosign signature verification for images
// referenced in POST /containers/create.
type ImageTrustOptions struct {
	// Mode is "off" | "warn" | "enforce". Default: off.
	Mode string
	// AllowedSigningKeys lists PEM-encoded public keys trusted to sign images.
	AllowedSigningKeys []SigningKeyOptions
	// AllowedKeyless lists Fulcio-backed identity patterns.
	AllowedKeyless []KeylessOptions
	// RequireRekorInclusion requires a Rekor tlog entry for keyless bundles.
	RequireRekorInclusion bool
	// VerifyTimeout overrides the default per-verification timeout.
	VerifyTimeout string
}

// SigningKeyOptions is one allowed signing key entry.
type SigningKeyOptions struct {
	PEM string
}

// KeylessOptions is one allowed keyless identity entry.
type KeylessOptions struct {
	Issuer         string
	SubjectPattern string
}

// imageVerifier is the narrow interface used by containerCreatePolicy so tests
// can inject a stub without a real registry or Rekor connection.
type imageVerifier interface {
	Verify(ctx context.Context, imageRef, digestHex string, entity verify.SignedEntity) error
}

// signatureFetcher resolves an image reference to the set of cosign signature
// candidates attached to it in the registry. The production implementation is
// internal/imagefetch.Fetcher; tests inject a stub to avoid registry I/O.
type signatureFetcher interface {
	FetchCandidates(ctx context.Context, logger *slog.Logger, imageRef string) ([]imagetrust.Candidate, error)
}

// ContainerCreateOptions configures request-body policy checks for
// POST /containers/create.
type ContainerCreateOptions struct {
	AllowPrivileged          bool
	AllowHostNetwork         bool
	AllowHostPID             bool
	AllowHostIPC             bool
	AllowedBindMounts        []string
	AllowAllDevices          bool
	AllowedDevices           []string
	AllowDeviceRequests      bool
	AllowedDeviceRequests    []AllowedDeviceRequestEntry
	AllowDeviceCgroupRules   bool
	AllowedDeviceCgroupRules []string

	RequireNoNewPrivileges     bool
	RequireNonRootUser         bool
	RequireReadonlyRootfs      bool
	RequireDropAllCapabilities bool
	AllowAllCapabilities       bool
	AllowedCapabilities        []string
	RequireMemoryLimit         bool
	RequireCPULimit            bool
	// RequireCPULimitHard narrows RequireCPULimit to accept only a genuine
	// CPU-time cap (NanoCpus or CpuQuota); CpuShares alone does not satisfy
	// it. Independent of RequireCPULimit — see hasHardCPULimit.
	RequireCPULimitHard     bool
	RequirePidsLimit        bool
	AllowedSeccompProfiles  []string
	DenyUnconfinedSeccomp   bool
	AllowedAppArmorProfiles []string
	DenyUnconfinedAppArmor  bool
	AllowHostUserNS         bool
	// RestrictNamespaceSharing gates HostConfig.NetworkMode/PidMode/IpcMode/
	// UsernsMode values of the form "container:<ref>" (join another
	// container's namespace) against AllowedNamespaceSharingContainers.
	// Default false: container:<ref> values continue to pass through
	// unchecked, matching today's behavior exactly — an independent,
	// orthogonal gate from AllowHostNetwork/PID/IPC/UserNS, which only ever
	// match the literal "host" value and continue to do so unchanged.
	RestrictNamespaceSharing bool
	// AllowedNamespaceSharingContainers allowlists the container:<ref>
	// targets permitted when RestrictNamespaceSharing is true. Only
	// consulted when RestrictNamespaceSharing is true; empty denies every
	// container: ref. Mirrors the AllowDeviceRequests/AllowedDeviceRequests
	// bool-escape-hatch-plus-allowlist shape, not AllowedRuntimes (which
	// denies non-empty values by default) — this field defaults to
	// pass-through, not deny-by-default.
	AllowedNamespaceSharingContainers []string
	// DenyNamespacePathMode denies HostConfig.NetworkMode values with an
	// "ns:" prefix (case-insensitive) — Docker's raw host-namespace-file
	// attachment form, which bypasses the "host" literal check entirely.
	// Scoped to NetworkMode only. Default false (pass-through).
	DenyNamespacePathMode bool
	RequiredLabels        []string

	// AllowedRuntimes allowlists HostConfig.Runtime values. An empty Runtime
	// selects the daemon default and is always permitted; any other (non-empty)
	// runtime is denied unless listed here. This prevents a client from silently
	// selecting an alternate OCI runtime with different (or absent) seccomp/
	// AppArmor defaults to escape the profile policy enforced for the default
	// runtime. Runtime names are matched case-sensitively (as in daemon.json).
	AllowedRuntimes []string

	// AllowSysctls permits setting kernel parameters via HostConfig.Sysctls.
	// Default false: any non-empty Sysctls map is denied.
	AllowSysctls bool

	// DenySelinuxDisable prevents label=disable (and label:disable) which
	// turns off SELinux confinement for the container. Default false
	// (pass-through) for backward-compatibility.
	DenySelinuxDisable bool

	// DenySelinuxLabelOverride denies label=user:, label=role:, label=type:,
	// label=level: SecurityOpt entries that customize the SELinux context.
	// Default false (pass-through). Independent of DenySelinuxDisable.
	DenySelinuxLabelOverride bool

	// DenyUnconfinedSystemPaths prevents systempaths=unconfined in SecurityOpt
	// AND rejects requests that set MaskedPaths or ReadonlyPaths to an empty
	// slice (the direct-API equivalent of systempaths=unconfined). Default false
	// for backward-compatibility.
	DenyUnconfinedSystemPaths bool

	// ImageTrust configures cosign-backed signature verification.
	ImageTrust ImageTrustOptions
}

type containerCreatePolicy struct {
	allowPrivileged          bool
	allowHostNetwork         bool
	allowHostPID             bool
	allowHostIPC             bool
	allowedBindMounts        []string
	allowAllDevices          bool
	allowedDevices           []string
	allowDeviceRequests      bool
	allowedDeviceRequests    []allowedDeviceRequestEntry
	allowDeviceCgroupRules   bool
	allowedDeviceCgroupRules []string

	requireNoNewPrivileges            bool
	requireNonRootUser                bool
	requireReadonlyRootfs             bool
	requireDropAllCapabilities        bool
	allowAllCapabilities              bool
	allowedCapabilities               []string
	requireMemoryLimit                bool
	requireCPULimit                   bool
	requireCPULimitHard               bool
	requirePidsLimit                  bool
	allowedSeccompProfiles            []string
	denyUnconfinedSeccomp             bool
	allowedAppArmorProfiles           []string
	denyUnconfinedAppArmor            bool
	allowHostUserNS                   bool
	restrictNamespaceSharing          bool
	allowedNamespaceSharingContainers []string
	denyNamespacePathMode             bool
	requiredLabels                    []string
	allowSysctls                      bool
	allowedRuntimes                   []string

	denySelinuxDisable        bool
	denySelinuxLabelOverride  bool
	denyUnconfinedSystemPaths bool

	// Image trust — non-nil when mode != off.
	imageTrustVerifier imageVerifier
	imageFetcher       signatureFetcher
	imageTrustCfg      imagetrust.Config
	imageTrustTimeout  time.Duration
	// imageTrustInitErr holds any error that occurred while building the image
	// trust verifier at policy construction time. When non-nil, inspect returns
	// a denial reason so that a misconfigured trust policy fails closed rather
	// than silently falling through to Docker.
	imageTrustInitErr error
}

func newContainerCreatePolicy(opts ContainerCreateOptions) containerCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
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

	p := containerCreatePolicy{
		allowPrivileged:                   opts.AllowPrivileged,
		allowHostNetwork:                  opts.AllowHostNetwork,
		allowHostPID:                      opts.AllowHostPID,
		allowHostIPC:                      opts.AllowHostIPC,
		allowedBindMounts:                 allowed,
		allowAllDevices:                   opts.AllowAllDevices,
		allowedDevices:                    allowedDevices,
		allowDeviceRequests:               opts.AllowDeviceRequests,
		allowedDeviceRequests:             allowedDeviceRequests,
		allowDeviceCgroupRules:            opts.AllowDeviceCgroupRules,
		allowedDeviceCgroupRules:          allowedDeviceCgroupRules,
		requireNoNewPrivileges:            opts.RequireNoNewPrivileges,
		requireNonRootUser:                opts.RequireNonRootUser,
		requireReadonlyRootfs:             opts.RequireReadonlyRootfs,
		requireDropAllCapabilities:        opts.RequireDropAllCapabilities,
		allowAllCapabilities:              opts.AllowAllCapabilities,
		allowedCapabilities:               normalizeCapabilityList(opts.AllowedCapabilities),
		requireMemoryLimit:                opts.RequireMemoryLimit,
		requireCPULimit:                   opts.RequireCPULimit,
		requireCPULimitHard:               opts.RequireCPULimitHard,
		requirePidsLimit:                  opts.RequirePidsLimit,
		allowedSeccompProfiles:            normalizeStringList(opts.AllowedSeccompProfiles),
		denyUnconfinedSeccomp:             opts.DenyUnconfinedSeccomp,
		allowedAppArmorProfiles:           normalizeStringList(opts.AllowedAppArmorProfiles),
		denyUnconfinedAppArmor:            opts.DenyUnconfinedAppArmor,
		allowHostUserNS:                   opts.AllowHostUserNS,
		restrictNamespaceSharing:          opts.RestrictNamespaceSharing,
		allowedNamespaceSharingContainers: normalizeStringList(opts.AllowedNamespaceSharingContainers),
		denyNamespacePathMode:             opts.DenyNamespacePathMode,
		requiredLabels:                    normalizeStringList(opts.RequiredLabels),
		allowSysctls:                      opts.AllowSysctls,
		allowedRuntimes:                   normalizeStringList(opts.AllowedRuntimes),
		denySelinuxDisable:                opts.DenySelinuxDisable,
		denySelinuxLabelOverride:          opts.DenySelinuxLabelOverride,
		denyUnconfinedSystemPaths:         opts.DenyUnconfinedSystemPaths,
	}

	// Build image trust verifier. Errors are stored in imageTrustInitErr so
	// that inspect can return a denial reason instead of silently allowing
	// requests through (fail-closed rather than fail-open).
	itf := buildImageTrustFields(opts.ImageTrust)
	p.imageTrustVerifier = itf.verifier
	p.imageFetcher = itf.fetcher
	p.imageTrustCfg = itf.cfg
	p.imageTrustTimeout = itf.timeout
	p.imageTrustInitErr = itf.initErr

	return p
}

// imageTrustFields holds the constructed cosign verification machinery shared
// by the container-create and service inspectors.
type imageTrustFields struct {
	verifier imageVerifier
	fetcher  signatureFetcher
	cfg      imagetrust.Config
	timeout  time.Duration
	initErr  error
}

// buildImageTrustFields constructs the cosign verifier and signature fetcher for
// the given options. Any construction error is returned in initErr so callers
// fail closed (deny) rather than silently allowing unverified images. When the
// mode is off/empty the zero value is returned (inactive).
func buildImageTrustFields(opts ImageTrustOptions) imageTrustFields {
	var f imageTrustFields
	if mode := imagetrust.Mode(opts.Mode); mode == imagetrust.ModeOff || mode == "" {
		return f
	}
	cfg, err := imagetrust.BuildConfig(buildImageTrustRaw(opts))
	if err != nil {
		f.initErr = fmt.Errorf("image trust policy build failed: %w", err)
		return f
	}
	// Keyless verification needs a TUF-backed trust root for the Fulcio and
	// Rekor public keys. Fetch it once here; a failure (no network, read-only
	// TUF cache) must fail closed rather than allow unverified keyless images.
	// Keyed-only configs skip this entirely.
	if len(cfg.AllowedKeyless) > 0 {
		tm, tmErr := imagetrust.LoadLiveTrustedRoot()
		if tmErr != nil {
			f.initErr = fmt.Errorf("image trust keyless trust root load failed: %w", tmErr)
			return f
		}
		cfg.TrustedMaterial = tm
	}
	v, verr := imagetrust.New(cfg)
	if verr != nil {
		f.initErr = fmt.Errorf("image trust verifier construction failed: %w", verr)
		return f
	}
	f.verifier = v
	f.fetcher = imagefetch.NewFetcher()
	f.cfg = cfg
	f.timeout = cfg.VerifyTimeout
	if f.timeout == 0 {
		f.timeout = imagetrust.VerifyTimeout
	}
	return f
}

// verifyImageTrust fetches and verifies the cosign signatures for imageRef under
// the configured mode, returning a deny reason ("" when allowed) and the
// verified image manifest digest ("" when nothing was verified, e.g. an empty
// ref or warn-mode bypass). subject prefixes the deny reason.
func verifyImageTrust(ctx context.Context, logger *slog.Logger, f imageTrustFields, imageRef, subject string) (denyReason, verifiedDigest string) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		// Require an explicit image reference when trust verification is
		// configured. Docker itself rejects creates without an image, but the
		// explicit deny preserves fail-closed behavior at the Sockguard layer
		// and avoids skipping the verifier call entirely.
		return fmt.Sprintf("%s denied: image field is required when image trust is configured", subject), ""
	}
	if f.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}
	// Fetch the cosign signatures attached to the image in the registry and
	// reconstruct a verifiable bundle for each, then verify under the configured
	// mode. A fetch failure (unsigned image, registry unreachable) is surfaced to
	// the verifier as a verification failure so enforce mode denies and warn mode
	// logs-and-allows.
	var (
		candidates []imagetrust.Candidate
		fetchErr   error
	)
	if f.fetcher != nil {
		candidates, fetchErr = f.fetcher.FetchCandidates(ctx, logger, imageRef)
	} else {
		fetchErr = fmt.Errorf("image trust misconfigured: no signature fetcher")
	}
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, f.verifier, f.cfg, logger, imageRef, candidates, fetchErr)
	if !outcome.Allowed {
		return fmt.Sprintf("%s denied: image trust verification failed for %s: %s", subject, imageRef, outcome.FailureMsg), ""
	}
	return "", outcome.VerifiedDigest
}

// rewriteJSONImageField returns body with its top-level "Image" field replaced
// by pinned. Other fields are preserved byte-for-byte (RawMessage) so large
// integer fields such as Memory are not corrupted by a float round-trip.
func rewriteJSONImageField(body []byte, pinned string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return nil, err
	}
	fields["Image"] = encoded
	return json.Marshal(fields)
}

func buildImageTrustRaw(opts ImageTrustOptions) imagetrust.RawConfig {
	keys := make([]imagetrust.SigningKeyConfig, 0, len(opts.AllowedSigningKeys))
	for _, k := range opts.AllowedSigningKeys {
		keys = append(keys, imagetrust.SigningKeyConfig{PEM: k.PEM})
	}
	kl := make([]imagetrust.KeylessConfig, 0, len(opts.AllowedKeyless))
	for _, k := range opts.AllowedKeyless {
		kl = append(kl, imagetrust.KeylessConfig{
			Issuer:         k.Issuer,
			SubjectPattern: k.SubjectPattern,
		})
	}
	return imagetrust.RawConfig{
		Mode:                  imagetrust.Mode(opts.Mode),
		AllowedSigningKeys:    keys,
		AllowedKeyless:        kl,
		RequireRekorInclusion: opts.RequireRekorInclusion,
		VerifyTimeoutStr:      opts.VerifyTimeout,
	}
}

func (p containerCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" || r.Body == nil {
		return "", nil
	}
	// Fail closed if the image trust policy failed to initialize: a
	// misconfigured trust config must not silently allow all images through.
	if p.imageTrustInitErr != nil {
		return fmt.Sprintf("container create denied: image trust policy initialization error: %s", p.imageTrustInitErr.Error()), nil
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
		// Deny malformed JSON bodies rather than passing them through. A valid
		// create request must be parseable; letting an unparseable body reach
		// Docker would silently skip all policy checks (fail-open).
		if logger != nil {
			logger.DebugContext(r.Context(), "container create request body is not valid JSON; denying", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "container create denied: malformed JSON request body", nil
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
	if denyReason := p.denyNamespaceSharingReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if p.denyNamespacePathMode && isNamespacePathMode(createReq.HostConfig.NetworkMode) {
		return "container create denied: ns: namespace path mode is not allowed", nil
	}
	if !p.allowSysctls && len(createReq.HostConfig.Sysctls) > 0 {
		return "container create denied: setting sysctls is not allowed", nil
	}
	if len(createReq.HostConfig.VolumesFrom) > 0 {
		return "container create denied: VolumesFrom is not allowed", nil
	}
	if isHostNamespaceMode(createReq.HostConfig.UTSMode) {
		return "container create denied: host UTS mode is not allowed", nil
	}
	if strings.TrimSpace(createReq.HostConfig.CgroupParent) != "" {
		return "container create denied: custom cgroup parent is not allowed", nil
	}
	if len(createReq.HostConfig.GroupAdd) > 0 {
		return "container create denied: supplemental group IDs are not allowed", nil
	}
	if len(createReq.HostConfig.ExtraHosts) > 0 {
		return "container create denied: ExtraHosts is not allowed", nil
	}
	if runtime := strings.TrimSpace(createReq.HostConfig.Runtime); runtime != "" && !slices.Contains(p.allowedRuntimes, runtime) {
		return fmt.Sprintf("container create denied: runtime %q is not allowlisted", runtime), nil
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
	if denyReason := p.denySystemPathsReason(createReq.HostConfig); denyReason != "" {
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

	if p.imageTrustVerifier != nil {
		imageRef := strings.TrimSpace(createReq.Image)
		fields := imageTrustFields{
			verifier: p.imageTrustVerifier,
			fetcher:  p.imageFetcher,
			cfg:      p.imageTrustCfg,
			timeout:  p.imageTrustTimeout,
		}
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, fields, imageRef, "container create")
		if denyReason != "" {
			return denyReason, nil
		}
		// Close the verify→pull TOCTOU: forward the digest-pinned reference that
		// was actually verified, so a registry that swaps the tag after
		// verification cannot make dockerd pull an unsigned image.
		if verifiedDigest != "" {
			if pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest); perr == nil && pinned != imageRef {
				rewritten, rerr := rewriteJSONImageField(body, pinned)
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

func isHostNamespaceMode(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "host")
}

// ContainerNamespaceRef reports whether mode has the form "container:<ref>"
// — Docker's syntax for joining another container's network/PID/IPC/user
// namespace — and, if so, returns the trimmed ref. The "container:" prefix
// is matched case-insensitively (as Docker itself does); the ref's case is
// preserved, since container IDs and names are case-sensitive. An empty ref
// ("container:" alone, or all-whitespace after the prefix) is rejected.
// Exported so the ownership package can reuse this exact parser instead of
// duplicating it.
func ContainerNamespaceRef(mode string) (ref string, ok bool) {
	trimmed := strings.TrimSpace(mode)
	const prefix = "container:"
	if len(trimmed) <= len(prefix) || !strings.EqualFold(trimmed[:len(prefix)], prefix) {
		return "", false
	}
	ref = strings.TrimSpace(trimmed[len(prefix):])
	if ref == "" {
		return "", false
	}
	return ref, true
}

// isNamespacePathMode reports whether mode has a case-insensitive "ns:"
// prefix — Docker's syntax for attaching to an arbitrary host network
// namespace file path, a form that bypasses the "host" literal check
// entirely.
func isNamespacePathMode(mode string) bool {
	trimmed := strings.TrimSpace(mode)
	const prefix = "ns:"
	return len(trimmed) >= len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix)
}

// denyNamespaceSharingReason enforces restrictNamespaceSharing against every
// HostConfig field that can join another container's namespace via
// "container:<ref>": NetworkMode, PidMode, IpcMode, and (defensively —
// stock Docker's support for a container: form here is unconfirmed)
// UsernsMode. UTSMode is deliberately excluded: it has no allow_host_uts
// escape hatch to parallel (host UTS mode is always denied above,
// unconditionally), and Docker does not document a container: join form for
// it.
func (p containerCreatePolicy) denyNamespaceSharingReason(hostConfig containerCreateHostConfig) string {
	if !p.restrictNamespaceSharing {
		return ""
	}
	fields := [...]struct {
		label string
		mode  string
	}{
		{"network", hostConfig.NetworkMode},
		{"PID", hostConfig.PidMode},
		{"IPC", hostConfig.IpcMode},
		{"user", hostConfig.UsernsMode},
	}
	for _, f := range fields {
		ref, ok := ContainerNamespaceRef(f.mode)
		if !ok {
			continue
		}
		if len(p.allowedNamespaceSharingContainers) == 0 {
			return fmt.Sprintf("container create denied: %s namespace sharing with another container is not allowed", f.label)
		}
		if !slices.Contains(p.allowedNamespaceSharingContainers, ref) {
			return fmt.Sprintf("container create denied: namespace-sharing target %q is not in the allowed list", ref)
		}
	}
	return ""
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
//
// A request with no effective capabilities (empty Capabilities, or sets that
// canonicalize to empty) is NOT treated as "no privilege": device runtimes such
// as the NVIDIA container runtime expand an empty request to a default capability
// set (gpu, utility, …). Such a request must therefore not vacuously satisfy an
// allowlist that constrains capabilities — it is permitted only when the matching
// allowlist entry itself declares no capability constraint.
func capabilitySetsAllowed(reqSets [][]string, allowedSets [][]string) bool {
	hasEffectiveCapability := false
	for _, reqSet := range reqSets {
		canonReq := canonicalizeCapabilitySet(reqSet)
		if len(canonReq) == 0 {
			continue
		}
		hasEffectiveCapability = true
		if !capabilitySetCoveredByAny(canonReq, allowedSets) {
			return false
		}
	}
	if !hasEffectiveCapability {
		return len(allowedSets) == 0
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
	return capabilityAddDenyReason(hostConfig.CapAdd, p.allowAllCapabilities, p.allowedCapabilities, "container create")
}

// capabilityAddDenyReason enforces a CapAdd-style allowlist against the
// requested capabilities, shared by the container-create and service
// inspectors. subject prefixes the deny reason; "" means allowed.
func capabilityAddDenyReason(requested []string, allowAll bool, allowed []string, subject string) string {
	if allowAll {
		return ""
	}
	for _, raw := range requested {
		capability := normalizeCapability(raw)
		if capability == "" {
			continue
		}
		if !slices.Contains(allowed, capability) {
			return fmt.Sprintf("%s denied: capability %q is not in the allowed list", subject, capability)
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
	if p.requireCPULimitHard && !hasHardCPULimit(hostConfig) {
		return "container create denied: a hard CPU cap is required (set HostConfig.NanoCpus or CpuQuota; CpuShares is a relative priority weight, not a cap, and does not satisfy this check)"
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
			// The deny-unconfined flag wins independently of the allowlist: an
			// admin who set deny_unconfined_seccomp must not be silently
			// overridden by an allowlist that happens to include "unconfined".
			if p.denyUnconfinedSeccomp && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined seccomp profile is not allowed"
			}
			if len(p.allowedSeccompProfiles) > 0 && !slices.Contains(p.allowedSeccompProfiles, value) {
				return fmt.Sprintf("container create denied: seccomp profile %q is not in the allowed list", value)
			}
		case "apparmor":
			seenAppArmor = true
			if p.denyUnconfinedAppArmor && strings.EqualFold(value, "unconfined") {
				return "container create denied: unconfined apparmor profile is not allowed"
			}
			if len(p.allowedAppArmorProfiles) > 0 && !slices.Contains(p.allowedAppArmorProfiles, value) {
				return fmt.Sprintf("container create denied: apparmor profile %q is not in the allowed list", value)
			}
		case "label":
			labelValue := strings.ToLower(strings.TrimSpace(value))
			if labelValue == "disable" {
				if p.denySelinuxDisable {
					return "container create denied: label=disable (SELinux disable) is not allowed"
				}
				// Otherwise pass through — existing behavior.
			} else {
				// Any other label= entry (user:, role:, type:, level:) is a
				// SELinux context override.
				if p.denySelinuxLabelOverride {
					return fmt.Sprintf("container create denied: selinux label override %q is not allowed (set deny_selinux_label_override: false to permit)", value)
				}
			}
		case "systempaths":
			sysValue := strings.ToLower(strings.TrimSpace(value))
			if sysValue == "unconfined" && p.denyUnconfinedSystemPaths {
				return "container create denied: systempaths=unconfined is not allowed"
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

// denySystemPathsReason rejects requests that set MaskedPaths or ReadonlyPaths
// to an explicit empty slice. The Docker CLI translates
// --security-opt systempaths=unconfined into HostConfig.MaskedPaths=[] and
// HostConfig.ReadonlyPaths=[] client-side (using the =unconfined form only).
// Direct API clients can achieve the same effect without the SecurityOpt string.
// A non-nil empty slice means the default masked/readonly path sets are being
// deliberately cleared; nil means the field was absent and daemon defaults apply.
func (p containerCreatePolicy) denySystemPathsReason(hostConfig containerCreateHostConfig) string {
	if !p.denyUnconfinedSystemPaths {
		return ""
	}
	if hostConfig.MaskedPaths != nil && len(*hostConfig.MaskedPaths) == 0 {
		return "container create denied: clearing MaskedPaths (systempaths=unconfined equivalent) is not allowed"
	}
	if hostConfig.ReadonlyPaths != nil && len(*hostConfig.ReadonlyPaths) == 0 {
		return "container create denied: clearing ReadonlyPaths (systempaths=unconfined equivalent) is not allowed"
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

func extractAndValidateBindSource(bind string, mount containerCreateMount) (string, bool) {
	if bind != "" {
		source, _, ok := strings.Cut(bind, ":")
		if !ok {
			return "", false
		}
		return normalizeBindMount(source)
	}

	if !strings.EqualFold(mount.Type, "bind") {
		return "", false
	}

	return normalizeBindMount(mount.Source)
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
	if isNumericRootUID(userPart) {
		return false
	}
	return true
}

// isNumericRootUID reports whether userPart parses as the numeric UID 0.
// Docker resolves a numeric Config.User with strconv, so "00", "000", and any
// other zero-padded form all run as root — an exact "0" string compare would
// miss them and let require_non_root_user / allow_root_user:false be bypassed.
func isNumericRootUID(userPart string) bool {
	n, err := strconv.ParseUint(userPart, 10, 32)
	return err == nil && n == 0
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

// hasHardCPULimit returns true only when a genuine CPU-time cap is set:
// NanoCpus or CpuQuota. Unlike hasCPULimit, a lone CpuPeriod does not count
// (it is only the denominator for CpuQuota and enforces nothing without it),
// and CpuShares does not count (it sets relative scheduling priority under
// contention, not an absolute ceiling — a CpuShares-only container can still
// consume 100% of every CPU it can reach on an idle host).
//
// CpuQuota is accepted without a paired CpuPeriod: per Docker's own docs
// (docs.docker.com/engine/containers/resource_constraints — "--cpu-period
// ... Defaults to 100000 microseconds (100 milliseconds)"), the CFS period
// defaults to 100000us (the same value the kernel's CFS bandwidth
// controller already applies to a cgroup) whenever CpuPeriod is left at its
// zero value, so CpuQuota alone still yields a real, computable CPU-time
// ceiling (CpuQuota / 100000).
func hasHardCPULimit(h containerCreateHostConfig) bool {
	return h.NanoCpus > 0 || h.CpuQuota > 0
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

// normalizeCapability canonicalizes a Linux capability name into the form
// HostConfig.CapAdd/CapDrop uses on the wire. Docker accepts both "NET_ADMIN"
// and "CAP_NET_ADMIN" and treats them identically; sockguard strips the
// "CAP_" prefix so a single allowlist entry covers both. Plugin manifest
// capabilities follow a different namespace — see normalizePluginCapability.
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
