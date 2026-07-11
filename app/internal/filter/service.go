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

	"github.com/codeswhat/sockguard/internal/imagefetch"
)

const maxServiceBodyBytes = 1 << 20 // 1 MiB

// ServiceOptions configures request-body inspection for service create/update.
type ServiceOptions struct {
	AllowHostNetwork   bool
	AllowedBindMounts  []string
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
	// AllowAllCapabilities / AllowedCapabilities mirror the container-create
	// CapabilityAdd allowlist for swarm task containers (ContainerSpec).
	AllowAllCapabilities bool
	AllowedCapabilities  []string
	// AllowSysctls permits ContainerSpec.Sysctls; default false denies any.
	AllowSysctls bool
	// RequireNonRootUser / RequireNoNewPrivileges / RequireReadonlyRootfs /
	// RequireDropAllCapabilities mirror the container-create hardening rails for
	// swarm task containers, enforced against ContainerSpec.User,
	// ContainerSpec.Privileges.NoNewPrivileges, ContainerSpec.ReadOnly, and
	// ContainerSpec.CapabilityDrop respectively.
	RequireNonRootUser         bool
	RequireNoNewPrivileges     bool
	RequireReadonlyRootfs      bool
	RequireDropAllCapabilities bool
	// DenyUnconfinedSeccomp denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode == "unconfined". Default false.
	// Note: does not automatically deny Mode=="custom" — see DenyCustomSeccompProfiles.
	DenyUnconfinedSeccomp bool
	// DenyCustomSeccompProfiles denies service create/update when
	// ContainerSpec.Privileges.Seccomp.Mode == "custom". Operators who use
	// carefully vetted custom seccomp profiles must leave this false.
	// When both DenyUnconfinedSeccomp and DenyCustomSeccompProfiles are true,
	// only Mode=="default" (or an absent Seccomp block) is permitted.
	DenyCustomSeccompProfiles bool
	// DenyUnconfinedAppArmor denies service create/update when
	// ContainerSpec.Privileges.AppArmor.Mode == "disabled". Swarm has no
	// "unconfined" AppArmor mode; "disabled" is the equivalent. Default false.
	DenyUnconfinedAppArmor bool
	// DenySelinuxDisable denies service create/update when
	// ContainerSpec.Privileges.SELinuxContext.Disable is true — the swarm
	// equivalent of the container-create SecurityOpt label=disable that turns off
	// SELinux confinement. Default false (opt-in).
	DenySelinuxDisable bool
	// DenySelinuxLabelOverride denies service create/update that customizes the
	// SELinux context via any of ContainerSpec.Privileges.SELinuxContext.{User,
	// Role,Type,Level} — the swarm equivalent of the container-create SecurityOpt
	// label=user:/role:/type:/level: override. Default false. Independent of
	// DenySelinuxDisable.
	DenySelinuxLabelOverride bool
	// ImageTrust applies cosign verification to ContainerSpec.Image, matching
	// the container-create path so swarm services cannot escape image trust.
	ImageTrust ImageTrustOptions
}

type servicePolicy struct {
	allowHostNetwork           bool
	allowedBindMounts          []string
	imagePolicy                imagePullPolicy
	allowAllCapabilities       bool
	allowedCapabilities        []string
	allowSysctls               bool
	requireNonRootUser         bool
	requireNoNewPrivileges     bool
	requireReadonlyRootfs      bool
	requireDropAllCapabilities bool
	denyUnconfinedSeccomp      bool
	denyCustomSeccompProfiles  bool
	denyUnconfinedAppArmor     bool
	denySelinuxDisable         bool
	denySelinuxLabelOverride   bool
	imageTrust                 imageTrustFields
}

type serviceRequest struct {
	TaskTemplate struct {
		ContainerSpec serviceContainerSpec `json:"ContainerSpec"`
	} `json:"TaskTemplate"`
	Networks []serviceNetwork `json:"Networks"`
}

// serviceContainerSpec mirrors the subset of Docker's swarm ContainerSpec that
// Sockguard inspects. Identity/privilege fields (User, ReadOnly, Privileges,
// CapabilityDrop) carry the swarm equivalents of the container-create hardening
// rails so service create/update cannot bypass them.
type serviceContainerSpec struct {
	Image          string                      `json:"Image"`
	User           string                      `json:"User"`
	Mounts         []serviceMount              `json:"Mounts"`
	CapabilityAdd  []string                    `json:"CapabilityAdd"`
	CapabilityDrop []string                    `json:"CapabilityDrop"`
	Sysctls        map[string]string           `json:"Sysctls"`
	ReadOnly       bool                        `json:"ReadOnly"`
	Privileges     *serviceContainerPrivileges `json:"Privileges"`
}

// serviceContainerPrivileges captures the swarm ContainerSpec.Privileges fields
// Sockguard enforces. NoNewPrivileges is a direct ContainerSpec.Privileges boolean rather than a
// SecurityOpt string; a nil Privileges block means the flag is unset (denied).
type serviceContainerPrivileges struct {
	NoNewPrivileges bool                   `json:"NoNewPrivileges"`
	Seccomp         *serviceSeccompOpts    `json:"Seccomp"`
	AppArmor        *serviceAppArmorOpts   `json:"AppArmor"`
	SELinuxContext  *serviceSELinuxContext `json:"SELinuxContext"`
}

// serviceSELinuxContext mirrors swarm ContainerSpec.Privileges.SELinuxContext.
// Disable turns off SELinux confinement (equivalent to the container-create
// SecurityOpt label=disable); User/Role/Type/Level customize the SELinux context
// (equivalent to label=user:/role:/type:/level:). A nil block means no explicit
// SELinux context was set and is always allowed.
type serviceSELinuxContext struct {
	Disable bool   `json:"Disable"`
	User    string `json:"User"`
	Role    string `json:"Role"`
	Type    string `json:"Type"`
	Level   string `json:"Level"`
}

// serviceSeccompOpts mirrors the subset of swarm SeccompOpts that Sockguard inspects.
// Profile []byte is intentionally omitted — the proxy cannot safely decode or
// evaluate the binary blob, and the presence of Mode=="custom" is sufficient to
// enforce deny_custom_seccomp_profiles without parsing the profile content.
// Exception: a non-nil Seccomp with empty Mode and non-empty Profile is treated
// as implicit "custom" (fail-closed) when deny_custom_seccomp_profiles is true.
type serviceSeccompOpts struct {
	Mode    string          `json:"Mode"`
	Profile json.RawMessage `json:"Profile,omitempty"`
}

// serviceAppArmorOpts mirrors the subset of swarm AppArmorOpts that Sockguard inspects.
type serviceAppArmorOpts struct {
	Mode string `json:"Mode"`
}

type serviceMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

type serviceNetwork struct {
	Target string `json:"Target"`
}

func newServicePolicy(opts ServiceOptions) servicePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return servicePolicy{
		allowHostNetwork:  opts.AllowHostNetwork,
		allowedBindMounts: allowed,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
		allowAllCapabilities:       opts.AllowAllCapabilities,
		allowedCapabilities:        normalizeCapabilityList(opts.AllowedCapabilities),
		allowSysctls:               opts.AllowSysctls,
		requireNonRootUser:         opts.RequireNonRootUser,
		requireNoNewPrivileges:     opts.RequireNoNewPrivileges,
		requireReadonlyRootfs:      opts.RequireReadonlyRootfs,
		requireDropAllCapabilities: opts.RequireDropAllCapabilities,
		denyUnconfinedSeccomp:      opts.DenyUnconfinedSeccomp,
		denyCustomSeccompProfiles:  opts.DenyCustomSeccompProfiles,
		denyUnconfinedAppArmor:     opts.DenyUnconfinedAppArmor,
		denySelinuxDisable:         opts.DenySelinuxDisable,
		denySelinuxLabelOverride:   opts.DenySelinuxLabelOverride,
		imageTrust:                 buildImageTrustFields(opts.ImageTrust),
	}
}

// denyHardeningReason enforces the swarm equivalents of the container-create
// boolean rails against ContainerSpec. It reuses the same isNonRootUser and
// capDropContainsAll helpers so service and container policy stay in lockstep.
// NoNewPrivileges is a direct ContainerSpec.Privileges boolean rather than a
// SecurityOpt string; a nil Privileges block means the flag is unset (denied).
func (p servicePolicy) denyHardeningReason(spec serviceContainerSpec) string {
	if p.requireNoNewPrivileges && (spec.Privileges == nil || !spec.Privileges.NoNewPrivileges) {
		return "service denied: no-new-privileges is required (set ContainerSpec.Privileges.NoNewPrivileges to true)"
	}
	if p.requireNonRootUser && !isNonRootUser(spec.User) {
		return "service denied: non-root user is required (set ContainerSpec.User to a non-zero UID or non-root username)"
	}
	if p.requireReadonlyRootfs && !spec.ReadOnly {
		return "service denied: read-only root filesystem is required (set ContainerSpec.ReadOnly to true)"
	}
	if p.requireDropAllCapabilities && !capDropContainsAll(spec.CapabilityDrop) {
		return "service denied: ContainerSpec.CapabilityDrop must include \"ALL\""
	}
	if denyReason := p.denySeccompModeReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denyAppArmorModeReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	if denyReason := p.denySelinuxContextReason(spec.Privileges); denyReason != "" {
		return denyReason
	}
	return ""
}

// denySelinuxContextReason enforces deny_selinux_disable and
// deny_selinux_label_override against ContainerSpec.Privileges.SELinuxContext,
// the swarm equivalents of the container-create SecurityOpt label=disable and
// label=user:/role:/type:/level: overrides. A nil Privileges or SELinuxContext
// block means no explicit context was set and is always allowed.
func (p servicePolicy) denySelinuxContextReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.SELinuxContext == nil {
		return ""
	}
	sel := priv.SELinuxContext
	if p.denySelinuxDisable && sel.Disable {
		return "service denied: SELinux disable is not allowed (ContainerSpec.Privileges.SELinuxContext.Disable)"
	}
	if p.denySelinuxLabelOverride &&
		(strings.TrimSpace(sel.User) != "" || strings.TrimSpace(sel.Role) != "" ||
			strings.TrimSpace(sel.Type) != "" || strings.TrimSpace(sel.Level) != "") {
		return "service denied: SELinux context override is not allowed (ContainerSpec.Privileges.SELinuxContext.User/Role/Type/Level)"
	}
	return ""
}

// denySeccompModeReason enforces deny_unconfined_seccomp and
// deny_custom_seccomp_profiles against ContainerSpec.Privileges.Seccomp.Mode.
// A nil Seccomp block means no explicit mode was set (Docker uses its default)
// and is always allowed. Mode comparison is case-insensitive; moby emits
// lowercase constants but third-party clients may vary.
// Fail-closed: a non-nil Seccomp with empty Mode but non-empty Profile is
// treated as implicit "custom" when deny_custom_seccomp_profiles is true,
// because the proxy cannot determine confinement intent from a bare blob.
func (p servicePolicy) denySeccompModeReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.Seccomp == nil {
		return ""
	}
	mode := strings.TrimSpace(priv.Seccomp.Mode)
	if p.denyUnconfinedSeccomp && strings.EqualFold(mode, "unconfined") {
		return "service denied: unconfined seccomp mode is not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
	}
	if p.denyCustomSeccompProfiles {
		if strings.EqualFold(mode, "custom") {
			return "service denied: custom seccomp profiles are not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
		}
		// A non-nil Seccomp with empty Mode and a non-empty Profile blob is an
		// unvettable custom profile; treat as implicit "custom" (fail-closed).
		// JSON "Profile": null decodes to the 4-byte literal RawMessage("null")
		// rather than nil, so guard against it explicitly to avoid a false deny.
		if mode == "" && hasSeccompProfileBlob(priv.Seccomp.Profile) {
			return "service denied: custom seccomp profiles are not allowed (ContainerSpec.Privileges.Seccomp.Mode)"
		}
	}
	return ""
}

// hasSeccompProfileBlob reports whether a raw Seccomp.Profile carries an actual
// inline profile. JSON null decodes to RawMessage("null") (len 4, non-nil), so a
// bare length check would misread "Profile": null as a custom profile.
func hasSeccompProfileBlob(profile json.RawMessage) bool {
	trimmed := bytes.TrimSpace(profile)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// denyAppArmorModeReason enforces deny_unconfined_apparmor against
// ContainerSpec.Privileges.AppArmor.Mode. Swarm uses "disabled" where
// container-create uses "unconfined"; both mean "no AppArmor confinement".
// A nil AppArmor block means no explicit mode was set and is always allowed.
func (p servicePolicy) denyAppArmorModeReason(priv *serviceContainerPrivileges) string {
	if priv == nil || priv.AppArmor == nil {
		return ""
	}
	mode := strings.TrimSpace(priv.AppArmor.Mode)
	if p.denyUnconfinedAppArmor && strings.EqualFold(mode, "disabled") {
		return "service denied: disabled apparmor mode is not allowed (ContainerSpec.Privileges.AppArmor.Mode)"
	}
	return ""
}

func (p servicePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isServiceWritePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxServiceBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req serviceRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "service request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "service denied: request body could not be inspected", nil
	}

	if !p.allowHostNetwork {
		for _, network := range req.Networks {
			if strings.EqualFold(strings.TrimSpace(network.Target), "host") {
				return "service denied: host network is not allowed", nil
			}
		}
	}

	for _, mount := range req.TaskTemplate.ContainerSpec.Mounts {
		if !strings.EqualFold(mount.Type, "bind") {
			continue
		}
		source, ok := normalizeBindMount(mount.Source)
		if !ok || bindPathAllowed(source, p.allowedBindMounts) {
			continue
		}
		return fmt.Sprintf("service denied: bind mount source %q is not allowlisted", source), nil
	}

	// Identity/privilege rails: ContainerSpec carries swarm equivalents of the
	// container-create hardening knobs (User, Privileges.NoNewPrivileges,
	// ReadOnly, CapabilityDrop). Enforce them so service create/update is not a
	// bypass of require_non_root_user and friends.
	if denyReason := p.denyHardeningReason(req.TaskTemplate.ContainerSpec); denyReason != "" {
		return denyReason, nil
	}

	// Swarm task containers can grant Linux capabilities and set sysctls via
	// ContainerSpec, exactly like /containers/create — enforce the same rails so
	// service create/update is not a bypass of the container-create policy.
	if denyReason := capabilityAddDenyReason(req.TaskTemplate.ContainerSpec.CapabilityAdd, p.allowAllCapabilities, p.allowedCapabilities, "service"); denyReason != "" {
		return denyReason, nil
	}
	if !p.allowSysctls && len(req.TaskTemplate.ContainerSpec.Sysctls) > 0 {
		return "service denied: setting sysctls is not allowed", nil
	}

	if denyReason := p.imagePolicy.denyReasonForReference(strings.TrimSpace(req.TaskTemplate.ContainerSpec.Image), "service"); denyReason != "" {
		return denyReason, nil
	}

	// Image trust: verify ContainerSpec.Image and pin it to the verified digest,
	// mirroring the container-create path. Without this, swarm services escape
	// cosign enforcement entirely.
	if p.imageTrust.initErr != nil {
		return fmt.Sprintf("service denied: image trust policy initialization error: %s", p.imageTrust.initErr.Error()), nil
	}
	if p.imageTrust.verifier != nil {
		imageRef := strings.TrimSpace(req.TaskTemplate.ContainerSpec.Image)
		denyReason, verifiedDigest := verifyImageTrust(r.Context(), logger, p.imageTrust, imageRef, "service")
		if denyReason != "" {
			return denyReason, nil
		}
		if verifiedDigest != "" {
			pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest)
			if perr != nil {
				// Verification succeeded but the verified reference cannot be
				// digest-pinned. Forwarding the original tag would reopen the
				// verify→pull TOCTOU this block exists to close, so deny rather
				// than fall through and forward an unpinned reference.
				return "", fmt.Errorf("pin verified image digest: %w", perr)
			}
			if pinned != imageRef {
				rewritten, rerr := rewriteServiceImage(body, pinned)
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

// rewriteServiceImage replaces TaskTemplate.ContainerSpec.Image with pinned,
// preserving every other field byte-for-byte (RawMessage) so resource limits
// and other numeric fields are not corrupted by a float round-trip.
//
// Every level is navigated case-insensitively, and a duplicate case-variant
// key at any level (TaskTemplate, ContainerSpec, or the Image leaf) is rejected
// fail-closed: Docker decodes these keys case-insensitively and honors the last
// duplicate after our re-marshal, so a shadow lowercase "image"/"containerspec"
// key would otherwise let a client run an image the cosign policy check — which
// decodes the same body via a struct — never verified. Collapsing the leaf to a
// single canonical "Image" key pins exactly the verified image at the daemon.
func rewriteServiceImage(body []byte, pinned string) ([]byte, error) {
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	ttKey, err := soleFoldedRawKey(top, "TaskTemplate")
	if err != nil {
		return nil, fmt.Errorf("service body: %w", err)
	}
	var taskTemplate map[string]json.RawMessage
	if err := json.Unmarshal(top[ttKey], &taskTemplate); err != nil {
		return nil, fmt.Errorf("decode TaskTemplate: %w", err)
	}
	csKey, err := soleFoldedRawKey(taskTemplate, "ContainerSpec")
	if err != nil {
		return nil, fmt.Errorf("service body: %w", err)
	}
	var containerSpec map[string]json.RawMessage
	if err := json.Unmarshal(taskTemplate[csKey], &containerSpec); err != nil {
		return nil, fmt.Errorf("decode ContainerSpec: %w", err)
	}
	if err := collapseImageKey(containerSpec, pinned); err != nil {
		return nil, err
	}
	// Collapse the parent keys to canonical case as well, matching collapseImageKey's
	// treatment of the Image leaf. The reject guard above already forbids duplicate
	// case-variant keys, so soleFoldedRawKey found exactly one variant at each level;
	// rewriting it to the canonical name keeps the pinned body unambiguous instead of
	// leaving a lowercase "tasktemplate"/"containerspec" the daemon only reads by fold.
	csRaw, err := json.Marshal(containerSpec)
	if err != nil {
		return nil, err
	}
	delete(taskTemplate, csKey)
	taskTemplate["ContainerSpec"] = csRaw
	ttRaw, err := json.Marshal(taskTemplate)
	if err != nil {
		return nil, err
	}
	delete(top, ttKey)
	top["TaskTemplate"] = ttRaw
	return json.Marshal(top)
}

func isServiceWritePath(normalizedPath string) bool {
	switch {
	case normalizedPath == "/services/create":
		return true
	case strings.HasPrefix(normalizedPath, "/services/"):
		_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/services/"), "/")
		return ok && tail == "update"
	default:
		return false
	}
}
