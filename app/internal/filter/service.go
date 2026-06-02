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
	// ImageTrust applies cosign verification to ContainerSpec.Image, matching
	// the container-create path so swarm services cannot escape image trust.
	ImageTrust ImageTrustOptions
}

type servicePolicy struct {
	allowHostNetwork     bool
	allowedBindMounts    []string
	imagePolicy          imagePullPolicy
	allowAllCapabilities bool
	allowedCapabilities  []string
	allowSysctls         bool
	imageTrust           imageTrustFields
}

type serviceRequest struct {
	TaskTemplate struct {
		ContainerSpec struct {
			Image          string            `json:"Image"`
			Mounts         []serviceMount    `json:"Mounts"`
			CapabilityAdd  []string          `json:"CapabilityAdd"`
			CapabilityDrop []string          `json:"CapabilityDrop"`
			Sysctls        map[string]string `json:"Sysctls"`
		} `json:"ContainerSpec"`
	} `json:"TaskTemplate"`
	Networks []serviceNetwork `json:"Networks"`
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
		allowAllCapabilities: opts.AllowAllCapabilities,
		allowedCapabilities:  normalizeCapabilityList(opts.AllowedCapabilities),
		allowSysctls:         opts.AllowSysctls,
		imageTrust:           buildImageTrustFields(opts.ImageTrust),
	}
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
			if pinned, perr := imagefetch.PinnedReference(imageRef, verifiedDigest); perr == nil && pinned != imageRef {
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
func rewriteServiceImage(body []byte, pinned string) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	var taskTemplate map[string]json.RawMessage
	if err := json.Unmarshal(top["TaskTemplate"], &taskTemplate); err != nil {
		return nil, fmt.Errorf("decode TaskTemplate: %w", err)
	}
	var containerSpec map[string]json.RawMessage
	if err := json.Unmarshal(taskTemplate["ContainerSpec"], &containerSpec); err != nil {
		return nil, fmt.Errorf("decode ContainerSpec: %w", err)
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return nil, err
	}
	containerSpec["Image"] = encoded
	if taskTemplate["ContainerSpec"], err = json.Marshal(containerSpec); err != nil {
		return nil, err
	}
	if top["TaskTemplate"], err = json.Marshal(taskTemplate); err != nil {
		return nil, err
	}
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
