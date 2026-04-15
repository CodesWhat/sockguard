package filter

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

const maxServiceBodyBytes = 1 << 20 // 1 MiB

// ServiceOptions configures request-body inspection for service create/update.
type ServiceOptions struct {
	AllowHostNetwork   bool
	AllowedBindMounts  []string
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
}

type servicePolicy struct {
	allowHostNetwork  bool
	allowedBindMounts []string
	imagePolicy       imagePullPolicy
}

type serviceRequest struct {
	TaskTemplate struct {
		ContainerSpec struct {
			Image  string         `json:"Image"`
			Mounts []serviceMount `json:"Mounts"`
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
		normalized, ok := normalizeContainerCreateBindMount(bindMount)
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
	}
}

func (p servicePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isServiceWritePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxServiceBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxServiceBodyBytes {
		return fmt.Sprintf("service denied: request body exceeds %d byte limit", maxServiceBodyBytes), nil
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	if len(body) == 0 {
		return "", nil
	}

	var req serviceRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "service request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
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
		source, ok := normalizeContainerCreateBindMount(mount.Source)
		if !ok || p.bindMountAllowed(source) {
			continue
		}
		return fmt.Sprintf("service denied: bind mount source %q is not allowlisted", source), nil
	}

	if denyReason := p.imagePolicy.denyReasonForReference(strings.TrimSpace(req.TaskTemplate.ContainerSpec.Image), "service"); denyReason != "" {
		return denyReason, nil
	}

	return "", nil
}

func (p servicePolicy) bindMountAllowed(source string) bool {
	for _, allowed := range p.allowedBindMounts {
		if allowed == "/" || source == allowed || strings.HasPrefix(source, allowed+"/") {
			return true
		}
	}
	return false
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
