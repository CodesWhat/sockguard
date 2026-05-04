package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
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
	AllowDeviceRequests    bool
	AllowDeviceCgroupRules bool
}

type containerCreatePolicy struct {
	allowPrivileged        bool
	allowHostNetwork       bool
	allowHostPID           bool
	allowHostIPC           bool
	allowedBindMounts      []string
	allowAllDevices        bool
	allowedDevices         []string
	allowDeviceRequests    bool
	allowDeviceCgroupRules bool
}

type containerCreateRequest struct {
	HostConfig containerCreateHostConfig `json:"HostConfig"`
}

type containerCreateHostConfig struct {
	Privileged        bool                    `json:"Privileged"`
	NetworkMode       string                  `json:"NetworkMode"`
	PidMode           string                  `json:"PidMode"`
	IpcMode           string                  `json:"IpcMode"`
	Binds             []string                `json:"Binds"`
	Mounts            []containerCreateMount  `json:"Mounts"`
	Devices           []containerCreateDevice `json:"Devices"`
	DeviceRequests    []json.RawMessage       `json:"DeviceRequests"`
	DeviceCgroupRules []string                `json:"DeviceCgroupRules"`
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

	return containerCreatePolicy{
		allowPrivileged:        opts.AllowPrivileged,
		allowHostNetwork:       opts.AllowHostNetwork,
		allowHostPID:           opts.AllowHostPID,
		allowHostIPC:           opts.AllowHostIPC,
		allowedBindMounts:      allowed,
		allowAllDevices:        opts.AllowAllDevices,
		allowedDevices:         allowedDevices,
		allowDeviceRequests:    opts.AllowDeviceRequests,
		allowDeviceCgroupRules: opts.AllowDeviceCgroupRules,
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
	if denyReason := p.denyDeviceReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}
	if denyReason := p.denyBindMountReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}

	return "", nil
}

func (p containerCreatePolicy) allowsAllContainerCreateBodies() bool {
	return p.allowPrivileged &&
		p.allowHostNetwork &&
		p.allowHostPID &&
		p.allowHostIPC &&
		bindPathAllowed("/", p.allowedBindMounts) &&
		(p.allowAllDevices || bindPathAllowed("/", p.allowedDevices)) &&
		p.allowDeviceRequests &&
		p.allowDeviceCgroupRules
}

func isHostNamespaceMode(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "host")
}

func (p containerCreatePolicy) denyDeviceReason(hostConfig containerCreateHostConfig) string {
	if !p.allowDeviceRequests && len(hostConfig.DeviceRequests) > 0 {
		return "container create denied: device requests are not allowed"
	}
	if !p.allowDeviceCgroupRules && len(hostConfig.DeviceCgroupRules) > 0 {
		return "container create denied: device cgroup rules are not allowed"
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
