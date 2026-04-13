package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
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
	AllowPrivileged   bool
	AllowHostNetwork  bool
	AllowedBindMounts []string
}

type containerCreatePolicy struct {
	allowPrivileged   bool
	allowHostNetwork  bool
	allowedBindMounts []string
}

type containerCreateRequest struct {
	HostConfig containerCreateHostConfig `json:"HostConfig"`
}

type containerCreateHostConfig struct {
	Privileged  bool                   `json:"Privileged"`
	NetworkMode string                 `json:"NetworkMode"`
	Binds       []string               `json:"Binds"`
	Mounts      []containerCreateMount `json:"Mounts"`
}

type containerCreateMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

func newContainerCreatePolicy(opts ContainerCreateOptions) containerCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeContainerCreateBindMount(bindMount)
		if !ok || containsString(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return containerCreatePolicy{
		allowPrivileged:   opts.AllowPrivileged,
		allowHostNetwork:  opts.AllowHostNetwork,
		allowedBindMounts: allowed,
	}
}

func (p containerCreatePolicy) inspect(r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" || r.Body == nil {
		return "", nil
	}

	// Read one byte past the limit so we can distinguish an at-limit payload
	// from an over-limit one without giving the client room to OOM the proxy.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxContainerCreateBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	if int64(len(body)) > maxContainerCreateBodyBytes {
		return fmt.Sprintf("container create denied: request body exceeds %d byte limit", maxContainerCreateBodyBytes), nil
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	if len(body) == 0 {
		return "", nil
	}

	var createReq containerCreateRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		// Let Docker return its native validation error when the create payload
		// is malformed; Sockguard only overrides known-dangerous valid requests.
		return "", nil
	}

	if !p.allowPrivileged && createReq.HostConfig.Privileged {
		return "container create denied: privileged containers are not allowed", nil
	}
	if !p.allowHostNetwork && strings.EqualFold(createReq.HostConfig.NetworkMode, "host") {
		return "container create denied: host network mode is not allowed", nil
	}
	if denyReason := p.denyBindMountReason(createReq.HostConfig); denyReason != "" {
		return denyReason, nil
	}

	return "", nil
}

func (p containerCreatePolicy) denyBindMountReason(hostConfig containerCreateHostConfig) string {
	for _, bind := range hostConfig.Binds {
		source, ok := containerCreateBindSource(bind)
		if !ok || p.bindMountAllowed(source) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	for _, mount := range hostConfig.Mounts {
		if !strings.EqualFold(mount.Type, "bind") {
			continue
		}
		source, ok := normalizeContainerCreateBindMount(mount.Source)
		if !ok || p.bindMountAllowed(source) {
			continue
		}
		return fmt.Sprintf("container create denied: bind mount source %q is not allowlisted", source)
	}

	return ""
}

func (p containerCreatePolicy) bindMountAllowed(source string) bool {
	for _, allowed := range p.allowedBindMounts {
		if allowed == "/" || source == allowed || strings.HasPrefix(source, allowed+"/") {
			return true
		}
	}
	return false
}

func containerCreateBindSource(bind string) (string, bool) {
	source, _, ok := strings.Cut(bind, ":")
	if !ok {
		return "", false
	}
	return normalizeContainerCreateBindMount(source)
}

func normalizeContainerCreateBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}
