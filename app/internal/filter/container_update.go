package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxContainerUpdateBodyBytes = 1 << 20 // 1 MiB

// ContainerUpdateOptions configures request-body policy checks for
// POST /containers/{id}/update.
type ContainerUpdateOptions struct {
	AllowPrivileged      bool
	AllowAllDevices      bool
	AllowCapabilities    bool
	AllowRestartPolicy   bool
	AllowResourceUpdates bool
}

type containerUpdatePolicy struct {
	allowPrivileged      bool
	allowAllDevices      bool
	allowCapabilities    bool
	allowRestartPolicy   bool
	allowResourceUpdates bool
}

func newContainerUpdatePolicy(opts ContainerUpdateOptions) containerUpdatePolicy {
	return containerUpdatePolicy{
		allowPrivileged:      opts.AllowPrivileged,
		allowAllDevices:      opts.AllowAllDevices,
		allowCapabilities:    opts.AllowCapabilities,
		allowRestartPolicy:   opts.AllowRestartPolicy,
		allowResourceUpdates: opts.AllowResourceUpdates,
	}
}

func (p containerUpdatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesContainerUpdateInspection(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxContainerUpdateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container update denied: request body exceeds %d byte limit", maxContainerUpdateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var root map[string]json.RawMessage
	if err := decodePolicySubsetJSON(body, &root); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "container update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "container update denied: request body could not be inspected", nil
	}

	objects := containerUpdatePolicyObjects(root)
	if !p.allowPrivileged && containerUpdateHasAnyField(objects, containerUpdatePrivilegedFields...) {
		return "container update denied: privileged mode changes are not allowed", nil
	}
	if !p.allowAllDevices && containerUpdateHasAnyField(objects, containerUpdateDeviceFields...) {
		return "container update denied: device changes are not allowed", nil
	}
	if !p.allowCapabilities && containerUpdateHasAnyField(objects, containerUpdateCapabilityFields...) {
		return "container update denied: capability changes are not allowed", nil
	}
	if !p.allowRestartPolicy && containerUpdateHasAnyField(objects, containerUpdateRestartPolicyFields...) {
		return "container update denied: restart policy changes are not allowed", nil
	}
	if !p.allowResourceUpdates && containerUpdateHasAnyField(objects, containerUpdateResourceControlFields...) {
		return "container update denied: resource control changes are not allowed", nil
	}

	return "", nil
}

func isContainerUpdatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	return ok && tail == "update"
}

func containerUpdatePolicyObjects(root map[string]json.RawMessage) []map[string]json.RawMessage {
	if len(root) == 0 {
		return nil
	}

	objects := []map[string]json.RawMessage{root}
	for _, field := range []string{"HostConfig", "Resources"} {
		if nested, ok := decodeContainerUpdateObjectField(root, field); ok {
			objects = append(objects, nested)
		}
	}
	if hostConfig, ok := decodeContainerUpdateObjectField(root, "HostConfig"); ok {
		if nested, ok := decodeContainerUpdateObjectField(hostConfig, "Resources"); ok {
			objects = append(objects, nested)
		}
	}
	return objects
}

func decodeContainerUpdateObjectField(root map[string]json.RawMessage, name string) (map[string]json.RawMessage, bool) {
	for key, raw := range root {
		if !strings.EqualFold(key, name) || len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}

		var nested map[string]json.RawMessage
		if err := decodePolicySubsetJSON(raw, &nested); err != nil || len(nested) == 0 {
			return nil, false
		}
		return nested, true
	}
	return nil, false
}

func containerUpdateHasAnyField(objects []map[string]json.RawMessage, fields ...string) bool {
	for _, object := range objects {
		for key := range object {
			for _, field := range fields {
				if strings.EqualFold(key, field) {
					return true
				}
			}
		}
	}
	return false
}

var containerUpdatePrivilegedFields = []string{
	"Privileged",
}

var containerUpdateDeviceFields = []string{
	"Devices",
	"DeviceCgroupRules",
	"DeviceRequests",
}

var containerUpdateCapabilityFields = []string{
	"CapAdd",
	"CapDrop",
	"Capabilities",
	"NoNewPrivileges",
	"SecurityOpt",
}

var containerUpdateRestartPolicyFields = []string{
	"RestartPolicy",
}

var containerUpdateResourceControlFields = []string{
	"BlkioDeviceReadBps",
	"BlkioDeviceReadIOps",
	"BlkioDeviceWriteBps",
	"BlkioDeviceWriteIOps",
	"BlkioWeight",
	"BlkioWeightDevice",
	"CgroupParent",
	"CgroupnsMode",
	"CpuCount",
	"CpuPercent",
	"CpuPeriod",
	"CpuQuota",
	"CpuRealtimePeriod",
	"CpuRealtimeRuntime",
	"CpuShares",
	"CpusetCpus",
	"CpusetMems",
	"IOMaximumBandwidth",
	"IOMaximumIOps",
	"KernelMemory",
	"KernelMemoryTCP",
	"Memory",
	"MemoryReservation",
	"MemorySwap",
	"MemorySwappiness",
	"NanoCpus",
	"OomKillDisable",
	"PidsLimit",
	"Resources",
	"Ulimits",
}
