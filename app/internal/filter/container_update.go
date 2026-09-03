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
	// AllowBlindWrites acknowledges native libpod update fields that cannot
	// be constrained by the structured container-update gates. Runtime wiring
	// supplies it from the global insecure_allow_body_blind_writes setting.
	AllowBlindWrites bool

	// RequireMemoryLimit/RequireCPULimit/RequireCPULimitHard/RequirePidsLimit
	// are enforced by ResourceLimitGuard (resource_limit_guard.go), not by
	// containerUpdatePolicy.inspect below — they revalidate the container's
	// EFFECTIVE post-update resource state, which requires a daemon lookup
	// that only runs post-ownership. They are carried on this struct purely
	// so config.ContainerUpdateRequestBodyConfig.ToFilterOptions has a single
	// destination field per config leaf; containerUpdatePolicy itself never
	// reads them.
	RequireMemoryLimit  bool
	RequireCPULimit     bool
	RequireCPULimitHard bool
	RequirePidsLimit    bool
}

type containerUpdatePolicy struct {
	allowPrivileged      bool
	allowAllDevices      bool
	allowCapabilities    bool
	allowRestartPolicy   bool
	allowResourceUpdates bool
	allowBlindWrites     bool
}

func newContainerUpdatePolicy(opts ContainerUpdateOptions) containerUpdatePolicy {
	return containerUpdatePolicy{
		allowPrivileged:      opts.AllowPrivileged,
		allowAllDevices:      opts.AllowAllDevices,
		allowCapabilities:    opts.AllowCapabilities,
		allowRestartPolicy:   opts.AllowRestartPolicy,
		allowResourceUpdates: opts.AllowResourceUpdates,
		allowBlindWrites:     opts.AllowBlindWrites,
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
		logRequestError(logger, r, slog.LevelDebug, "container update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
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
	if !p.allowResourceUpdates && containerUpdateHasAnyResourceChange(objects, containerUpdateResourceControlFields...) {
		return "container update denied: resource control changes are not allowed", nil
	}

	return "", nil
}

// isContainerUpdatePath matches POST /containers/{id}/update, the
// Docker-compat spelling only. The libpod spelling is
// isLibpodContainerUpdatePath and routes to inspectLibpod instead, because
// the two endpoints share nothing but a name on the wire. Both are built from
// containerSubresourcePath so the pair cannot drift; the split here is a
// deliberate body-shape decision, not two independently maintained lists.
func isContainerUpdatePath(normalizedPath string) bool {
	libpod, ok := containerSubresourcePath(normalizedPath, "update")
	return ok && !libpod
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
		for key, raw := range object {
			for _, field := range fields {
				if strings.EqualFold(key, field) && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return true
				}
			}
		}
	}
	return false
}

// containerUpdateHasAnyResourceChange distinguishes Moby's serialized zero
// values from resource mutations. UpdateConfig embeds Resources without
// omitempty tags, so a restart-only client request contains every resource
// key. The daemon applies scalar values only when nonzero, string values only
// when nonempty, and pointer/slice values only when non-nil. JSON null is nil;
// an empty array is deliberately not treated as nil because the blkio arrays
// use a non-nil empty slice to clear their existing value.
func containerUpdateHasAnyResourceChange(objects []map[string]json.RawMessage, fields ...string) bool {
	for _, object := range objects {
		for key, raw := range object {
			for _, field := range fields {
				if strings.EqualFold(key, field) && containerUpdateResourceValueChanges(field, raw) {
					return true
				}
			}
		}
	}
	return false
}

func containerUpdateResourceValueChanges(field string, raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return false
	}

	switch field {
	case "BlkioWeight",
		"CpuCount",
		"CpuPercent",
		"CpuPeriod",
		"CpuQuota",
		"CpuRealtimePeriod",
		"CpuRealtimeRuntime",
		"CpuShares",
		"IOMaximumBandwidth",
		"IOMaximumIOps",
		"KernelMemory",
		"KernelMemoryTCP",
		"Memory",
		"MemoryReservation",
		"MemorySwap",
		"NanoCpus":
		return !bytes.Equal(trimmed, []byte("0"))
	case "CgroupParent", "CgroupnsMode", "CpusetCpus", "CpusetMems":
		var value string
		return json.Unmarshal(trimmed, &value) != nil || value != ""
	default:
		return true
	}
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
