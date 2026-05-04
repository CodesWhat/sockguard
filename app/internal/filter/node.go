package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

const (
	maxNodeBodyBytes       = 256 << 10 // 256 KiB
	defaultOwnerLabelKey   = "com.sockguard.owner"
	nodeUpdateDenyPrefix   = "node update denied"
	nodeDecodeDebugMessage = "node update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation"
)

// NodeOptions configures request-body inspection for node updates.
type NodeOptions struct {
	AllowNameChange         bool
	AllowRoleChange         bool
	AllowAvailabilityChange bool
	AllowLabelMutation      bool
	AllowedLabelKeys        []string
}

type nodePolicy struct {
	allowNameChange         bool
	allowRoleChange         bool
	allowAvailabilityChange bool
	allowLabelMutation      bool
	allowedLabelKeys        []string
}

type nodeUpdateRequest struct {
	Name         json.RawMessage `json:"Name"`
	Labels       json.RawMessage `json:"Labels"`
	Role         json.RawMessage `json:"Role"`
	Availability json.RawMessage `json:"Availability"`
}

func newNodePolicy(opts NodeOptions) nodePolicy {
	return nodePolicy{
		allowNameChange:         opts.AllowNameChange,
		allowRoleChange:         opts.AllowRoleChange,
		allowAvailabilityChange: opts.AllowAvailabilityChange,
		allowLabelMutation:      opts.AllowLabelMutation,
		allowedLabelKeys:        normalizeNodeAllowedLabelKeys(opts.AllowedLabelKeys),
	}
}

func (p nodePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isNodeUpdatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxNodeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("%s: request body exceeds %d byte limit", nodeUpdateDenyPrefix, maxNodeBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req nodeUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logNodeDecodeDefer(logger, r, err)
		return "", nil
	}

	denyReason, err := p.denyReason(req)
	if err != nil {
		logNodeDecodeDefer(logger, r, err)
		return "", nil
	}
	return denyReason, nil
}

func (p nodePolicy) denyReason(req nodeUpdateRequest) (string, error) {
	role, rolePresent, err := nodeStringField(req.Role)
	if err != nil {
		return "", err
	}
	if rolePresent && role != "" && !p.allowRoleChange {
		return "node update denied: role changes are not allowed", nil
	}

	availability, availabilityPresent, err := nodeStringField(req.Availability)
	if err != nil {
		return "", err
	}
	if availabilityPresent && availability != "" && !p.allowAvailabilityChange {
		return "node update denied: availability changes are not allowed", nil
	}

	name, namePresent, err := nodeStringField(req.Name)
	if err != nil {
		return "", err
	}
	if namePresent && name != "" && !p.allowNameChange {
		return "node update denied: name changes are not allowed", nil
	}

	labels, labelsPresent, err := nodeLabelsField(req.Labels)
	if err != nil {
		return "", err
	}
	if labelsPresent && !p.allowLabelMutation && !p.allowsConfiguredLabelOnly(labels) {
		return "node update denied: label mutation is not allowed", nil
	}

	return "", nil
}

func (p nodePolicy) allowsConfiguredLabelOnly(labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	for key, value := range labels {
		if !slices.Contains(p.allowedLabelKeys, key) {
			return false
		}
		if key == defaultOwnerLabelKey && value == "" {
			return false
		}
	}
	return true
}

func normalizeNodeAllowedLabelKeys(values []string) []string {
	normalized := []string{defaultOwnerLabelKey}
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" || slices.Contains(normalized, key) {
			continue
		}
		normalized = append(normalized, key)
	}
	return normalized
}

func nodeStringField(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, err
	}
	return strings.TrimSpace(value), true, nil
}

func nodeLabelsField(raw json.RawMessage) (map[string]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true, nil
	}

	var labels map[string]string
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, true, err
	}
	return labels, true, nil
}

func logNodeDecodeDefer(logger *slog.Logger, r *http.Request, err error) {
	if logger != nil {
		logger.DebugContext(r.Context(), nodeDecodeDebugMessage, "error", err, "method", r.Method, "path", r.URL.Path)
	}
}

func isNodeUpdatePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}
