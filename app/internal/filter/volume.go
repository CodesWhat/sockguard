package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

const maxVolumeBodyBytes = 1 << 20 // 1 MiB

// VolumeOptions configures request-body policy checks for POST /volumes/create.
type VolumeOptions struct {
	AllowCustomDrivers bool
	AllowDriverOpts    bool
	// AllowedBindMounts is the container-create bind-mount allowlist, not a
	// key of its own: a local-driver volume whose options ask for a bind
	// reaches the same host path a HostConfig.Binds entry would, so it is
	// checked against the same list. RequestBodyConfig.ToFilterOptions
	// cross-wires it. Only consulted when AllowDriverOpts is true, since
	// otherwise every driver options map is already denied outright.
	AllowedBindMounts []string
}

type volumePolicy struct {
	allowCustomDrivers bool
	allowDriverOpts    bool
	allowedBindMounts  []string
}

type volumeCreateRequest struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
	Opts       map[string]string `json:"Opts"`
}

func newVolumePolicy(opts VolumeOptions) volumePolicy {
	allowed := make([]string, 0, len(opts.AllowedBindMounts))
	for _, bindMount := range opts.AllowedBindMounts {
		normalized, ok := normalizeBindMount(bindMount)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return volumePolicy{
		allowCustomDrivers: opts.AllowCustomDrivers,
		allowDriverOpts:    opts.AllowDriverOpts,
		allowedBindMounts:  allowed,
	}
}

func (p volumePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/volumes/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxVolumeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("volume create denied: request body exceeds %d byte limit", maxVolumeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req volumeCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "volume create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "volume create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !strings.EqualFold(driver, "local") && !p.allowCustomDrivers {
		return fmt.Sprintf("volume create denied: driver %q is not allowed", driver), nil
	}

	if !p.allowDriverOpts && len(req.DriverOpts)+len(req.Opts) > 0 {
		return "volume create denied: driver options are not allowed", nil
	}

	for _, options := range []map[string]string{req.DriverOpts, req.Opts} {
		if denyReason := denyLocalVolumeBindDeviceReason(req.Driver, options, p.allowedBindMounts, "volume create"); denyReason != "" {
			return denyReason, nil
		}
	}

	return "", nil
}
