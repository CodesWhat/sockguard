package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxVolumeBodyBytes = 1 << 20 // 1 MiB

// VolumeOptions configures request-body policy checks for POST /volumes/create.
type VolumeOptions struct {
	AllowCustomDrivers bool
	AllowDriverOpts    bool
}

type volumePolicy struct {
	allowCustomDrivers bool
	allowDriverOpts    bool
}

type volumeCreateRequest struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
	Opts       map[string]string `json:"Opts"`
}

func newVolumePolicy(opts VolumeOptions) volumePolicy {
	return volumePolicy{
		allowCustomDrivers: opts.AllowCustomDrivers,
		allowDriverOpts:    opts.AllowDriverOpts,
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
		if logger != nil {
			logger.DebugContext(r.Context(), "volume create request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "volume create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !strings.EqualFold(driver, "local") && !p.allowCustomDrivers {
		return fmt.Sprintf("volume create denied: driver %q is not allowed", driver), nil
	}

	if !p.allowDriverOpts && len(req.DriverOpts)+len(req.Opts) > 0 {
		return "volume create denied: driver options are not allowed", nil
	}

	return "", nil
}
