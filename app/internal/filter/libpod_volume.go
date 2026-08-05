package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxLibpodVolumeBodyBytes = 1 << 20 // 1 MiB

// libpodVolumeCreateRequest mirrors Podman's entities.VolumeCreateOptions
// (pkg/domain/entities/types/volumes.go, pinned to Podman v5.8.1 — confirmed
// directly against upstream source per the design doc's C4 requirement).
// Unlike Docker's volumeCreateRequest, libpod's type carries no json tags at
// all: encoding/json falls back to the exported Go field name, so "Driver"
// and "Options" (not Docker's "DriverOpts"/"Opts") are the wire keys. Kept
// as its own decode struct — never made "smart" for both shapes — per the
// design doc's C6/agreed-core guidance.
type libpodVolumeCreateRequest struct {
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
}

// inspectLibpod is volumePolicy's libpod-path counterpart to inspect: same
// allow_custom_drivers/allow_driver_opts gates (config reused verbatim under
// the libpod_volume key, #148), different route match and decode shape.
func (p volumePolicy) inspectLibpod(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"volumes/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodVolumeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod volume create denied: request body exceeds %d byte limit", maxLibpodVolumeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodVolumeCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod volume create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod volume create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !strings.EqualFold(driver, "local") && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod volume create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowDriverOpts && len(req.Options) > 0 {
		return "libpod volume create denied: driver options are not allowed", nil
	}

	return "", nil
}
