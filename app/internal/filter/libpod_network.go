package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const maxLibpodNetworkBodyBytes = 1 << 20 // 1 MiB

// libpodNetworkCreateRequest mirrors Podman's libnetwork/types.Network
// (go.podman.io/common's libnetwork/types package, pinned via Podman
// v5.8.1's go.sum — confirmed directly against upstream source per the
// design doc's C4 requirement). Its shape has almost nothing in common with
// Docker's networkCreateRequest: lowercase snake_case json tags, no nested
// IPAM object (subnets/options are top-level fields), and no
// Attachable/Ingress/ConfigOnly/ConfigFrom/Scope/EnableIPv4 concept at
// all — libpod networks predate and are independent of Docker's swarm mode.
// Subnets is decoded as raw messages only to detect presence (custom static
// IPAM config); its element shape is irrelevant to the gates below and
// deliberately not modeled. Kept as its own decode struct — never made
// "smart" for both shapes — per the design doc's C6/agreed-core guidance.
//
// Fields on the reused NetworkRequestBodyConfig with no libpod analog
// (allow_swarm_scope, allow_ingress, allow_attachable, allow_config_only,
// allow_config_from, allow_custom_ipam_drivers, allow_endpoint_config,
// endpoint_config (#186's granular per-field gates), allow_disconnect_force,
// allow_disable_ipv4) are simply never consulted here — see
// configuration.mdx's libpod_network section for the documented list,
// rather than silently reinterpreting them against unrelated fields. There
// is no libpod-native network-connect endpoint at all (Podman's compat API
// connect goes through the Docker-compat path, not libpod's own), so
// endpoint_config has nothing to gate here regardless.
type libpodNetworkCreateRequest struct {
	Driver      string            `json:"driver"`
	Options     map[string]string `json:"options"`
	IPAMOptions map[string]string `json:"ipam_options"`
	Subnets     []json.RawMessage `json:"subnets"`
}

// inspectLibpodCreate is networkPolicy's libpod-path counterpart to
// inspectCreate: config reused verbatim under the libpod_network key
// (#148), narrowed to the gates that have a libpod analog (see
// libpodNetworkCreateRequest's doc comment).
func (p networkPolicy) inspectLibpodCreate(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != libpodPathPrefix+"networks/create" || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodNetworkBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod network create denied: request body exceeds %d byte limit", maxLibpodNetworkBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodNetworkCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod network create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod network create denied: request body could not be inspected", nil
	}

	if driver := strings.TrimSpace(req.Driver); driver != "" && !isBuiltinNetworkDriver(driver) && !p.allowCustomDrivers {
		return fmt.Sprintf("libpod network create denied: driver %q is not allowed", driver), nil
	}
	if !p.allowDriverOptions && len(req.Options) > 0 {
		return "libpod network create denied: driver options are not allowed", nil
	}
	if !p.allowCustomIPAMConfig && len(req.Subnets) > 0 {
		return "libpod network create denied: custom subnet configuration is not allowed", nil
	}
	if !p.allowIPAMOptions && len(req.IPAMOptions) > 0 {
		return "libpod network create denied: IPAM options are not allowed", nil
	}

	return "", nil
}
