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

const maxVolumeBodyBytes = 1 << 20 // 1 MiB

// VolumeOptions configures request-body policy checks for POST /volumes/create
// and PUT /volumes/{name}.
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
	// AllowClusterVolumeSecrets permits ClusterVolumeSpec.Secrets on
	// PUT /volumes/{name}. Default false, and deliberately its own knob
	// rather than a reuse of AllowDriverOpts: driver options are a routine
	// setting on ordinary local volumes, so overloading that flag would
	// silently open secret rewriting for every operator who already sets it.
	// Each entry names a Swarm secret the daemon then hands to the CSI
	// plugin, so a caller who can rewrite the list can point the plugin at a
	// secret it was never granted. AllowClusterVolumeUpdates does NOT admit
	// Secrets — this is the only flag that does.
	AllowClusterVolumeSecrets bool
	// AllowClusterVolumeUpdates permits every OTHER ClusterVolumeSpec field
	// on PUT /volumes/{name}: Availability, Group, AccessMode,
	// CapacityRange and AccessibilityRequirements. Default false.
	AllowClusterVolumeUpdates bool
}

type volumePolicy struct {
	allowCustomDrivers        bool
	allowDriverOpts           bool
	allowedBindMounts         []string
	allowClusterVolumeSecrets bool
	allowClusterVolumeUpdates bool
}

type volumeCreateRequest struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
	Opts       map[string]string `json:"Opts"`
}

// volumeUpdateRequest mirrors Docker's volume.UpdateOptions, the body
// PUT /volumes/{name}?version=N decodes (moby's volume router registers
// `PUT /volumes/{name:.*}` on putVolumesUpdate). It is a single optional
// `Spec` object; an absent or null Spec is a no-op the daemon applies
// nothing from, so it is allowed here rather than denied.
type volumeUpdateRequest struct {
	Spec *volumeClusterSpec `json:"Spec"`
}

// volumeClusterSpec mirrors Docker's volume.ClusterVolumeSpec — the Swarm
// CSI half of the volume API. None of its fields carry an explicit JSON name
// in moby, so the wire keys are the Go field names and encoding/json's
// case-insensitive fallback accepts the lowercase spellings a hand-rolled
// client might send.
//
// The three object-valued fields are captured as json.RawMessage because
// presence is all the gates need, and a raw capture is what makes a
// field-level type mismatch (AccessMode as a number, say) surface as a
// decode error and fail closed instead of being silently skipped — the same
// reason nodeUpdateRequest captures its fields that way.
//
// Which gate covers what is deliberately lopsided. Secrets sits behind its
// own AllowClusterVolumeSecrets because it is the one field that reaches
// outside the volume: each entry names a Swarm secret whose value the daemon
// passes to the CSI plugin. The rest share AllowClusterVolumeUpdates —
// Availability drain/pause forces the volume off every node using it, and
// Group, AccessMode, CapacityRange and AccessibilityRequirements re-shape
// how and where the volume is published. Today moby's Cluster.UpdateVolume
// applies only Availability and ignores the others, but that is a
// daemon-version fact and not something a fail-closed proxy should rely on,
// so every field is gated.
type volumeClusterSpec struct {
	Group                     string            `json:"Group"`
	AccessMode                json.RawMessage   `json:"AccessMode"`
	AccessibilityRequirements json.RawMessage   `json:"AccessibilityRequirements"`
	CapacityRange             json.RawMessage   `json:"CapacityRange"`
	Secrets                   []json.RawMessage `json:"Secrets"`
	Availability              string            `json:"Availability"`
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
		allowCustomDrivers:        opts.AllowCustomDrivers,
		allowDriverOpts:           opts.AllowDriverOpts,
		allowedBindMounts:         allowed,
		allowClusterVolumeSecrets: opts.AllowClusterVolumeSecrets,
		allowClusterVolumeUpdates: opts.AllowClusterVolumeUpdates,
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

// inspectUpdate gates PUT /volumes/{name}, the Swarm cluster-volume (CSI)
// update. The endpoint had no matcher and no inspector at all, so a client
// holding an allow rule for it could rewrite an existing volume's
// ClusterVolumeSpec — including the Swarm secrets handed to the CSI plugin —
// with nothing read and no blind-write acknowledgment demanded, while the
// sibling POST /volumes/create was inspected by default.
//
// It is inspected rather than parked behind insecure_allow_body_blind_writes
// for the reason libpod's network update was: the body is one small,
// fully-modelable JSON object, so an acknowledgment where a decode struct
// suffices is the weaker control.
//
// One shipped preset reaches the route: portainer.yaml allows
// `method: "*"` on `/volumes/**`, which is precisely the shape that made this
// an unread write. Every other config under app/configs/ denies it, verified
// by replaying all 25 through the production evaluator.
//
// The ownership layer already authorizes the target: volumeIdentifier
// matches any method under /volumes/ that is not create or prune, so
// checkOwnedResource runs for PUT and denies an update aimed at another
// owner's volume before this inspector's field gates matter. This function
// is the body half of the same request.
func (p volumePolicy) inspectUpdate(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPut || !isVolumeUpdatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxVolumeBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("volume update denied: request body exceeds %d byte limit", maxVolumeBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req volumeUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "volume update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", err)
		return "volume update denied: request body could not be inspected", nil
	}

	if req.Spec == nil {
		return "", nil
	}

	if !p.allowClusterVolumeSecrets && len(req.Spec.Secrets) > 0 {
		return "volume update denied: cluster volume secrets are not allowed", nil
	}

	if p.allowClusterVolumeUpdates {
		return "", nil
	}
	if strings.TrimSpace(req.Spec.Availability) != "" {
		return "volume update denied: cluster volume availability changes are not allowed", nil
	}
	if strings.TrimSpace(req.Spec.Group) != "" {
		return "volume update denied: cluster volume group changes are not allowed", nil
	}
	if volumeClusterSpecFieldSet(req.Spec.AccessMode) {
		return "volume update denied: cluster volume access mode changes are not allowed", nil
	}
	if volumeClusterSpecFieldSet(req.Spec.CapacityRange) {
		return "volume update denied: cluster volume capacity changes are not allowed", nil
	}
	if volumeClusterSpecFieldSet(req.Spec.AccessibilityRequirements) {
		return "volume update denied: cluster volume topology changes are not allowed", nil
	}

	return "", nil
}

// volumeClusterSpecFieldSet reports whether a raw ClusterVolumeSpec field was
// present with a value. An absent key and an explicit null are both "not
// present": moby applies neither, so neither is a change to gate.
func volumeClusterSpecFieldSet(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// isVolumeUpdatePath matches the whole route moby registers for the
// cluster-volume update, `PUT /volumes/{name:.*}`. The identifier is a
// slash-bearing path rather than one segment because that is how the route
// is spelled upstream, so a rule constrained below one literal segment must
// still land here.
//
// PUT /volumes/create and PUT /volumes/prune match too, and that is correct
// rather than sloppy: there is no PUT route for either, so moby resolves
// both into putVolumesUpdate with the name "create" or "prune". Excluding
// them the way volumeIdentifier and matchesVolumeInspection exclude the POST
// spellings would leave two uninspected doors into the same handler.
func isVolumeUpdatePath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "/volumes/") &&
		strings.TrimPrefix(normalizedPath, "/volumes/") != ""
}
