package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

const maxSwarmBodyBytes = 256 << 10 // 256 KiB

// SwarmOptions configures request-body inspection for swarm writes.
type SwarmOptions struct {
	AllowForceNewCluster          bool
	AllowExternalCA               bool
	AllowedJoinRemoteAddrs        []string
	AllowTokenRotation            bool
	AllowManagerUnlockKeyRotation bool
	AllowAutoLockManagers         bool
	AllowSigningCAUpdate          bool
}

type swarmPolicy struct {
	allowForceNewCluster          bool
	allowExternalCA               bool
	allowedJoinRemoteAddrs        []string
	allowTokenRotation            bool
	allowManagerUnlockKeyRotation bool
	allowAutoLockManagers         bool
	allowSigningCAUpdate          bool
}

type swarmInitRequest struct {
	ForceNewCluster bool            `json:"ForceNewCluster"`
	Spec            swarmSpecConfig `json:"Spec"`
}

type swarmJoinRequest struct {
	ListenAddr    string   `json:"ListenAddr"`
	AdvertiseAddr string   `json:"AdvertiseAddr"`
	DataPathAddr  string   `json:"DataPathAddr"`
	RemoteAddrs   []string `json:"RemoteAddrs"`
	JoinToken     string   `json:"JoinToken"`
}

type swarmUpdateRequest struct {
	CAConfig         swarmCAConfig `json:"CAConfig"`
	EncryptionConfig struct {
		AutoLockManagers bool `json:"AutoLockManagers"`
	} `json:"EncryptionConfig"`
}

type swarmSpecConfig struct {
	CAConfig swarmCAConfig `json:"CAConfig"`
}

type swarmCAConfig struct {
	ExternalCAs   []json.RawMessage `json:"ExternalCAs"`
	SigningCACert string            `json:"SigningCACert"`
	SigningCAKey  string            `json:"SigningCAKey"`
	ForceRotate   uint64            `json:"ForceRotate"`
}

func newSwarmPolicy(opts SwarmOptions) swarmPolicy {
	return swarmPolicy{
		allowForceNewCluster:          opts.AllowForceNewCluster,
		allowExternalCA:               opts.AllowExternalCA,
		allowedJoinRemoteAddrs:        normalizeSwarmRemoteAddrs(opts.AllowedJoinRemoteAddrs),
		allowTokenRotation:            opts.AllowTokenRotation,
		allowManagerUnlockKeyRotation: opts.AllowManagerUnlockKeyRotation,
		allowAutoLockManagers:         opts.AllowAutoLockManagers,
		allowSigningCAUpdate:          opts.AllowSigningCAUpdate,
	}
}

func (p swarmPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return "", nil
	}

	switch normalizedPath {
	case "/swarm/init":
		return p.inspectInit(logger, r)
	case "/swarm/join":
		return p.inspectJoin(logger, r)
	case "/swarm/update":
		return p.inspectUpdate(logger, r)
	default:
		return "", nil
	}
}

func (p swarmPolicy) inspectInit(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("swarm init denied: request body exceeds %d byte limit", maxSwarmBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmInitRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "swarm init request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	if !p.allowForceNewCluster && req.ForceNewCluster {
		return "swarm init denied: force-new-cluster is not allowed", nil
	}
	if !p.allowExternalCA && len(req.Spec.CAConfig.ExternalCAs) > 0 {
		return "swarm init denied: external CAs are not allowed", nil
	}
	if !p.allowSigningCAUpdate && hasSwarmSigningCAUpdate(req.Spec.CAConfig) {
		return "swarm init denied: signing CA updates are not allowed", nil
	}

	return "", nil
}

func (p swarmPolicy) inspectJoin(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("swarm join denied: request body exceeds %d byte limit", maxSwarmBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmJoinRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "swarm join request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	for _, remoteAddr := range req.RemoteAddrs {
		normalized := normalizeSwarmRemoteAddr(remoteAddr)
		if normalized == "" || p.joinRemoteAddrAllowed(normalized) {
			continue
		}
		return fmt.Sprintf("swarm join denied: remote address %q is not allowlisted", normalized), nil
	}

	return "", nil
}

func (p swarmPolicy) inspectUpdate(logger *slog.Logger, r *http.Request) (string, error) {
	body, err := readBoundedBody(r, maxSwarmBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return fmt.Sprintf("swarm update denied: request body exceeds %d byte limit", maxSwarmBodyBytes), nil
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req swarmUpdateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		if logger != nil {
			logger.DebugContext(r.Context(), "swarm update request body could not be decoded for Sockguard policy inspection; deferring to Docker validation", "error", err, "method", r.Method, "path", r.URL.Path)
		}
		return "", nil
	}

	if !p.allowExternalCA && len(req.CAConfig.ExternalCAs) > 0 {
		return "swarm update denied: external CAs are not allowed", nil
	}
	if !p.allowSigningCAUpdate && hasSwarmSigningCAUpdate(req.CAConfig) {
		return "swarm update denied: signing CA updates are not allowed", nil
	}
	if !p.allowAutoLockManagers && req.EncryptionConfig.AutoLockManagers {
		return "swarm update denied: manager autolock is not allowed", nil
	}
	if !p.allowTokenRotation && queryBool(r, "rotateWorkerToken") {
		return "swarm update denied: worker token rotation is not allowed", nil
	}
	if !p.allowTokenRotation && queryBool(r, "rotateManagerToken") {
		return "swarm update denied: manager token rotation is not allowed", nil
	}
	if !p.allowManagerUnlockKeyRotation && queryBool(r, "rotateManagerUnlockKey") {
		return "swarm update denied: manager unlock key rotation is not allowed", nil
	}

	return "", nil
}

func normalizeSwarmRemoteAddrs(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := normalizeSwarmRemoteAddr(value)
		if trimmed == "" || slices.Contains(normalized, trimmed) {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func normalizeSwarmRemoteAddr(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (p swarmPolicy) joinRemoteAddrAllowed(remoteAddr string) bool {
	return slices.Contains(p.allowedJoinRemoteAddrs, remoteAddr)
}

func hasSwarmSigningCAUpdate(cfg swarmCAConfig) bool {
	return strings.TrimSpace(cfg.SigningCACert) != "" || strings.TrimSpace(cfg.SigningCAKey) != "" || cfg.ForceRotate > 0
}

func queryBool(r *http.Request, name string) bool {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	switch strings.ToLower(raw) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
