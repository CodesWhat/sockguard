package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

const maxLibpodPodCreateBodyBytes = 1 << 20 // 1 MiB

// LibpodPodCreateOptions configures request-body policy checks for
// POST /libpod/pods/create — Podman's native pod-create endpoint. Pods have
// no Docker-compat equivalent, so this is its own inspector rather than an
// extension of container_create. See #148 and the design doc's C6 note on
// what is deliberately NOT covered here yet.
type LibpodPodCreateOptions struct {
	// AllowHostNetwork permits a pod-level NetNS of {"nsmode":"host"} — the
	// pod (and every container that joins it) shares the host network
	// namespace. Mirrors container_create.AllowHostNetwork's posture for the
	// pod-wide equivalent. Default false.
	AllowHostNetwork bool
	// AllowSharedPIDNamespace permits "pid" in the pod's SharedNamespaces
	// list, letting every container in the pod see (and signal) every other
	// container's processes — the pod-wide analog of container_create's
	// PidMode: host, scoped to the pod rather than the host. Default false.
	AllowSharedPIDNamespace bool
	// AllowedInfraImageRegistries allowlists the registry the pod's
	// infra_image reference resolves to, reusing the same host-allowlist
	// shape as ImagePullOptions.AllowedRegistries (see normalizeRegistryHost
	// / parseImageReference in image_pull.go). An empty infra_image
	// (Podman's built-in default pause image) is always allowed regardless
	// of this list. Default empty: any explicit infra_image is denied.
	AllowedInfraImageRegistries []string
}

type libpodPodCreatePolicy struct {
	allowHostNetwork            bool
	allowSharedPIDNamespace     bool
	allowedInfraImageRegistries []string
}

// The pod-create decode reuses libpodNamespace from
// libpod_container_create_types.go — both mirror the same specgen.Namespace
// wire shape ({"nsmode":"...","value":"..."}, pkg/specgen/namespaces.go,
// pinned to Podman v5.8.1).

// libpodPodCreateRequest decodes the subset of Podman's PodSpecGenerator
// (pkg/specgen/podspecgen.go, v5.8.1) this inspector gates. PodSpecGenerator
// embeds PodBasicConfig/PodNetworkConfig/etc. as anonymous Go struct fields,
// which encoding/json flattens to the top level on the wire — so "netns",
// "shared_namespaces", and "infra_image" all appear directly in the request
// body, not nested under a sub-object.
type libpodPodCreateRequest struct {
	NetNS            libpodNamespace `json:"netns"`
	SharedNamespaces []string        `json:"shared_namespaces"`
	InfraImage       string          `json:"infra_image"`
}

func newLibpodPodCreatePolicy(opts LibpodPodCreateOptions) libpodPodCreatePolicy {
	allowed := make([]string, 0, len(opts.AllowedInfraImageRegistries))
	for _, registry := range opts.AllowedInfraImageRegistries {
		normalized, ok := normalizeRegistryHost(registry)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return libpodPodCreatePolicy{
		allowHostNetwork:            opts.AllowHostNetwork,
		allowSharedPIDNamespace:     opts.AllowSharedPIDNamespace,
		allowedInfraImageRegistries: allowed,
	}
}

func (p libpodPodCreatePolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodPodCreatePath(normalizedPath) || r.Body == nil {
		return "", nil
	}

	body, err := readBoundedBody(r, maxLibpodPodCreateBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("libpod pod create denied: request body exceeds %d byte limit", maxLibpodPodCreateBodyBytes))
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	if len(body) == 0 {
		return "", nil
	}

	var req libpodPodCreateRequest
	if err := decodePolicySubsetJSON(body, &req); err != nil {
		logRequestError(logger, r, slog.LevelDebug, "libpod pod create request body could not be decoded for Sockguard policy inspection; deferring to Podman validation", err)
		return "libpod pod create denied: request body could not be inspected", nil
	}

	if !p.allowHostNetwork && isHostNamespaceMode(req.NetNS.NSMode) {
		return "libpod pod create denied: host network namespace is not allowed", nil
	}
	if !p.allowSharedPIDNamespace && slices.ContainsFunc(req.SharedNamespaces, isSharedPIDNamespaceEntry) {
		return "libpod pod create denied: shared PID namespace is not allowed", nil
	}
	if denyReason := p.denyInfraImageReason(req.InfraImage); denyReason != "" {
		return denyReason, nil
	}

	// TODO(#148): cross-owner namespace-sharing checks and owner-label
	// injection (design doc C6 — pod-level share/netns targets resolved
	// against AllowedNamespaceSharingContainers, lowercase "labels" mutation
	// on create) are deferred to the ownership/visibility follow-up PR. This
	// inspector only gates the raw request-body fields above.

	return "", nil
}

func (p libpodPodCreatePolicy) denyInfraImageReason(infraImage string) string {
	ref := strings.TrimSpace(infraImage)
	if ref == "" {
		return ""
	}
	parsed, ok := parseImageReference(ref)
	if !ok {
		return ""
	}
	if slices.Contains(p.allowedInfraImageRegistries, parsed.registry) {
		return ""
	}
	return fmt.Sprintf("libpod pod create denied: infra image registry %q is not allowlisted", parsed.registry)
}

func isSharedPIDNamespaceEntry(ns string) bool {
	return strings.EqualFold(strings.TrimSpace(ns), "pid")
}
