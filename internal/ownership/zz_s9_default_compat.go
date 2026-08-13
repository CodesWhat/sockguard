package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/dockerfilters"
	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// libpodNamespaceSharingFields are the namespace-mode object fields whose
// {"nsmode":"container","value":"<ref>"} form joins another container's
// namespace, shared verbatim between POST /libpod/containers/create
// (libpodContainerCreateRequest) and POST /libpod/pods/create
// (PodBasicConfig/PodNetworkConfig) — both SpecGenerator and
// PodSpecGenerator expose the identical netns/pidns/ipcns/userns/utsns set.
// cgroupns is intentionally excluded, mirroring
// internal/filter/libpod_container_create.go's denyNamespaceSharingReason
// (itself mirroring the Docker-compat containerCreatePolicy's own exclusion).
var libpodNamespaceSharingFields = [...]string{"netns", "pidns", "ipcns", "userns", "utsns"}

// mutateLibpodContainerCreateOwnershipBody injects the owner label into a
// POST /libpod/containers/create body under the lowercase "labels" key
// (SpecGenerator field name, confirmed against
// testdata/libpod/labels.json) and extracts the cross-owner references
// authorization must also cover: the "pod" field (joining another owner's
// pod — #148 design doc item 4), the "image" field, and any
// {"nsmode":"container","value":"<ref>"} namespace-sharing target — the
// libpod-shaped counterpart of mutateContainerCreateOwnershipBody's Docker
// HostConfig.{NetworkMode,PidMode,IpcMode,UTSMode,UsernsMode} handling.
func mutateLibpodContainerCreateOwnershipBody(r *http.Request, labelKey, owner string) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, "labels")
		if err != nil {
			return err
		}
		labels[labelKey] = owner

		refs.namespaceContainers = libpodNamespaceRefs(decoded)

		for _, image := range filter.FoldedStrings(decoded, "image") {
			appendEmbeddedOwnershipReference(&refs.embeddedResources, dockerresource.KindImage, image, "libpod container create image")
		}
		for _, pod := range filter.FoldedStrings(decoded, "pod") {
			appendEmbeddedOwnershipReference(&refs.embeddedResources, dockerresource.KindLibpodPod, pod, "libpod container create pod")
		}
		return nil
	})
	return refs, err
}

// mutateLibpodPodCreateOwnershipBody injects the owner label into a
// POST /libpod/pods/create body under the lowercase "labels" key
// (PodBasicConfig.Labels, confirmed against podman v5.8.1's
// pkg/specgen/podspecgen.go source) and extracts the same class of
// cross-owner references container-create gets: any
// {"nsmode":"container","value":"<ref>"} namespace-sharing target across
// netns/pidns/ipcns/userns/utsns (closing the deferral #190's changelog
// entry called out — "cross-owner pod-membership checks are explicitly
// deferred to a later PR"), and the "infra_image" field (an explicit,
// non-default infra image is a "join/reference another owner's resource"
// exactly like container-create's own "image" field; an empty infra_image —
// Podman's built-in default pause image — never appears here since
// FoldedStrings skips empty/absent values).
func mutateLibpodPodCreateOwnershipBody(r *http.Request, labelKey, owner string) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, "labels")
		if err != nil {
			return err
		}
		labels[labelKey] = owner

		refs.namespaceContainers = libpodNamespaceRefs(decoded)

		for _, infraImage := range filter.FoldedStrings(decoded, "infra_image") {
			appendEmbeddedOwnershipReference(&refs.embeddedResources, dockerresource.KindImage, infraImage, "libpod pod create infra_image")
		}
		return nil
	})
	return refs, err
}

// libpodNamespaceRefs extracts every distinct "container:<ref>"-equivalent
// namespace-sharing target from a decoded libpod container-create or
// pod-create body's netns/pidns/ipcns/userns/utsns fields. Key matching is
// case-INSENSITIVE via filter.FoldedObjects/FoldedStrings for the same
// reason containerCreateNamespaceRefs folds Docker's HostConfig keys: a
// crafted case-variant field name must not smuggle a namespace join past
// this check (mutateJSONBody's RejectDuplicateCaseVariantJSONKeys pass
// already ensures at most one case-variant of each field can be present).
func libpodNamespaceRefs(decoded map[string]any) []string {
	var refs []string
	for _, field := range libpodNamespaceSharingFields {
		for _, ns := range filter.FoldedObjects(decoded, field) {
			ref, ok := libpodNamespaceContainerRef(ns)
			if !ok || slices.Contains(refs, ref) {
				continue
			}
			refs = append(refs, ref)
		}
	}
	return refs
}

// libpodNamespaceContainerRef reports whether a decoded namespace object
// ({"nsmode": "...", "value": "..."}) joins another container's namespace
// and, if so, returns the trimmed ref. Mirrors
// libpodNamespace.containerRef in internal/filter/libpod_container_create_types.go,
// operating on the generic map[string]any shape mutateJSONBody decodes into
// rather than a typed struct.
func libpodNamespaceContainerRef(ns map[string]any) (string, bool) {
	if !filter.FoldedStringEquals(ns, "nsmode", "container") {
		return "", false
	}
	for _, value := range filter.FoldedStrings(ns, "value") {
		value = strings.TrimSpace(value)
		if value != "" {
			return value, true
		}
	}
	return "", false
}

// addOwnerLabelToLibpodBody injects the owner label into a libpod
// network/volume create body under labelField — the exact wire key to use,
// since the two endpoints disagree on casing: lowercase "labels" for
// network create (go.podman.io/common's libnetwork/types.Network carries a
// `json:"labels,omitempty"` tag), capitalized "Labels" for volume create
// (entities.VolumeCreateOptions carries no json tags at all, so
// encoding/json falls back to the Go field name — see libpod_volume.go's
// libpodVolumeCreateRequest doc comment, which pins the same behavior for
// its "Driver"/"Options" fields). Neither body carries a cross-owner
// reference worth extracting (no image, container, or pod field), so this
// never returns *ownershipRequestReferences the way the container/pod
// mutators do.
func addOwnerLabelToLibpodBody(r *http.Request, labelKey, owner, labelField string) error {
	return mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, labelField)
		if err != nil {
			return err
		}
		labels[labelKey] = owner
		return nil
	})
}

// libpod_paths.go is paths.go's counterpart for Podman's native /libpod/
// API family (#148 PR5). Every matcher here is exact-prefix-guarded on
// libpodPrefix so a Docker-compat path can never satisfy a libpod predicate
// and vice versa, mirroring internal/filter/libpod_normalize.go's own
// exact-prefix-guard convention for the same reason (see that file's doc
// comment on isLibpodPath).
const libpodPrefix = "/libpod/"

const (
	libpodContainerCreatePath = libpodPrefix + "containers/create"
	libpodPodCreatePath       = libpodPrefix + "pods/create"
	libpodNetworkCreatePath   = libpodPrefix + "networks/create"
	libpodVolumeCreatePath    = libpodPrefix + "volumes/create"
	libpodSecretCreatePath    = libpodPrefix + "secrets/create"
)

// isLibpodOwnershipPath reports whether normPath falls under the /libpod/
// route family, for the sole purpose of deciding whether a denial reason
// should carry the "libpod " prefix convention (#148 design doc, item 5) —
// matching the human-readable-reason style internal/filter's libpod_*.go
// inspectors already use ("libpod container create denied: ...").
func isLibpodOwnershipPath(normPath string) bool {
	return strings.HasPrefix(normPath, libpodPrefix)
}

// libpodNeedsOwnerFilter mirrors needsOwnerFilter for libpod's list
// endpoints. Podman consistently suffixes every /libpod/ list endpoint with
// "/json" (unlike the Docker-compat API's mixed /networks vs /containers/json
// convention), so every entry here follows that one shape.
func libpodNeedsOwnerFilter(normPath string) bool {
	switch normPath {
	case libpodPrefix + "containers/json",
		libpodPrefix + "pods/json",
		libpodPrefix + "networks/json",
		libpodPrefix + "volumes/json",
		libpodPrefix + "secrets/json":
		return true
	default:
		return false
	}
}

// libpodContainerIdentifier matches any /libpod/containers/{id}/... path,
// returning {id}. Mirrors containerIdentifier's "any action on a specific
// container" breadth (start/stop/kill/exec-create/attach/inspect/...), not
// just inspect — a client acting on another owner's container through the
// libpod route family must be denied the same as through the Docker-compat
// one.
func libpodContainerIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"containers/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"containers/"), "/")
	switch identifier {
	case "", "create", "json", "prune":
		return "", false
	default:
		return identifier, true
	}
}

// libpodExecIdentifier matches /libpod/exec/{id}/..., the libpod
// counterpart of execIdentifier. Podman's exec-session store is shared
// between the Docker-compat and libpod route families (both are a view onto
// the same libpod runtime state), so the existing Docker-compat
// GET /exec/{id}/json upstream inspector correctly resolves a libpod-created
// exec session's owning container too — no separate libpod-path exec
// inspector is needed here.
func libpodExecIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

// libpodPodIdentifier matches /libpod/pods/{id}/..., the libpod-only
// counterpart of containerIdentifier for KindLibpodPod. "stats" is reserved
// alongside "json"/"create"/"prune" because GET /libpod/pods/stats is a
// collection-level endpoint (all pods' stats), not a per-pod one.
func libpodPodIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"pods/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"pods/"), "/")
	switch identifier {
	case "", "create", "json", "prune", "stats":
		return "", false
	default:
		return identifier, true
	}
}

// libpodNetworkIdentifier matches /libpod/networks/{id}/..., checked against
// the Docker-compat KindNetwork path (see dockerresource.KindLibpodNetwork's
// doc comment on why ownership's write-side check does not need the
// libpod-native inspect path the way visibility's does).
func libpodNetworkIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"networks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"networks/"), "/")
	switch identifier {
	case "", "create", "prune", "json":
		return "", false
	default:
		return identifier, true
	}
}

// libpodVolumeIdentifier matches /libpod/volumes/{id}/....
func libpodVolumeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"volumes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"volumes/"), "/")
	switch identifier {
	case "", "create", "prune", "json":
		return "", false
	default:
		return identifier, true
	}
}

// libpodSecretIdentifier matches /libpod/secrets/{id}/....
func libpodSecretIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, libpodPrefix+"secrets/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, libpodPrefix+"secrets/"), "/")
	switch identifier {
	case "", "create", "json":
		return "", false
	default:
		return identifier, true
	}
}

const DefaultLabelKey = "com.sockguard.owner"

const (
	reasonCodeOwnerRequestInvalid     = "owner_request_invalid"
	reasonCodeOwnerPolicyLookupFailed = "owner_policy_lookup_failed"
	reasonCodeOwnerPolicyDeniedAccess = "owner_policy_denied_access"
)

// maxOwnershipBodyBytes caps the request body the ownership middleware will
// read when it mutates a container/network/volume create body or a build
// query to inject the owner label. Docker's own create payloads are at most
// a few KiB, so 1 MiB is generous while preventing an allowlisted client
// from OOMing the proxy with an unbounded JSON body.
const maxOwnershipBodyBytes = 1 << 20 // 1 MiB

// ownershipVerdict is the outcome of an ownership policy check against an
// inbound request. Callers should forward `verdictPassThrough` and
// `verdictAllow` unchanged to the next handler; `verdictDeny` should short
// circuit with a 403 and the accompanying reason.
type ownershipVerdict int

const (
	// verdictPassThrough means the request does not target a resource that
	// the ownership middleware knows how to inspect, so it is forwarded
	// unchanged to the next handler.
	verdictPassThrough ownershipVerdict = iota
	// verdictAllow means the request targets a labeled resource that matches
	// the configured owner.
	verdictAllow
	// verdictDeny means the request targets a labeled resource that belongs
	// to a different owner identity.
	verdictDeny
)

type embeddedOwnershipReference struct {
	kind       dockerresource.Kind
	identifier string
	source     string
}

type ownershipRequestReferences struct {
	namespaceContainers []string
	embeddedResources   []embeddedOwnershipReference
}

// Options configures per-proxy resource ownership labeling and enforcement.
type Options struct {
	Owner              string
	LabelKey           string
	AllowUnownedImages bool
	// AllowCrossOwnerNamespaceSharing restores the pre-v1.5 pass-through
	// behavior for POST /containers/create: by default (false), every
	// HostConfig.NetworkMode/PidMode/IpcMode/UTSMode/UsernsMode "container:<ref>"
	// namespace-sharing target is resolved and the request is denied if the
	// referenced container belongs to a different owner. Set true to
	// restore the old unchecked behavior.
	AllowCrossOwnerNamespaceSharing bool
}

type upstreamInspector struct {
	client *http.Client
}

// Middleware applies owner-label mutation and enforcement for a single proxy
// identity. When Owner is empty, it is a no-op. It is the single-local-socket
// shorthand; MiddlewareWithRoundTripper takes the shared upstream transport so
// owner-label inspects follow the same active endpoint as the proxied request.
func Middleware(upstreamSocket string, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithClient(dockerclient.New(upstreamSocket), logger, opts)
}

// MiddlewareWithRoundTripper is Middleware over the shared upstream RoundTripper
// (typically an *upstream.Resolver), keeping owner-label inspection coherent
// with the request path under failover.
func MiddlewareWithRoundTripper(rt http.RoundTripper, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	return middlewareWithClient(dockerclient.NewWithRoundTripper(rt), logger, opts)
}

func middlewareWithClient(client *http.Client, logger *slog.Logger, opts Options) func(http.Handler) http.Handler {
	inspector := upstreamInspector{
		client: client,
	}

	return middlewareWithDeps(logger, opts, inspector.inspectResource, inspector.inspectExec)
}

func middlewareWithDeps(
	logger *slog.Logger,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
) func(http.Handler) http.Handler {
	opts = opts.normalized()
	if opts.Owner == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prefer the normalized path the filter middleware already stamped
			// on the access-log meta so we don't re-run NormalizePath on the
			// hot path. If ownership runs outside a filter chain (rare — tests
			// and isolated usage), fall back to computing it here.
			var normPath string
			if meta := logging.MetaForRequest(w, r); meta != nil && meta.NormPath != "" {
				normPath = meta.NormPath
			} else {
				normPath = filter.NormalizePath(r.URL.Path)
			}

			refs, err := mutateOwnershipRequest(r, normPath, opts)
			if err != nil {
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerRequestInvalid, err.Error(), nil)
				_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
				return
			}

			verdict, reason, err := allowOwnershipRequest(r.Context(), normPath, opts, inspectResource, inspectExec, refs)
			if err != nil {
				logger.ErrorContext(r.Context(), "owner policy lookup failed", "error", logging.SafeString(err.Error()), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyLookupFailed, "owner policy lookup failed", nil)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner policy lookup failed"})
				return
			}
			if verdict != verdictDeny {
				next.ServeHTTP(w, r)
				return
			}

			meta := logging.MetaForRequest(w, r)
			if meta.AllowsPassThrough() {
				logging.SetWouldDenyWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
				next.ServeHTTP(w, r)
				return
			}
			logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
			_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
		})
	}
}

func (o Options) normalized() Options {
	if o.LabelKey == "" {
		o.LabelKey = DefaultLabelKey
	}
	return o
}

// mutateOwnershipRequest injects the owner label and extracts every resource
// identifier embedded in container/service create or update bodies during the
// same bounded decode pass. Authorization must cover those identifiers as well
// as the resource named by the URL; otherwise an owner-stamped workload could
// still consume another owner's image, volume, network, secret, or config.
func mutateOwnershipRequest(r *http.Request, normPath string, opts Options) (*ownershipRequestReferences, error) {
	switch {
	case normPath == "/containers/create":
		return mutateContainerCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/networks/create", normPath == "/volumes/create", normPath == "/secrets/create", normPath == "/configs/create":
		return nil, addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/services/create", isServiceUpdatePath(normPath):
		return mutateServiceOwnershipBody(r, opts.LabelKey, opts.Owner)
	case isNodeUpdatePath(normPath), isSwarmUpdatePath(normPath):
		return nil, addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case normPath == "/build":
		return nil, addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case normPath == libpodContainerCreatePath:
		return mutateLibpodContainerCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case normPath == libpodPodCreatePath:
		return mutateLibpodPodCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case normPath == libpodNetworkCreatePath:
		return nil, addOwnerLabelToLibpodBody(r, opts.LabelKey, opts.Owner, "labels")
	case normPath == libpodVolumeCreatePath:
		return nil, addOwnerLabelToLibpodBody(r, opts.LabelKey, opts.Owner, "Labels")
	case normPath == libpodSecretCreatePath:

		return nil, addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case needsOwnerFilter(normPath), libpodNeedsOwnerFilter(normPath):
		return nil, addOwnerLabelFilter(r, opts.LabelKey, opts.Owner)
	default:
		return nil, nil
	}
}

// allowOwnershipRequest is allowOwnershipRequestUnprefixed with the "libpod "
// deny-reason prefix convention (#148 design doc item 5, matching the
// human-readable-reason style internal/filter's libpod_*.go inspectors
// already use) applied once, for every libpod-family request path, rather
// than threading the prefix decision through each individual check
// function.
func allowOwnershipRequest(
	ctx context.Context,
	normPath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
	refs *ownershipRequestReferences,
) (ownershipVerdict, string, error) {
	verdict, reason, err := allowOwnershipRequestUnprefixed(ctx, normPath, opts, inspectResource, inspectExec, refs)
	if verdict == verdictDeny && isLibpodOwnershipPath(normPath) {
		reason = "libpod " + reason
	}
	return verdict, reason, err
}

func allowOwnershipRequestUnprefixed(
	ctx context.Context,
	normPath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
	refs *ownershipRequestReferences,
) (ownershipVerdict, string, error) {
	strictest := verdictPassThrough
	if refs != nil {
		if !opts.AllowCrossOwnerNamespaceSharing && len(refs.namespaceContainers) > 0 {
			verdict, reason, err := checkContainerNamespaceSharingRefs(ctx, inspectResource, refs.namespaceContainers, opts)
			if err != nil || verdict == verdictDeny {
				return verdict, reason, err
			}
			if verdict == verdictAllow {
				strictest = verdictAllow
			}
		}

		verdict, reason, err := checkEmbeddedOwnershipReferences(ctx, inspectResource, refs.embeddedResources, opts)
		if err != nil || verdict == verdictDeny {
			return verdict, reason, err
		}
		if verdict == verdictAllow {
			strictest = verdictAllow
		}
	}

	verdict, reason, err := allowPathOwnershipRequest(ctx, normPath, opts, inspectResource, inspectExec)
	if err != nil || verdict == verdictDeny {
		return verdict, reason, err
	}
	if verdict == verdictAllow || strictest == verdictAllow {
		return verdictAllow, "", nil
	}
	return verdictPassThrough, "", nil
}

func allowPathOwnershipRequest(
	ctx context.Context,
	normPath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
) (ownershipVerdict, string, error) {
	if identifier, ok := containerIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, identifier, opts, false)
	}
	if execID, ok := execIdentifier(normPath); ok {
		containerID, found, err := inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictPassThrough, "", nil
		}
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, containerID, opts, false)
	}
	if identifier, ok := networkIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNetwork, identifier, opts, false)
	}
	if identifier, ok := volumeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindVolume, identifier, opts, false)
	}
	if identifier, ok := imageIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	}
	if identifier, ok := serviceIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindService, identifier, opts, false)
	}
	if identifier, ok := taskIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindTask, identifier, opts, false)
	}
	if identifier, ok := secretIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSecret, identifier, opts, false)
	}
	if identifier, ok := configIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindConfig, identifier, opts, false)
	}
	if identifier, ok := nodeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNode, identifier, opts, isNodeUpdatePath(normPath))
	}
	if isSwarmPath(normPath) || isSwarmUpdatePath(normPath) {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSwarm, "", opts, isSwarmUpdatePath(normPath))
	}

	if identifier, ok := libpodContainerIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, identifier, opts, false)
	}
	if execID, ok := libpodExecIdentifier(normPath); ok {
		containerID, found, err := inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictPassThrough, "", nil
		}
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, containerID, opts, false)
	}
	if identifier, ok := libpodPodIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindLibpodPod, identifier, opts, false)
	}
	if identifier, ok := libpodNetworkIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNetwork, identifier, opts, false)
	}
	if identifier, ok := libpodVolumeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindVolume, identifier, opts, false)
	}
	if identifier, ok := libpodSecretIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSecret, identifier, opts, false)
	}
	return verdictPassThrough, "", nil
}

func checkEmbeddedOwnershipReferences(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	refs []embeddedOwnershipReference,
	opts Options,
) (ownershipVerdict, string, error) {
	strictest := verdictPassThrough
	for _, ref := range refs {
		labels, found, err := inspectResource(ctx, ref.kind, ref.identifier)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictDeny, fmt.Sprintf(
				"owner policy could not resolve %s %q referenced by %s",
				singularResource(ref.kind),
				ref.identifier,
				ref.source,
			), nil
		}

		allowUnowned := ref.kind == dockerresource.KindImage && opts.AllowUnownedImages
		if !ownerMatches(labels, opts.LabelKey, opts.Owner, allowUnowned) {
			return verdictDeny, fmt.Sprintf(
				"owner policy denied access to %s %q referenced by %s",
				singularResource(ref.kind),
				ref.identifier,
				ref.source,
			), nil
		}
		strictest = verdictAllow
	}
	return strictest, "", nil
}

func checkOwnedResource(ctx context.Context, inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error), kind dockerresource.Kind, identifier string, opts Options, allowUnowned bool) (ownershipVerdict, string, error) {
	labels, found, err := inspectResource(ctx, kind, identifier)
	if err != nil {
		return verdictPassThrough, "", err
	}
	if !found {
		return verdictPassThrough, "", nil
	}
	if ownerMatches(labels, opts.LabelKey, opts.Owner, allowUnowned) {
		return verdictAllow, "", nil
	}
	return verdictDeny, fmt.Sprintf("owner policy denied access to %s", singularResource(kind)), nil
}

// checkContainerNamespaceSharingRefs denies POST /containers/create when any
// namespace-sharing container: target belongs to a different owner than
// opts.Owner. allowUnowned is false for each check — same as every other
// container-targeting ownership check — so an unlabeled target is treated
// as a cross-owner risk rather than implicitly trusted. Returns the first
// cross-owner denial encountered; otherwise the strictest verdict across
// all refs (verdictAllow if at least one ref resolved to an owned
// container, verdictPassThrough if every ref resolved to nothing sockguard
// could inspect).
func checkContainerNamespaceSharingRefs(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	refs []string,
	opts Options,
) (ownershipVerdict, string, error) {
	strictest := verdictPassThrough
	for _, ref := range refs {
		verdict, _, err := checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, ref, opts, false)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if verdict == verdictDeny {
			return verdictDeny, fmt.Sprintf("owner policy denied access to namespace-sharing target container %q", ref), nil
		}
		if verdict == verdictAllow {
			strictest = verdictAllow
		}
	}
	return strictest, "", nil
}

func ownerMatches(labels map[string]string, labelKey, owner string, allowUnowned bool) bool {
	if labels == nil {
		return allowUnowned
	}
	value, ok := labels[labelKey]
	if !ok || value == "" {
		return allowUnowned
	}
	return value == owner
}

func singularResource(kind dockerresource.Kind) string {
	switch kind {
	case dockerresource.KindContainer:
		return "container"
	case dockerresource.KindImage:
		return "image"
	case dockerresource.KindNetwork:
		return "network"
	case dockerresource.KindVolume:
		return "volume"
	case dockerresource.KindService:
		return "service"
	case dockerresource.KindTask:
		return "task"
	case dockerresource.KindSecret:
		return "secret"
	case dockerresource.KindConfig:
		return "config"
	case dockerresource.KindNode:
		return "node"
	case dockerresource.KindSwarm:
		return "swarm"
	case dockerresource.KindLibpodPod:
		return "pod"
	default:
		return string(kind)
	}
}

func addOwnerLabelToBody(r *http.Request, labelKey, owner string) error {
	return mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		labels[labelKey] = owner
		return nil
	})
}

// addOwnerLabelToContainerCreateBody is retained for focused mutation tests.
// Production uses mutateContainerCreateOwnershipBody so the same decode also
// returns non-namespace Docker resource references for authorization.
func addOwnerLabelToContainerCreateBody(r *http.Request, labelKey, owner string) ([]string, error) {
	refs, err := mutateContainerCreateOwnershipBody(r, labelKey, owner)
	if refs == nil {
		return nil, err
	}
	return refs.namespaceContainers, err
}

func mutateContainerCreateOwnershipBody(r *http.Request, labelKey, owner string) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := filter.NestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		labels[labelKey] = owner
		refs.namespaceContainers = containerCreateNamespaceRefs(decoded)
		refs.embeddedResources = containerCreateEmbeddedOwnershipReferences(decoded)
		return nil
	})
	return refs, err
}

func containerCreateEmbeddedOwnershipReferences(decoded map[string]any) []embeddedOwnershipReference {
	var refs []embeddedOwnershipReference
	for _, image := range filter.FoldedStrings(decoded, "Image") {
		appendEmbeddedOwnershipReference(&refs, dockerresource.KindImage, image, "container Image")
	}

	for _, hostConfig := range filter.FoldedObjects(decoded, "HostConfig") {
		for _, binds := range filter.FoldedArrays(hostConfig, "Binds") {
			for _, value := range binds {
				bind, ok := value.(string)
				if !ok {
					continue
				}
				source, _, ok := strings.Cut(bind, ":")
				source = strings.TrimSpace(source)
				if !ok || source == "" || strings.HasPrefix(source, "/") {
					continue
				}
				appendEmbeddedOwnershipReference(&refs, dockerresource.KindVolume, source, "container HostConfig.Binds")
			}
		}

		for _, mounts := range filter.FoldedArrays(hostConfig, "Mounts") {
			for _, value := range mounts {
				mount, ok := value.(map[string]any)
				if !ok || !filter.FoldedStringEquals(mount, "Type", "volume") {
					continue
				}
				for _, source := range filter.FoldedStrings(mount, "Source") {
					appendEmbeddedOwnershipReference(&refs, dockerresource.KindVolume, source, "container HostConfig.Mounts")
				}
			}
		}

		for _, mode := range filter.FoldedStrings(hostConfig, "NetworkMode") {
			if !isCustomNetworkMode(mode) {
				continue
			}
			appendEmbeddedOwnershipReference(&refs, dockerresource.KindNetwork, mode, "container HostConfig.NetworkMode")
		}
	}

	for _, networkingConfig := range filter.FoldedObjects(decoded, "NetworkingConfig") {
		for _, endpoints := range filter.FoldedObjects(networkingConfig, "EndpointsConfig") {
			names := make([]string, 0, len(endpoints))
			for name := range endpoints {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				if isCustomNetworkMode(name) {
					appendEmbeddedOwnershipReference(&refs, dockerresource.KindNetwork, name, "container NetworkingConfig.EndpointsConfig")
				}
				endpoint, ok := endpoints[name].(map[string]any)
				if !ok {
					continue
				}
				for _, networkID := range filter.FoldedStrings(endpoint, "NetworkID") {
					appendEmbeddedOwnershipReference(&refs, dockerresource.KindNetwork, networkID, "container NetworkingConfig.EndpointsConfig.NetworkID")
				}
			}
		}
	}
	return refs
}

// namespaceModeFields are the HostConfig fields whose "container:<ref>" form
// joins another container's namespace. NetworkMode/PidMode/IpcMode/UTSMode all
// document the container: form; UsernsMode is included defensively (stock
// Docker's support there is unconfirmed, and matching a non-container: value
// never yields a ref, so a spurious entry costs nothing).
var namespaceModeFields = [...]string{"NetworkMode", "PidMode", "IpcMode", "UTSMode", "UsernsMode"}

// containerCreateNamespaceRefs extracts every distinct "container:<ref>"
// namespace-sharing target from a decoded /containers/create body's
// HostConfig.{NetworkMode,PidMode,IpcMode,UTSMode,UsernsMode} fields. Malformed or
// absent HostConfig, and non-string field values, are treated as "no refs"
// rather than an error — filter's container_create.go is the layer
// responsible for rejecting malformed bodies; ownership only needs to know
// which (if any) foreign containers a well-formed create would join.
//
// Key matching is case-INSENSITIVE and iterates every case-variant of
// HostConfig and each mode field, because Docker decodes these keys
// case-insensitively: an exact-case lookup would let a client smuggle the
// namespace join past the cross-owner check with a lowercase "hostconfig"/
// "networkmode" key that Docker still honors.
func containerCreateNamespaceRefs(decoded map[string]any) []string {
	hostConfigs := filter.FoldedObjects(decoded, "HostConfig")
	var refs []string

	for _, field := range namespaceModeFields {
		for _, hostConfig := range hostConfigs {
			for key, value := range hostConfig {
				if !strings.EqualFold(key, field) {
					continue
				}
				mode, ok := value.(string)
				if !ok {
					continue
				}
				ref, ok := filter.ContainerNamespaceRef(mode)
				if !ok || slices.Contains(refs, ref) {
					continue
				}
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

func appendEmbeddedOwnershipReference(refs *[]embeddedOwnershipReference, kind dockerresource.Kind, identifier, source string) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" || slices.ContainsFunc(*refs, func(ref embeddedOwnershipReference) bool {
		return ref.kind == kind && ref.identifier == identifier
	}) {
		return
	}
	*refs = append(*refs, embeddedOwnershipReference{kind: kind, identifier: identifier, source: source})
}

func isCustomNetworkMode(raw string) bool {
	mode := strings.TrimSpace(raw)
	if mode == "" {
		return false
	}
	if _, ok := filter.ContainerNamespaceRef(mode); ok {
		return false
	}
	if strings.HasPrefix(strings.ToLower(mode), "ns:") {
		return false
	}
	switch strings.ToLower(mode) {
	case "default", "bridge", "host", "none", "ingress", "docker_gwbridge":
		return false
	default:
		return true
	}
}

func addOwnerLabelToServiceBody(r *http.Request, labelKey, owner string) error {
	_, err := mutateServiceOwnershipBody(r, labelKey, owner)
	return err
}

func mutateServiceOwnershipBody(r *http.Request, labelKey, owner string) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		serviceLabels, err := filter.NestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		serviceLabels[labelKey] = owner

		containerLabels, err := filter.NestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels")
		if err != nil {
			return err
		}
		containerLabels[labelKey] = owner
		refs.embeddedResources = serviceEmbeddedOwnershipReferences(decoded)
		return nil
	})
	return refs, err
}

func serviceEmbeddedOwnershipReferences(decoded map[string]any) []embeddedOwnershipReference {
	var refs []embeddedOwnershipReference
	for _, taskTemplate := range filter.FoldedObjects(decoded, "TaskTemplate") {
		for _, containerSpec := range filter.FoldedObjects(taskTemplate, "ContainerSpec") {
			for _, image := range filter.FoldedStrings(containerSpec, "Image") {
				appendEmbeddedOwnershipReference(&refs, dockerresource.KindImage, image, "service TaskTemplate.ContainerSpec.Image")
			}

			for _, mounts := range filter.FoldedArrays(containerSpec, "Mounts") {
				for _, value := range mounts {
					mount, ok := value.(map[string]any)
					if !ok || !filter.FoldedStringEquals(mount, "Type", "volume") {
						continue
					}
					for _, source := range filter.FoldedStrings(mount, "Source") {
						appendEmbeddedOwnershipReference(&refs, dockerresource.KindVolume, source, "service TaskTemplate.ContainerSpec.Mounts")
					}
				}
			}

			appendServiceObjectReferences(&refs, containerSpec, "Secrets", "SecretID", "SecretName", dockerresource.KindSecret)
			appendServiceObjectReferences(&refs, containerSpec, "Configs", "ConfigID", "ConfigName", dockerresource.KindConfig)
		}
	}

	for _, networks := range filter.FoldedArrays(decoded, "Networks") {
		for _, value := range networks {
			network, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for _, target := range filter.FoldedStrings(network, "Target") {
				if isCustomNetworkMode(target) {
					appendEmbeddedOwnershipReference(&refs, dockerresource.KindNetwork, target, "service Networks.Target")
				}
			}
		}
	}
	return refs
}

func appendServiceObjectReferences(
	refs *[]embeddedOwnershipReference,
	containerSpec map[string]any,
	arrayKey, idKey, nameKey string,
	kind dockerresource.Kind,
) {
	for _, values := range filter.FoldedArrays(containerSpec, arrayKey) {
		for _, value := range values {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			identifiers := filter.FoldedStrings(object, idKey)
			if !slices.ContainsFunc(identifiers, func(identifier string) bool {
				return strings.TrimSpace(identifier) != ""
			}) {
				identifiers = filter.FoldedStrings(object, nameKey)
			}
			for _, identifier := range identifiers {
				appendEmbeddedOwnershipReference(refs, kind, identifier, "service TaskTemplate.ContainerSpec."+arrayKey)
			}
		}
	}
}

func addOwnerLabelToBuildQuery(r *http.Request, labelKey, owner string) error {
	query := r.URL.Query()
	labels := make(map[string]string)
	if encoded := query.Get("labels"); encoded != "" {
		if err := json.NewDecoder(strings.NewReader(encoded)).Decode(&labels); err != nil {
			return fmt.Errorf("decode build labels: %w", err)
		}
	}
	labels[labelKey] = owner
	encoded, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("encode build labels: %w", err)
	}
	query.Set("labels", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

func addOwnerLabelFilter(r *http.Request, labelKey, owner string) error {
	query := r.URL.Query()
	filters, err := dockerfilters.Decode(query.Get("filters"))
	if err != nil {
		return err
	}
	filterKey := ownerFilterKey(filter.NormalizePath(r.URL.Path))
	label := labelKey + "=" + owner

	filters[filterKey] = []string{label}
	encoded, err := json.Marshal(filters)
	if err != nil {
		return fmt.Errorf("encode filters: %w", err)
	}
	query.Set("filters", string(encoded))
	r.URL.RawQuery = query.Encode()
	return nil
}

func mutateJSONBody(r *http.Request, mutate func(map[string]any) error) error {
	if r.Body == nil {
		return fmt.Errorf("request body is required")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxOwnershipBodyBytes+1))
	if closeErr := r.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) > maxOwnershipBodyBytes {
		return fmt.Errorf("request body exceeds %d byte limit", maxOwnershipBodyBytes)
	}
	if len(body) == 0 {
		return fmt.Errorf("request body is required")
	}

	if err := filter.RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return fmt.Errorf("ambiguous request body: %w", err)
	}

	// UseNumber preserves JSON numbers as json.Number (underlying string)
	// instead of coercing them to float64. That matters because the default
	// map[string]any decode path silently truncates any Docker container
	// create field with a 53-bit-or-larger integer — memory limits, pid
	// caps, CPU shares — on the re-encode pass. json.Number round-trips
	// exact digits whether we touch the field or not.
	var decoded map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}

	if decoded == nil {
		return fmt.Errorf("decode request body: JSON null is not a valid object")
	}
	if err := mutate(decoded); err != nil {
		return err
	}

	encoded, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("encode request body: %w", err)
	}
	r.ContentLength = int64(len(encoded))
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	return nil
}

func (u upstreamInspector) inspectResource(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
	target, ok := dockerresource.InspectPath(kind, identifier)
	if !ok {
		return nil, false, fmt.Errorf("unsupported resource kind %q", kind)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build inspect %s request: %w", kind, err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("inspect %s %q: upstream returned %s", kind, identifier, resp.Status)
	}

	labels, err := dockerresource.DecodeLabels(resp.Body, kind)
	if err != nil {
		return nil, false, err
	}
	return labels, true, nil
}

func (u upstreamInspector) inspectExec(ctx context.Context, identifier string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil)
	if err != nil {
		return "", false, fmt.Errorf("build inspect exec request: %w", err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("inspect exec %q: upstream returned %s", identifier, resp.Status)
	}

	var body struct {
		ContainerID string `json:"ContainerID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", false, err
	}
	if body.ContainerID == "" {
		return "", false, fmt.Errorf("inspect exec %q: empty container id", identifier)
	}
	return body.ContainerID, true, nil
}
func needsOwnerFilter(normPath string) bool {
	switch normPath {
	case "/events", "/containers/json", "/containers/prune", "/images/json", "/images/prune", "/networks", "/networks/prune", "/volumes", "/volumes/prune", "/services", "/tasks", "/secrets", "/configs", "/nodes":
		return true
	default:
		return false
	}
}

func containerIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/containers/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/containers/"), "/")
	switch identifier {
	case "", "create", "json", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func execIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/exec/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/exec/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func networkIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/networks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/networks/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func volumeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/volumes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/volumes/"), "/")
	switch identifier {
	case "", "create", "prune":
		return "", false
	default:
		return identifier, true
	}
}

func imageIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/images/") {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, "/images/")
	switch rest {
	case "", "json", "create", "search", "get", "load", "prune":
		return "", false
	}

	for _, suffix := range []string{"/json", "/history", "/push", "/tag", "/get"} {
		if strings.HasSuffix(rest, suffix) {
			return strings.TrimSuffix(rest, suffix), true
		}
	}
	return rest, true
}

func serviceIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/services/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func isServiceUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/services/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/services/"), "/")
	return ok && identifier != "" && identifier != "create" && tail == "update"
}

func taskIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/tasks/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/tasks/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func secretIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/secrets/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/secrets/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func configIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/configs/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/configs/"), "/")
	switch identifier {
	case "", "create":
		return "", false
	default:
		return identifier, true
	}
}

func nodeIdentifier(normPath string) (string, bool) {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return "", false
	}
	identifier, _, _ := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	if identifier == "" {
		return "", false
	}
	return identifier, true
}

func isNodeUpdatePath(normPath string) bool {
	if !strings.HasPrefix(normPath, "/nodes/") {
		return false
	}
	identifier, tail, ok := strings.Cut(strings.TrimPrefix(normPath, "/nodes/"), "/")
	return ok && identifier != "" && tail == "update"
}

func isSwarmPath(normPath string) bool {
	return normPath == "/swarm"
}

func isSwarmUpdatePath(normPath string) bool {
	return normPath == "/swarm/update"
}

func ownerFilterKey(normPath string) string {
	if normPath == "/nodes" {
		return "node.label"
	}
	return "label"
}
