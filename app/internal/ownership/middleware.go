package ownership

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/dockerfilters"
	"github.com/codeswhat/sockguard/internal/dockerresource"
	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/httpjson"
	"github.com/codeswhat/sockguard/internal/logging"
)

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
	// HostConfig.NetworkMode/PidMode/IpcMode/UsernsMode "container:<ref>"
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
	// Ownership decisions must observe current daemon state. Docker names and
	// image tags are mutable, so memoizing even a positive label result can
	// authorize a different resource after a delete/recreate or retag. Inspect
	// every request instead; per-request embedded references are deduplicated
	// before reaching this boundary.
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
				logger.ErrorContext(r.Context(), "owner policy lookup failed", "error", err, "method", r.Method, "path", r.URL.Path)
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
	case needsOwnerFilter(normPath):
		return nil, addOwnerLabelFilter(r, opts.LabelKey, opts.Owner)
	default:
		return nil, nil
	}
}

func allowOwnershipRequest(
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
	default:
		return string(kind)
	}
}

func addOwnerLabelToBody(r *http.Request, labelKey, owner string) error {
	return mutateJSONBody(r, func(decoded map[string]any) error {
		labels, err := nestedObject(decoded, "Labels")
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
		labels, err := nestedObject(decoded, "Labels")
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
	for _, image := range foldedStrings(decoded, "Image") {
		appendEmbeddedOwnershipReference(&refs, dockerresource.KindImage, image, "container Image")
	}

	for _, hostConfig := range foldedObjects(decoded, "HostConfig") {
		for _, binds := range foldedArrays(hostConfig, "Binds") {
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

		for _, mounts := range foldedArrays(hostConfig, "Mounts") {
			for _, value := range mounts {
				mount, ok := value.(map[string]any)
				if !ok || !foldedStringEquals(mount, "Type", "volume") {
					continue
				}
				for _, source := range foldedStrings(mount, "Source") {
					appendEmbeddedOwnershipReference(&refs, dockerresource.KindVolume, source, "container HostConfig.Mounts")
				}
			}
		}

		for _, mode := range foldedStrings(hostConfig, "NetworkMode") {
			if !isCustomNetworkMode(mode) {
				continue
			}
			appendEmbeddedOwnershipReference(&refs, dockerresource.KindNetwork, mode, "container HostConfig.NetworkMode")
		}
	}

	for _, networkingConfig := range foldedObjects(decoded, "NetworkingConfig") {
		for _, endpoints := range foldedObjects(networkingConfig, "EndpointsConfig") {
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
				for _, networkID := range foldedStrings(endpoint, "NetworkID") {
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
	hostConfigs := foldedObjects(decoded, "HostConfig")
	var refs []string
	// Iterate the mode fields in fixed order for deterministic ref ordering,
	// scanning every case-variant key inside each HostConfig so a duplicate
	// lowercase mode key cannot smuggle an unchecked ref past the loop.
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

// foldedObjects returns every object value in m whose key case-folds to key,
// in map-iteration order. Docker decodes duplicate case-variant keys and lets
// the last win, so a security check must inspect all variants rather than an
// exact-case single lookup.
func foldedObjects(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if obj, ok := v.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

func foldedStrings(m map[string]any, key string) []string {
	var out []string
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if value, ok := v.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func foldedArrays(m map[string]any, key string) [][]any {
	var out [][]any
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		if values, ok := v.([]any); ok {
			out = append(out, values)
		}
	}
	return out
}

func foldedStringEquals(m map[string]any, key, want string) bool {
	for _, value := range foldedStrings(m, key) {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
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
		serviceLabels, err := nestedObject(decoded, "Labels")
		if err != nil {
			return err
		}
		serviceLabels[labelKey] = owner

		containerLabels, err := nestedObjectPath(decoded, "TaskTemplate", "ContainerSpec", "Labels")
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
	for _, taskTemplate := range foldedObjects(decoded, "TaskTemplate") {
		for _, containerSpec := range foldedObjects(taskTemplate, "ContainerSpec") {
			for _, image := range foldedStrings(containerSpec, "Image") {
				appendEmbeddedOwnershipReference(&refs, dockerresource.KindImage, image, "service TaskTemplate.ContainerSpec.Image")
			}

			for _, mounts := range foldedArrays(containerSpec, "Mounts") {
				for _, value := range mounts {
					mount, ok := value.(map[string]any)
					if !ok || !foldedStringEquals(mount, "Type", "volume") {
						continue
					}
					for _, source := range foldedStrings(mount, "Source") {
						appendEmbeddedOwnershipReference(&refs, dockerresource.KindVolume, source, "service TaskTemplate.ContainerSpec.Mounts")
					}
				}
			}

			appendServiceObjectReferences(&refs, containerSpec, "Secrets", "SecretID", "SecretName", dockerresource.KindSecret)
			appendServiceObjectReferences(&refs, containerSpec, "Configs", "ConfigID", "ConfigName", dockerresource.KindConfig)
		}
	}

	for _, networks := range foldedArrays(decoded, "Networks") {
		for _, value := range networks {
			network, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for _, target := range foldedStrings(network, "Target") {
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
	for _, values := range foldedArrays(containerSpec, arrayKey) {
		for _, value := range values {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			identifiers := foldedStrings(object, idKey)
			if !slices.ContainsFunc(identifiers, func(identifier string) bool {
				return strings.TrimSpace(identifier) != ""
			}) {
				identifiers = foldedStrings(object, nameKey)
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
	// Unconditional replacement ensures a client-supplied owner label cannot
	// coexist with the proxy-enforced label, preventing OR-semantics bypass.
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
	// Read one byte past the limit so we can distinguish at-limit from
	// over-limit without giving the client room to OOM the proxy.
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
	// Owner-label stamping re-marshals the whole body through a map, and
	// json.Marshal re-sorts the keys — so a duplicate case-variant key (e.g.
	// "hostconfig" beside the filter-inspected "HostConfig") could be reordered
	// into the last position the daemon honors, smuggling a value the filter
	// already cleared past its check. Reject such a body fail-closed before we
	// touch it. See filter.RejectDuplicateCaseVariantJSONKeys.
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
	// json.Decode into map[string]any does not error on a JSON null literal —
	// it simply leaves the map as nil. Reject it explicitly: a null body is
	// not a valid Docker API payload, and passing nil to the mutate callback
	// would panic when it tries to write into the map.
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

// nestedObject returns the object stored under key, creating it when absent.
// Key matching is case-INSENSITIVE and collision-collapsing. Docker decodes
// JSON object keys case-insensitively and, on duplicate case-variant keys,
// lets the last one win. A client could otherwise smuggle a lowercase
// "labels" alongside the proxy-injected "Labels" and — because json.Marshal
// emits map keys in sorted order, placing "labels" after "Labels" — have
// Docker prefer the client's forged owner label. To close that spoof, every
// key that case-folds to key is merged into a single object stored under the
// exact canonical key, and all variant keys are removed, so the re-encoded
// body carries exactly one unambiguous key that Docker reads verbatim.
func nestedObject(decoded map[string]any, key string) (map[string]any, error) {
	merged := map[string]any{}
	var variants []string
	for k, v := range decoded {
		if !strings.EqualFold(k, key) {
			continue
		}
		variants = append(variants, k)
		if v == nil {
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", key)
		}
		for kk, vv := range obj {
			merged[kk] = vv
		}
	}
	for _, k := range variants {
		delete(decoded, k)
	}
	decoded[key] = merged
	return merged, nil
}

func nestedObjectPath(decoded map[string]any, keys ...string) (map[string]any, error) {
	current := decoded
	for _, key := range keys {
		next, err := nestedObject(current, key)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
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
