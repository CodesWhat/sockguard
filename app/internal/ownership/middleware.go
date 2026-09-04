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

	"github.com/codeswhat/sockguard/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const DefaultLabelKey = "com.sockguard.owner"

const (
	reasonCodeOwnerRequestInvalid                    = "owner_request_invalid"
	reasonCodeOwnerPolicyLookupFailed                = "owner_policy_lookup_failed"
	reasonCodeOwnerPolicyDeniedAccess                = "owner_policy_denied_access"
	reasonCodeOwnerVisibilityPodmanEventsUnscopeable = "owner_visibility_podman_events_unscopeable"
	reasonCodeOwnerPodmanSecretList                  = "owner_podman_secret_list_unscopeable" //nolint:gosec // reason code, not a credential
)

const ownerVisibilityPodmanEventsDenyReason = "events denied: this upstream is Podman, whose GET /events filters labels disjunctively, so owner isolation and visibility label selectors cannot be enforced together"

// maxOwnershipBodyBytes caps the request body the ownership middleware will
// read when it mutates a create body, extracts network-membership references,
// or injects an owner label into a build query. Docker's own payloads are at most
// a few KiB, so 1 MiB is generous while preventing an allowlisted client
// from OOMing the proxy with an unbounded JSON body.
const maxOwnershipBodyBytes = 1 << 20 // 1 MiB

// ownershipVerdict is the outcome of an ownership policy check against an
// inbound request. Callers should forward `verdictPassThrough` and
// `verdictAllow` unchanged to the next handler; the two denial verdicts should
// short circuit with the status their denialStatus reports and the
// accompanying reason.
type ownershipVerdict int

const (
	// verdictPassThrough means the request does not target a resource that
	// the ownership middleware knows how to inspect, so it is forwarded
	// unchanged to the next handler.
	verdictPassThrough ownershipVerdict = iota
	// verdictAllow means the request targets a labeled resource that matches
	// the configured owner.
	verdictAllow
	// verdictDeny means the request targets a resource that exists and whose
	// labels do not satisfy the active owner policy, or names a reference
	// ownership refuses to authorize at all.
	verdictDeny
	// verdictDenyMissing means the request targets a resource the daemon
	// could not resolve. It is as fail-closed as verdictDeny — nothing is
	// forwarded in enforce mode — and differs only in the status the client
	// sees. See denialStatus.
	verdictDenyMissing
)

// denied reports whether the verdict refuses the request. Both denial
// verdicts fail closed identically; a caller that needs the difference asks
// denialStatus for it rather than comparing against one constant, which is
// how a missing target could otherwise leak past a `!= verdictDeny` test.
func (v ownershipVerdict) denied() bool {
	return v == verdictDeny || v == verdictDenyMissing
}

// denialStatus is the HTTP status a denial answers with in enforce mode.
//
// A target the daemon could not resolve answers 404, not 403, for two
// reasons. It matches what the visibility layer already returns for a
// resource its policy hides (see handleVisibilityInspectRequest), so a
// deployment running both layers reports one status for "you cannot have
// this" rather than two. And it is the status an idempotent client expects:
// compose teardown, Ryuk and terraform all DELETE resources that may already
// be gone, and a 403 there turns a converged run into an error.
//
// A resolved resource with a foreign owner keeps 403: the request named
// something real that policy refuses.
func (v ownershipVerdict) denialStatus() int {
	if v == verdictDenyMissing {
		return http.StatusNotFound
	}
	return http.StatusForbidden
}

type embeddedOwnershipReference struct {
	kind       dockerresource.Kind
	identifier string
	source     string
}

type ownershipRequestReferences struct {
	namespaceContainers []string
	embeddedResources   []embeddedOwnershipReference
	imageBatch          *imageBatchOwnershipReferences
	// denyReason, when set, is a refusal the request-shape inspection
	// reached on its own, before any inspect. It exists because some
	// requests name their resource in the query string rather than the
	// path, so the decision needs the *http.Request the mutation pass
	// already holds, while the refusal still has to travel the ordinary
	// verdict path — a 403 an operator can stage through warn mode and read
	// in the access log under reasonCodeOwnerPolicyDeniedAccess, not the
	// unconditional 400 a mutation error produces.
	denyReason string
}

// Options configures per-proxy resource ownership labeling and enforcement.
type Options struct {
	Owner              string
	LabelKey           string
	AllowUnownedImages bool
	// AllowCrossOwnerNamespaceSharing restores the pre-v1.5 pass-through
	// behavior for POST /containers/create: by default (false), every
	// HostConfig.NetworkMode/PidMode/IpcMode/UTSMode/UsernsMode "container:<ref>"
	// namespace-sharing target is looked up and the request is denied if the
	// referenced container is missing or does not belong to the configured
	// owner. Set true to restore the old unchecked behavior.
	AllowCrossOwnerNamespaceSharing bool
	// UpstreamFlavor is the engine behind the upstream socket, resolved at
	// startup from upstream.flavor (see internal/upstreamflavor). It changes
	// exactly one thing here: whether the Docker-compat GET /secrets is
	// refused, because on Podman that path is compat.ListSecrets, whose
	// filter grammar rejects the owner label this layer injects into every
	// other list. See filter.PodmanCompatSecretListDenyReason.
	//
	// Podman's other divergence, the disjunctive GET /events filter, needs no
	// flavor here: addOwnerLabelFilter replaces the key with exactly one
	// value, and one value evaluates the same under either rule. Only the
	// combination with a visibility selector is inexpressible, and that
	// arrives on the request as dockerfilters.RequiresSoleValue rather than
	// as a flavor.
	//
	// The zero value means Docker, so a chain builder that drops the field
	// leaves the compat /secrets 500 in place with every unit test green;
	// TestServeChainPassesResolvedFlavorToOwnership is the wiring proof.
	UpstreamFlavor upstreamflavor.Flavor
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

	// Hoisted out of the request closure for the reason the visibility
	// middleware hoists its own copy: upstream.flavor is reload-immutable and
	// the chain is rebuilt on reload anyway, so the request path compares a
	// bool rather than a string.
	podmanUpstream := opts.UpstreamFlavor == upstreamflavor.Podman

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

			// Refuse host-wide libpod reads before ordinary resource-path
			// classification. Two collection words ("showmounted" and
			// "stats") are otherwise indistinguishable here from container
			// names, which would trigger an inspect and let a foreign-resource
			// denial pass through under warn/audit rollout before the
			// unconditional collection refusal got a chance to run.
			//
			// HEAD is refused alongside GET for the reason
			// serveOwnershipAllowed gives for the two disk-usage reads:
			// nothing here has a body-filtering step HEAD could legitimately
			// need, so gating on GET alone would forward it to the daemon.
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				if read, ok := filter.LookupLibpodUnscopeableRead(normPath); ok {
					denyUnscopeableLibpodRead(w, r, read)
					return
				}
				// The Docker-compat secret list is the same refusal on a
				// Podman upstream, gated on the flavor because "/secrets"
				// exists on both engines and only Podman serves it from
				// compat.ListSecrets. needsOwnerFilter has it, so without
				// this the owner label reaches a filter grammar that accepts
				// only name and id and every request answers 500. See
				// filter.PodmanCompatSecretListDenyReason.
				if podmanUpstream && normPath == filter.PodmanCompatSecretListPath {
					denyPodmanCompatSecretList(w, r)
					return
				}
			}

			// Refuse the libpod writes owner isolation cannot scope, for the
			// reason filter.LibpodPodPruneDenyReason gives: the endpoint
			// takes no filters and names no resource, so forwarding it
			// deletes other owners' resources. Like the read refusals above
			// it is unconditional — a warn-mode measurement is worth nothing
			// once the pods are gone.
			if write, ok := filter.LookupLibpodUnscopeableWrite(r.Method, normPath); ok {
				denyUnscopeableLibpodWrite(w, r, write)
				return
			}

			ownerFilterApplies := needsOwnerFilter(r.Method, normPath) || libpodNeedsOwnerFilter(r.Method, normPath)
			if ownerFilterApplies && dockerfilters.RequiresSoleValue(r, ownerFilterKey(normPath)) {
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerVisibilityPodmanEventsUnscopeable, ownerVisibilityPodmanEventsDenyReason, nil)
				_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: ownerVisibilityPodmanEventsDenyReason})
				return
			}

			refs, err := mutateOwnershipRequest(r, normPath, opts)
			if err != nil {
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerRequestInvalid, err.Error(), nil)
				_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
				return
			}

			// The SCP route view is filter.NormalizePodmanRoutePath, not
			// filter.NormalizePath. Podman's router matches on the escaped
			// path INCLUDING a trailing slash, and that slash decides the
			// route: /libpod/images/scp/victim/push/ misses the anchored
			// per-image /push handler registered earlier and falls through to
			// the /libpod/images/scp/{name:.*} catch-all, so the daemon SCPs
			// the local image "victim/push/". NormalizePath's path.Clean drops
			// the slash, which read the same request as a push of an image
			// named "scp/victim", a name no daemon has, so the inspect came
			// back not-found and ownership passed the transfer through.
			routePath := normPath
			if r.Method == http.MethodPost && strings.HasPrefix(normPath, libpodPrefix+"images/scp/") {
				routePath = filter.NormalizePodmanRoutePath(r.URL.EscapedPath())
			}
			verdict, reason, err := allowOwnershipRequestWithRoutePath(r.Context(), r.Method, normPath, routePath, opts, inspectResource, inspectExec, refs)
			if err != nil {
				logger.ErrorContext(r.Context(), "owner policy lookup failed", "error", logging.SafeString(err.Error()), "method", logging.SafeString(r.Method), "path", logging.SafeString(r.URL.Path))
				logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyLookupFailed, "owner policy lookup failed", nil)
				_ = httpjson.Write(w, http.StatusBadGateway, httpjson.ErrorResponse{Message: "owner policy lookup failed"})
				return
			}
			if !verdict.denied() {
				serveOwnershipAllowed(logger, next, w, r, normPath, opts)
				return
			}

			meta := logging.MetaForRequest(w, r)
			if meta.AllowsPassThrough() {
				logging.SetWouldDenyWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
				next.ServeHTTP(w, r)
				return
			}
			logging.SetDeniedWithCode(w, r, reasonCodeOwnerPolicyDeniedAccess, reason, nil)
			_ = httpjson.Write(w, verdict.denialStatus(), httpjson.ErrorResponse{Message: reason})
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
// identifier embedded in container/service create or update and network
// membership bodies during the same bounded decode pass. Authorization must
// cover those identifiers as well as the resource named by the URL; otherwise
// a permitted request could still consume or modify another owner's resource.
func mutateOwnershipRequest(r *http.Request, normPath string, opts Options) (*ownershipRequestReferences, error) {
	switch {
	case isImageBatchOwnershipPath(r.Method, normPath):
		batch, err := parseImageBatchOwnershipReferences(r, normPath)
		if err != nil {
			return nil, err
		}
		return &ownershipRequestReferences{imageBatch: batch}, nil
	case r.Method == http.MethodPost && normPath == "/containers/create":
		return mutateContainerCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && isNetworkMembershipChangePath(normPath):
		return extractNetworkMembershipOwnershipReferences(r)
	case r.Method == http.MethodPost && (normPath == "/networks/create" || normPath == "/volumes/create" || normPath == "/secrets/create" || normPath == "/configs/create"):
		return nil, addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && (normPath == "/services/create" || isServiceUpdatePath(normPath)):
		return mutateServiceOwnershipBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && (isNodeUpdatePath(normPath) || isSwarmUpdatePath(normPath)):
		return nil, addOwnerLabelToBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && isCommitPath(normPath):
		return mutateCommitOwnershipRequest(r, opts)
	case r.Method == http.MethodPost && (normPath == "/build" || normPath == libpodPrefix+"build"):
		return nil, addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && normPath == libpodContainerCreatePath:
		return mutateLibpodContainerCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && normPath == libpodPodCreatePath:
		return mutateLibpodPodCreateOwnershipBody(r, opts.LabelKey, opts.Owner)
	case r.Method == http.MethodPost && normPath == libpodNetworkCreatePath:
		return nil, addOwnerLabelToLibpodBody(r, opts.LabelKey, opts.Owner, "labels")
	case r.Method == http.MethodPost && normPath == libpodVolumeCreatePath:
		return nil, addOwnerLabelToLibpodBody(r, opts.LabelKey, opts.Owner, "Labels")
	case r.Method == http.MethodPost && normPath == libpodSecretCreatePath:
		// libpod secret create has no JSON body envelope at all — the body is
		// the raw secret payload, and driver/labels are URL query parameters
		// (see internal/filter/libpod_secret.go's doc comment). The existing
		// build-query mutator already does exactly this "decode 'labels' query
		// param as a JSON-encoded map, inject, re-encode" shape.
		return nil, addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner)
	case needsOwnerFilter(r.Method, normPath), libpodNeedsOwnerFilter(r.Method, normPath):
		return nil, addOwnerLabelFilter(r, opts.LabelKey, opts.Owner)
	default:
		return nil, nil
	}
}

func extractNetworkMembershipOwnershipReferences(r *http.Request) (*ownershipRequestReferences, error) {
	refs := &ownershipRequestReferences{}
	err := mutateJSONBody(r, func(decoded map[string]any) error {
		for _, identifier := range filter.FoldedStrings(decoded, "Container") {
			appendEmbeddedOwnershipReference(&refs.embeddedResources, dockerresource.KindContainer, identifier, "network membership Container")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// allowOwnershipRequest is allowOwnershipRequestUnprefixed with the "libpod "
// deny-reason prefix convention (#148 design doc item 5, matching the
// human-readable-reason style internal/filter's libpod_*.go inspectors
// already use) applied once, for every libpod-family request path, rather
// than threading the prefix decision through each individual check
// function.
func allowOwnershipRequest(
	ctx context.Context,
	method string,
	normPath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
	refs *ownershipRequestReferences,
) (ownershipVerdict, string, error) {
	return allowOwnershipRequestWithRoutePath(ctx, method, normPath, normPath, opts, inspectResource, inspectExec, refs)
}

func allowOwnershipRequestWithRoutePath(
	ctx context.Context,
	method string,
	normPath string,
	routePath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
	refs *ownershipRequestReferences,
) (ownershipVerdict, string, error) {
	verdict, reason, err := allowOwnershipRequestUnprefixed(ctx, method, normPath, routePath, opts, inspectResource, inspectExec, refs)
	if verdict.denied() && isLibpodOwnershipPath(normPath) {
		reason = "libpod " + reason
	}
	return verdict, reason, err
}

func allowOwnershipRequestUnprefixed(
	ctx context.Context,
	method string,
	normPath string,
	routePath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
	refs *ownershipRequestReferences,
) (ownershipVerdict, string, error) {
	strictest := verdictPassThrough
	if refs != nil {
		if refs.denyReason != "" {
			return verdictDeny, refs.denyReason, nil
		}
		verdict, reason, err := checkImageBatchOwnershipReferences(ctx, inspectResource, refs.imageBatch, opts)
		if err != nil || verdict.denied() {
			return verdict, reason, err
		}
		if verdict == verdictAllow {
			strictest = verdictAllow
		}

		if !opts.AllowCrossOwnerNamespaceSharing && len(refs.namespaceContainers) > 0 {
			verdict, reason, err := checkContainerNamespaceSharingRefs(ctx, inspectResource, refs.namespaceContainers, opts)
			if err != nil || verdict.denied() {
				return verdict, reason, err
			}
			if verdict == verdictAllow {
				strictest = verdictAllow
			}
		}

		verdict, reason, err = checkEmbeddedOwnershipReferences(ctx, inspectResource, refs.embeddedResources, opts)
		if err != nil || verdict.denied() {
			return verdict, reason, err
		}
		if verdict == verdictAllow {
			strictest = verdictAllow
		}
	}

	verdict, reason, err := allowPathOwnershipRequest(ctx, method, normPath, routePath, opts, inspectResource, inspectExec)
	if err != nil || verdict.denied() {
		return verdict, reason, err
	}
	if verdict == verdictAllow || strictest == verdictAllow {
		return verdictAllow, "", nil
	}
	return verdictPassThrough, "", nil
}

func allowPathOwnershipRequest(
	ctx context.Context,
	method string,
	normPath string,
	routePath string,
	opts Options,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	inspectExec func(context.Context, string) (string, bool, error),
) (ownershipVerdict, string, error) {
	if reason, deny := imageEffectDenial(method, normPath); deny {
		return verdictDeny, reason, nil
	}
	if identifier, ok := containerIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, identifier, opts, false)
	}
	if execID, ok := execIdentifier(normPath); ok {
		containerID, found, err := inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictDenyMissing, "owner policy could not resolve exec session", nil
		}
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, containerID, opts, false)
	}
	if identifier, ok := networkIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNetwork, identifier, opts, false)
	}
	if identifier, ok := volumeIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindVolume, identifier, opts, false)
	}
	if identifier, ok := imageIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	}
	if identifier, ok := serviceIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindService, identifier, opts, false)
	}
	if identifier, ok := taskIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindTask, identifier, opts, false)
	}
	if identifier, ok := secretIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSecret, identifier, opts, false)
	}
	if identifier, ok := configIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindConfig, identifier, opts, false)
	}
	if identifier, ok := nodeIdentifier(normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNode, identifier, opts, isNodeUpdatePath(normPath))
	}
	if isSwarmPath(normPath) || isSwarmUpdatePath(normPath) {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindSwarm, "", opts, isSwarmUpdatePath(normPath))
	}
	// libpod route family (#148 PR5): mirrors the Docker-compat dispatch
	// above resource-for-resource so a client cannot evade ownership
	// enforcement by switching from the Docker-compat API to Podman's
	// native one for actions on an already-existing resource. Containers,
	// networks, volumes, images and secrets are checked against their
	// Docker-compat inspect path (dockerresource.KindContainer/KindNetwork/
	// KindVolume/KindImage/KindSecret) since Podman's compat API is a
	// translation layer over the same underlying resource store for those
	// kinds; pods have no Docker-compat equivalent and use
	// dockerresource.KindLibpodPod.
	if identifier, ok := libpodContainerIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, identifier, opts, false)
	}
	if execID, ok := libpodExecIdentifier(normPath); ok {
		containerID, found, err := inspectExec(ctx, execID)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if !found {
			return verdictDenyMissing, "owner policy could not resolve exec session", nil
		}
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindContainer, containerID, opts, false)
	}
	if identifier, ok := libpodPodIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindLibpodPod, identifier, opts, false)
	}
	if identifier, ok := libpodNetworkIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindNetwork, identifier, opts, false)
	}
	if identifier, ok := libpodVolumeIdentifier(method, normPath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindVolume, identifier, opts, false)
	}
	if identifier, remote, ok := libpodImageScpSource(method, routePath); ok {
		switch {
		case remote:
			return verdictDeny, "owner policy denied access to remote image source", nil
		case identifier == "":
			// 403, not the 404 an unresolvable target gets: nothing was
			// looked up. The source is malformed, so there is no image name
			// to ask the daemon about, and "could not resolve" is reserved
			// for a lookup that ran and came back empty.
			return verdictDeny, "owner policy denied access to malformed local image source", nil
		default:
			return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
		}
	}
	if identifier, ok := libpodImageIdentifierForRoute(method, normPath, routePath); ok {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	}
	if identifier, ok := libpodSecretIdentifier(method, normPath); ok {
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
			return verdictDenyMissing, fmt.Sprintf(
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

// checkOwnedResource authorizes one resource named by the request.
//
// The two failures it can report are deliberately different verdicts, not one
// denial with two wordings. A resource the daemon could not resolve is
// verdictDenyMissing ("could not resolve"), which enforce mode answers with a
// 404; a resolved resource whose labels do not satisfy the policy is
// verdictDeny ("denied access to"), which stays a 403. Both fail closed: the
// requested upstream path is never contacted either way. See denialStatus.
func checkOwnedResource(ctx context.Context, inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error), kind dockerresource.Kind, identifier string, opts Options, allowUnowned bool) (ownershipVerdict, string, error) {
	labels, found, err := inspectResource(ctx, kind, identifier)
	if err != nil {
		return verdictPassThrough, "", err
	}
	if !found {
		return verdictDenyMissing, fmt.Sprintf("owner policy could not resolve %s", singularResource(kind)), nil
	}
	if ownerMatches(labels, opts.LabelKey, opts.Owner, allowUnowned) {
		return verdictAllow, "", nil
	}
	return verdictDeny, fmt.Sprintf("owner policy denied access to %s", singularResource(kind)), nil
}

// checkContainerNamespaceSharingRefs denies POST /containers/create when any
// namespace-sharing container: target is missing or does not belong to
// opts.Owner. allowUnowned is false for each check — same as every other
// container-targeting ownership check — so an unlabeled target is treated
// as a cross-owner risk rather than implicitly trusted. Returns the first
// denial encountered; otherwise verdictAllow when at least one target was
// checked, or verdictPassThrough when there are no targets.
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
		switch verdict {
		case verdictDenyMissing:
			return verdictDenyMissing, fmt.Sprintf("owner policy could not resolve namespace-sharing target container %q", ref), nil
		case verdictDeny:
			return verdictDeny, fmt.Sprintf("owner policy denied access to namespace-sharing target container %q", ref), nil
		case verdictAllow:
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
	// Client-supplied values under this key are dropped: Swarm's control-plane
	// lists fold `label` into a map[string]string over a randomly-ordered
	// Args.Get, so a client value repeating the owner key can displace the
	// proxy-enforced one.
	//
	// Selectors sockguard itself injected earlier in the chain survive that
	// drop. The visibility middleware runs first and writes the same key, and
	// replacing its selectors left the request owner-scoped but not
	// visibility-scoped. Both sets go upstream together, and both engines AND
	// the values under `label` — see internal/dockerfilters/injected.go for the
	// daemon-side matchers that make that true.
	injected := dockerfilters.InjectedSelectors(r, filterKey)
	values := make([]string, 0, len(injected)+1)
	values = append(values, label)
	for _, selector := range injected {
		if !slices.Contains(values, selector) {
			values = append(values, selector)
		}
	}
	filters[filterKey] = values
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

func (u upstreamInspector) inspectResource(ctx context.Context, kind dockerresource.Kind, identifier string) (map[string]string, bool, error) {
	target, ok := dockerresource.InspectPath(kind, identifier)
	if !ok {
		return nil, false, fmt.Errorf("unsupported resource kind %q", kind)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil) // #nosec G704 -- InspectPath accepts only a validated engine resource identifier.
	if err != nil {
		return nil, false, fmt.Errorf("build inspect %s request: %w", kind, err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+url.PathEscape(identifier)+"/json", nil) // #nosec G704 -- the fixed local-engine URL contains only a path-escaped identifier.
	if err != nil {
		return "", false, fmt.Errorf("build inspect exec request: %w", err)
	}
	resp, err := u.client.Do(req) // #nosec G704 -- the inspector client targets the local container-engine socket, not the URL host.
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
