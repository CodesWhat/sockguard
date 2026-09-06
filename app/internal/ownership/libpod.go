package ownership

import (
	"net/http"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// libpod.go holds the owner-label mutation and cross-owner reference
// extraction for Podman's native /libpod/ create endpoints (#148 PR5,
// design doc C6). It intentionally mirrors, rather than reuses, the
// Docker-compat mutation helpers in middleware.go: libpod's SpecGenerator/
// PodSpecGenerator wire shapes use different field names, different key
// casing (lowercase "labels" for containers/pods/networks vs. capitalized
// "Labels" — a genuine SpecGenerator/PodSpecGenerator quirk verified against
// real captures — for volumes, whose entities.VolumeCreateOptions type
// carries no json tags at all), and a namespace-sharing object shape
// ({"nsmode":"container","value":"<ref>"}) instead of Docker's
// "container:<ref>" string form. Keeping these paths structurally separate
// from mutateContainerCreateOwnershipBody/mutateServiceOwnershipBody is the
// same fail-open guard the filter package's libpod inspectors already
// apply to body inspection (see libpod_container_create.go's doc comment).

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
// this check (mutateJSONBody's RejectDuplicateCaseVariantJSONValue pass
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
