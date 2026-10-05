package ownership

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

const (
	// libpodCreateMaxReferences bounds the resources one create is checked
	// for. Each costs an inspect, and the body is the client's to fill. It is
	// the bound a build's names already have.
	libpodCreateMaxReferences = buildMaxTags

	libpodCreateDenyUnreadable      = "owner policy denied %s with a %s reference it can't look up"
	libpodCreateDenyTooMany         = "owner policy denied %s that names more resources than it can authorize"
	libpodCreateDenyImageVolumeName = "owner policy denied %s with an image volume that doesn't name its image by full ID, which Podman looks up again at every start"
	libpodCreateDenyArtifactVolume  = "owner policy denied %s with an artifact volume: an artifact carries no owner label to check"
)

// libpodCreateReferences is what a libpod container or pod create names in its
// body besides the image, the pod and the namespace targets the two mutators
// in libpod.go collect: other containers, networks and named volumes, and the
// images it mounts as volumes. Every one of resources has to resolve to
// something carrying the caller's owner label. denyReason is set instead when
// the body names something no lookup at create can answer for, and the create
// is refused before anything is looked up.
//
// It is its own field of ownershipRequestReferences, with its own refusal,
// so that nothing else reading the same body can overwrite it.
type libpodCreateReferences struct {
	denyReason string
	resources  []embeddedOwnershipReference
}

// libpodContainerCreateReferences reads the references of a
// POST /libpod/containers/create body, a SpecGenerator. Read from Podman
// 5.8.6 pkg/specgen/specgen.go and volumes.go, and from where MakeContainer
// resolves each field: pkg/specgen/generate/container_create.go, storage.go
// and namespaces.go, and libpod/runtime_ctr.go.
//
//   - `volumes_from` lists containers, each as "<container>[:<options>]".
//     Podman copies that container's mounts and named volumes into the new
//     one (storage.go getVolumesFrom).
//   - `dependencyContainers` lists containers the new one won't start
//     without. Starting the new one through the API starts them first
//     (container_create.go:693, pkg/api/handlers/compat/containers_start.go:39).
//   - `Networks` is a map keyed by network name or ID, and `cni_networks` is
//     the list Podman reads when that map is empty (namespaces.go:363-372).
//   - `volumes` lists named volumes. See namedVolumes.
//   - `image_volumes` lists images to mount. See imageVolumes.
//   - `artifact_volumes` lists artifacts to mount. See artifactVolumes.
//
// The rest of the SpecGenerator isn't read here:
//
//   - `rootfs`, `overlay_volumes`, `mounts`, `devices`, `init_path`,
//     `base_hosts_file`, `seccomp_profile_path`, `conmon_pid_file`,
//     `cgroup_parent`, `oci_runtime` and a namespace with nsmode "path" all
//     name something on the daemon host. That has no owner label to check,
//     so it's a question for the request-body inspector (internal/filter),
//     not for owner isolation.
//   - `network_options` is keyed by network mode ("slirp4netns", "pasta"),
//     not by network. `init_container_type` is "always" or "once", and acts
//     on the pod `pod` names, which is checked.
//   - `raw_image_name` is recorded on the container and never looked up.
//   - `devices_from` is decoded and never read by Podman 5.8.6.
//   - `secrets` and `secret_env` name secrets, which this doesn't cover.
//
// The body is decoded with encoding/json, which matches a key to a field in
// any letter case, so every key is folded here: the top-level ones, and
// `Name` and `Source` inside a volume, which carry no JSON tag at all.
// mutateJSONBody has already refused a body that spells one key two ways,
// and it forwards the body it decoded, re-encoded, so a key given twice
// reaches Podman once, with the value read here.
func libpodContainerCreateReferences(decoded map[string]any) *libpodCreateReferences {
	reader := libpodCreateReferenceReader{create: "container create"}
	reader.containerList(decoded, "volumes_from", libpodVolumesFromContainer)
	reader.containerList(decoded, "dependencyContainers", nil)
	reader.shared(decoded)
	reader.artifactVolumes(decoded, "artifact_volumes")
	return reader.references()
}

// libpodPodCreateReferences reads the references of a POST /libpod/pods/create
// body, a PodSpecGenerator.
//
// Podman's handler marshals the PodSpecGenerator it decoded and unmarshals
// that into the infra container's SpecGenerator, then creates the infra
// container with MakeContainer. So the pod's `volumes_from`, `Networks`,
// `cni_networks`, `volumes` and `image_volumes` become the infra container's,
// and are resolved exactly as a container create's are. A key
// PodSpecGenerator has no field for is dropped on the way:
// `dependencyContainers` and `artifact_volumes` never reach the infra
// container. Read from Podman 5.8.6 pkg/api/handlers/libpod/pods.go:37-74,
// pkg/specgen/podspecgen.go and pkg/specgen/generate/pod_create.go.
//
// `serviceContainerID` is the pod's own reference. Podman resolves it with
// LookupContainer, records the pod on that container, and restarts the
// container whenever the pod starts, whatever kind of container it is
// (libpod/options.go:2162-2180, libpod/service.go:211-233).
func libpodPodCreateReferences(decoded map[string]any) *libpodCreateReferences {
	reader := libpodCreateReferenceReader{create: "pod create"}
	reader.containerList(decoded, "volumes_from", libpodVolumesFromContainer)
	reader.container(decoded, "serviceContainerID")
	reader.shared(decoded)
	return reader.references()
}

// checkLibpodCreateReferences authorizes what a libpod create names. Each
// reference goes through checkEmbeddedOwnershipReferences, so the answers are
// the Docker-compatible create's: one the daemon can't resolve is a 404, one
// that resolves without the caller's owner label is a 403, and a failed lookup
// fails closed.
func checkLibpodCreateReferences(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	refs *libpodCreateReferences,
	opts Options,
) (ownershipVerdict, string, error) {
	if refs == nil {
		return verdictPassThrough, "", nil
	}
	if refs.denyReason != "" {
		return verdictDeny, refs.denyReason, nil
	}
	return checkEmbeddedOwnershipReferences(ctx, inspectResource, refs.resources, opts)
}

// libpodCreateReferenceReader collects the references of one create body.
// create names the request in a reason: "container create" or "pod create".
type libpodCreateReferenceReader struct {
	create string
	refs   libpodCreateReferences
}

func (r *libpodCreateReferenceReader) references() *libpodCreateReferences {
	if r.refs.denyReason == "" && len(r.refs.resources) == 0 {
		return nil
	}
	return &r.refs
}

// shared reads the fields a container create and a pod create both have.
func (r *libpodCreateReferenceReader) shared(decoded map[string]any) {
	r.networkMap(decoded, "Networks")
	r.networkList(decoded, "cni_networks")
	r.namedVolumes(decoded, "volumes")
	r.imageVolumes(decoded, "image_volumes")
}

// unreadable refuses the create for a field whose value isn't the shape
// Podman decodes, or that names a resource with a reference no inspect can be
// asked about. The first refusal stands.
func (r *libpodCreateReferenceReader) unreadable(field string) {
	r.deny(fmt.Sprintf(libpodCreateDenyUnreadable, r.create, field))
}

func (r *libpodCreateReferenceReader) deny(reason string) {
	if r.refs.denyReason == "" {
		r.refs.denyReason = reason
	}
}

// add records one reference, and reports false once the create names more
// than it will be checked for. The identifier goes to the lookup exactly as
// it arrived: Podman doesn't trim a reference before resolving it, so a
// padded one is a different lookup, not the same one.
func (r *libpodCreateReferenceReader) add(kind dockerresource.Kind, identifier, field string) bool {
	if slices.ContainsFunc(r.refs.resources, func(ref embeddedOwnershipReference) bool {
		return ref.kind == kind && ref.identifier == identifier
	}) {
		return true
	}
	if len(r.refs.resources) == libpodCreateMaxReferences {
		r.deny(fmt.Sprintf(libpodCreateDenyTooMany, r.create))
		return false
	}
	r.refs.resources = append(r.refs.resources, embeddedOwnershipReference{
		kind:       kind,
		identifier: identifier,
		source:     r.create + " " + field,
	})
	return true
}

// libpodVolumesFromContainer returns the container a `volumes_from` entry
// names: everything before the first colon, which is where Podman cuts the
// options off (pkg/specgen/generate/storage.go getVolumesFrom).
func libpodVolumesFromContainer(entry string) string {
	container, _, _ := strings.Cut(entry, ":")
	return container
}

// containerList reads a field that lists containers. Podman resolves each
// with LookupContainer, an exact name or a unique ID prefix, and the
// Docker-compatible container inspect owner isolation asks is the same
// lookup. An empty reference never resolves there, and the inspect can't be
// asked about one, so it's refused.
func (r *libpodCreateReferenceReader) containerList(decoded map[string]any, field string, container func(entry string) string) {
	value, ok := libpodCreateField(decoded, field)
	entries, isList := libpodCreateStringList(value)
	if !ok || !isList {
		r.unreadable(field)
		return
	}
	for _, entry := range entries {
		if container != nil {
			entry = container(entry)
		}
		if entry == "" {
			r.unreadable(field)
			return
		}
		if !r.add(dockerresource.KindContainer, entry, field) {
			return
		}
	}
}

// container reads a field that names one container, or none when it's empty.
func (r *libpodCreateReferenceReader) container(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	reference, isString := libpodCreateString(value)
	switch {
	case !ok || !isString:
		r.unreadable(field)
	case reference != "":
		r.add(dockerresource.KindContainer, reference, field)
	}
}

// networkMap reads `Networks`, whose keys are the networks to join. The keys
// are data, so they're read as written and in order.
func (r *libpodCreateReferenceReader) networkMap(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	if !ok {
		r.unreadable(field)
		return
	}
	if value == nil {
		return
	}
	networks, isObject := value.(map[string]any)
	if !isObject {
		r.unreadable(field)
		return
	}
	for _, name := range slices.Sorted(maps.Keys(networks)) {
		if !r.network(name, field) {
			return
		}
	}
}

// networkList reads `cni_networks`, the list Podman turns into `Networks`
// when that map is empty. It's checked whether or not the map is.
func (r *libpodCreateReferenceReader) networkList(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	names, isList := libpodCreateStringList(value)
	if !ok || !isList {
		r.unreadable(field)
		return
	}
	for _, name := range names {
		if !r.network(name, field) {
			return
		}
	}
}

// network records one network a create joins, and reports false when the
// create is refused for it.
//
// Podman resolves every name with NetworkInspect, an exact name or a unique ID
// prefix (Podman 5.8.6 libpod/runtime_ctr.go:264-313). The Docker-compatible
// network inspect is the same lookup for every name but "bridge", which it
// reads as the default network (pkg/api/handlers/compat/networks.go:27-32 and
// :55). A create's `Networks` reads "bridge" as a network of that name, so
// such a network is checked against the default one's labels. That network
// has none, and the create is refused.
//
// "default" is the one name that isn't looked up. Podman renames that key to
// the default network before it resolves anything
// (pkg/specgen/generate/namespaces.go:380-383), and that's the network a
// create naming none joins, so the key reaches nothing a create couldn't
// already reach. It's also the key podman-remote sends for `--network bridge`
// (pkg/specgen/namespaces.go:364-376), so looking it up would refuse that.
//
// The Docker-compatible create skips more names than that
// (isCustomNetworkMode): "bridge", "host", "none" and the two Swarm ones. Here
// those are ordinary network names, which Podman lets anyone create, so
// they're looked up like any other.
//
// The default network under its real name ("podman" unless containers.conf
// says otherwise) is looked up too, and refused for having no owner label,
// the way the Docker-compatible create refuses it.
//
// An empty name is a prefix of every network ID, so Podman resolves it when
// the host has one network. The inspect can't be asked about it, and it's
// refused.
func (r *libpodCreateReferenceReader) network(name, field string) bool {
	switch name {
	case "":
		r.unreadable(field)
		return false
	case "default":
		return true
	default:
		return r.add(dockerresource.KindNetwork, name, field)
	}
}

// namedVolumes reads `volumes`, a list of NamedVolume objects.
//
// Podman looks a volume up by its exact name, and so does the
// Docker-compatible volume inspect (libpod/runtime_ctr.go:496-519,
// libpod/runtime_volume.go:35). An entry with no name is an anonymous volume,
// created new for the container, and names nothing.
//
// A name nothing holds is refused like any other unresolved reference, as it
// is on the Docker-compatible create. Podman would create that volume on the
// spot, with no labels (runtime_ctr.go:529-565), so it would belong to no
// owner and the caller's next create naming it would be refused. Create the
// volume first, through POST /libpod/volumes/create, which stamps it.
func (r *libpodCreateReferenceReader) namedVolumes(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	volumes, isList := libpodCreateObjectList(value)
	if !ok || !isList {
		r.unreadable(field)
		return
	}
	for _, volume := range volumes {
		name, ok := libpodCreateStringField(volume, "Name")
		if !ok {
			r.unreadable(field)
			return
		}
		if name != "" && !r.add(dockerresource.KindVolume, name, field) {
			return
		}
	}
}

// imageVolumes reads `image_volumes`, a list of ImageVolume objects whose
// Source is the image to mount into the container.
//
// This is the one reference a check at create can't vouch for as written.
// Podman doesn't resolve the source when it creates the container. It keeps
// the string and looks it up at every start, with the lookup that tries a
// name before an ID prefix, and nothing stops an image being untagged or
// removed while a container still names it. So a caller could tag an image of
// its own "abc", pass the check with it, untag it, and have the next start
// mount whichever image has an ID starting with "abc", whoever owns it. Read
// from Podman 5.8.6 libpod/options.go:1387-1403 and
// libpod/container_internal_common.go:504-510, and go.podman.io/common
// v0.67.1 libimage/runtime.go:274-345.
//
// A full image ID has none of that. The lookup matches it against image IDs
// and nothing else, and an ID is derived from the image's config, labels
// included, so it can only ever resolve to the image it resolved to here. So
// a source has to be a full ID, and anything else is refused, whoever's image
// it names today. The ID is then checked like the image a container is
// created from: the caller's own passes, and an unlabeled one follows
// allow_unowned_images.
func (r *libpodCreateReferenceReader) imageVolumes(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	volumes, isList := libpodCreateObjectList(value)
	if !ok || !isList {
		r.unreadable(field)
		return
	}
	for _, volume := range volumes {
		source, ok := libpodCreateStringField(volume, "Source")
		if !ok {
			r.unreadable(field)
			return
		}
		if !isFullImageID(source) {
			r.deny(fmt.Sprintf(libpodCreateDenyImageVolumeName, r.create))
			return
		}
		if !r.add(dockerresource.KindImage, source, field) {
			return
		}
	}
}

// isFullImageID reports whether reference is a full image ID as libimage
// reads one: 64 lowercase hex digits, with or without a "sha256:" prefix
// (go.podman.io/common v0.67.1 libimage/runtime.go:274-296,
// go.podman.io/image/v5 5.39.2 docker/reference IsFullIdentifier). Uppercase
// hex, a shorter prefix and a name all go through the name lookup instead.
func isFullImageID(reference string) bool {
	id := strings.TrimPrefix(reference, "sha256:")
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// artifactVolumes refuses a container create that mounts an artifact with
// `artifact_volumes`.
//
// Podman looks an artifact up by name at every start, as it does an image
// volume, and here there's no spelling that makes a check hold: an artifact
// has annotations and no labels, so owner isolation can't tell whose one is
// even at create. Read from Podman 5.8.6 pkg/specgen/volumes.go:61-86 and
// libpod/container_internal_common.go:544-556.
func (r *libpodCreateReferenceReader) artifactVolumes(decoded map[string]any, field string) {
	value, ok := libpodCreateField(decoded, field)
	if !ok {
		r.unreadable(field)
		return
	}
	if value == nil {
		return
	}
	volumes, isList := value.([]any)
	switch {
	case !isList:
		r.unreadable(field)
	case len(volumes) > 0:
		r.deny(fmt.Sprintf(libpodCreateDenyArtifactVolume, r.create))
	}
}

// libpodCreateField returns the value of the key in object that encoding/json
// would decode into the field named key, which is one that matches it in any
// letter case. A missing key is a nil value. ok is false when two keys match,
// because nothing here can say which one Podman would keep.
func libpodCreateField(object map[string]any, key string) (value any, ok bool) {
	found := false
	for candidate, candidateValue := range object {
		if !strings.EqualFold(candidate, key) {
			continue
		}
		if found {
			return nil, false
		}
		found, value = true, candidateValue
	}
	return value, true
}

// libpodCreateString reads a value Podman decodes into a string. A null
// leaves the string empty.
func libpodCreateString(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

// libpodCreateStringField reads the string field of object named key.
func libpodCreateStringField(object map[string]any, key string) (string, bool) {
	value, ok := libpodCreateField(object, key)
	if !ok {
		return "", false
	}
	return libpodCreateString(value)
}

// libpodCreateStringList reads a value Podman decodes into a []string. A null
// leaves the list empty, and a null element is an empty string.
func libpodCreateStringList(value any) ([]string, bool) {
	if value == nil {
		return nil, true
	}
	elements, ok := value.([]any)
	if !ok {
		return nil, false
	}
	list := make([]string, 0, len(elements))
	for _, element := range elements {
		text, ok := libpodCreateString(element)
		if !ok {
			return nil, false
		}
		list = append(list, text)
	}
	return list, true
}

// libpodCreateObjectList reads a value Podman decodes into a list of pointers
// to structs. A null leaves the list empty. A null element is a nil pointer
// Podman goes on to dereference, so it's read as malformed.
func libpodCreateObjectList(value any) ([]map[string]any, bool) {
	if value == nil {
		return nil, true
	}
	elements, ok := value.([]any)
	if !ok {
		return nil, false
	}
	list := make([]map[string]any, 0, len(elements))
	for _, element := range elements {
		object, ok := element.(map[string]any)
		if !ok {
			return nil, false
		}
		list = append(list, object)
	}
	return list, true
}
