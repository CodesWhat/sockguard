package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/apipath"
	"github.com/codeswhat/sockguard/v2/app/internal/config"
)

var (
	errCreateRefChainNotFound  = errors.New("no such object")
	errCreateRefChainAmbiguous = errors.New("more than one result")
)

// createRefChainObject is one resource in libpodCreateRefChainDaemon's store:
// its ID and the owner label it carries, empty for none.
type createRefChainObject struct {
	ID    string
	Owner string
}

// createRefChainCreated is one container or pod libpodCreateRefChainDaemon
// created: the owner label it carries and every existing resource Podman would
// have attached to it, as "<how> <name> (<its owner>)".
type createRefChainCreated struct {
	Kind  string
	Owner string
	Uses  []string
}

// createRefChainNamespace is specgen.Namespace.
type createRefChainNamespace struct {
	NSMode string `json:"nsmode,omitempty"`
	Value  string `json:"value,omitempty"`
}

// createRefChainSpec is the part of specgen.SpecGenerator that names an
// existing resource, with Podman's field names and JSON tags. Volumes,
// ImageVolumes and Networks carry no tag on the fields the daemon reads, so
// they match on the Go name in any letter case.
type createRefChainSpec struct {
	Labels               map[string]string       `json:"labels,omitempty"`
	Pod                  string                  `json:"pod,omitempty"`
	Image                string                  `json:"image"`
	DependencyContainers []string                `json:"dependencyContainers,omitempty"`
	PidNS                createRefChainNamespace `json:"pidns"`
	UtsNS                createRefChainNamespace `json:"utsns"`
	IpcNS                createRefChainNamespace `json:"ipcns"`
	UserNS               createRefChainNamespace `json:"userns"`
	CgroupNS             createRefChainNamespace `json:"cgroupns"`
	NetNS                createRefChainNamespace `json:"netns"`
	VolumesFrom          []string                `json:"volumes_from,omitempty"`
	Volumes              []*struct {
		Name string
		Dest string
	} `json:"volumes,omitempty"`
	ImageVolumes []*struct {
		Source      string
		Destination string
	} `json:"image_volumes,omitempty"`
	ArtifactVolumes []*struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	} `json:"artifact_volumes,omitempty"`
	Networks    map[string]json.RawMessage
	CNINetworks []string `json:"cni_networks,omitempty"`
	DevicesFrom []string `json:"devices_from,omitempty"`
}

// createRefChainPodSpec is the same part of specgen.PodSpecGenerator. A pod
// spec has no cgroupns, pod, image, dependencyContainers, artifact_volumes or
// devices_from.
type createRefChainPodSpec struct {
	Labels      map[string]string       `json:"labels,omitempty"`
	NoInfra     bool                    `json:"no_infra,omitempty"`
	IpcNS       createRefChainNamespace `json:"ipcns"`
	PidNS       createRefChainNamespace `json:"pidns"`
	UserNS      createRefChainNamespace `json:"userns"`
	UtsNS       createRefChainNamespace `json:"utsns"`
	NetNS       createRefChainNamespace `json:"netns"`
	Networks    map[string]json.RawMessage
	CNINetworks []string `json:"cni_networks,omitempty"`
	VolumesFrom []string `json:"volumes_from,omitempty"`
	Volumes     []*struct {
		Name string
		Dest string
	} `json:"volumes,omitempty"`
	ImageVolumes []*struct {
		Source      string
		Destination string
	} `json:"image_volumes,omitempty"`
	ServiceContainerID string `json:"serviceContainerID,omitempty"`
}

// libpodCreateRefChainDaemon is a Podman store behind the two creates whose
// body names existing resources, POST /vX/libpod/containers/create and
// POST /vX/libpod/pods/create, and the inspects owner isolation looks those
// resources up with.
//
// Both handlers decode the body with encoding/json, into a SpecGenerator and a
// PodSpecGenerator, so a key matches its field in any letter case. Read from
// Podman 5.8.6 pkg/api/handlers/libpod/containers_create.go and pods.go, and
// pkg/specgen/specgen.go, podspecgen.go, volumes.go and namespaces.go.
//
// What MakeContainer does with each reference, from
// pkg/specgen/generate/container_create.go, storage.go and namespaces.go and
// libpod/runtime_ctr.go:
//
//   - `pod` is resolved with LookupPod and the container joins it.
//   - A namespace with nsmode "container" resolves its value with
//     LookupContainer and the container joins that namespace: pidns, ipcns,
//     utsns, userns, netns and cgroupns alike.
//   - Each `volumes_from` entry is "<container>[:<options>]". The container is
//     resolved with LookupContainer and its mounts and named volumes are
//     copied in.
//   - Each `dependencyContainers` entry is resolved with LookupContainer. The
//     new container won't start until they run, and a start through the API
//     starts them first (pkg/api/handlers/compat/containers_start.go:39).
//   - Each `volumes` entry with a name is looked up by that exact name. One
//     that doesn't exist is created on the spot, with no labels. An entry
//     with no name is an anonymous volume.
//   - With bridge networking, every `Networks` key is resolved with
//     NetworkInspect, a name or a unique ID prefix, after the key "default" is
//     renamed to the default network. `cni_networks` is read only when
//     `Networks` is empty. With neither, the container joins the default
//     network.
//   - `image_volumes` and `artifact_volumes` aren't resolved at create at all.
//     Podman keeps each source as written and looks it up at every start
//     (libpod/container_internal_common.go:504-506 and :550). The daemon
//     records what the first start would mount.
//   - `devices_from` is decoded and never read.
//
// PodCreate marshals the PodSpecGenerator it decoded and unmarshals that into
// the infra container's SpecGenerator, so the pod's namespaces, networks and
// volumes become the infra container's, and a key PodSpecGenerator has no
// field for is dropped. MapSpec refuses a pod whose netns joins a container.
// With `no_infra` true none of that runs: there's no infra container, the
// pod's volumes, image volumes, volumes_from and cni_networks are decoded and
// never read, and Validate refuses a `Networks` that names anything
// (pkg/api/handlers/libpod/pods.go:43-75, pkg/specgen/pod_validate.go:40-48
// and pkg/specgen/generate/pod_create.go:76-113).
// `serviceContainerID` is resolved with LookupContainer, and starting the pod
// restarts that container (libpod/options.go:2162, libpod/service.go:211-233).
//
// LookupContainer and LookupPod match an exact name, then a unique ID prefix,
// and NetworkInspect does the same. The inspects resolve the same way:
// GET /containers/{name}/json, GET /libpod/pods/{name}/json and
// GET /networks/{name}, which reads "bridge" as the default network
// (pkg/api/handlers/compat/networks.go:27). GET /volumes/{name} matches the
// exact name, as the create does. A container named "broken-ctr" answers 500
// so the lookup failure path can be driven.
type libpodCreateRefChainDaemon struct {
	mu         sync.Mutex
	containers map[string]createRefChainObject
	pods       map[string]createRefChainObject
	networks   map[string]createRefChainObject
	volumes    map[string]createRefChainObject
	images     map[string]createRefChainObject
	artifacts  []string
	lookups    []string
	created    []createRefChainCreated
}

const (
	createRefChainMineImageID   = "1111111111111111111111111111111111111111111111111111111111111111"
	createRefChainTheirsImageID = "2222222222222222222222222222222222222222222222222222222222222222"
	createRefChainBaseImageID   = "3333333333333333333333333333333333333333333333333333333333333333"
	createRefChainDefaultNet    = "podman"
)

func newLibpodCreateRefChainDaemon() *libpodCreateRefChainDaemon {
	id := func(digit string) string { return strings.Repeat(digit, 64) }
	return &libpodCreateRefChainDaemon{
		containers: map[string]createRefChainObject{
			"mine-ctr":   {ID: id("a"), Owner: "team-a"},
			"theirs-ctr": {ID: id("b"), Owner: "team-b"},
			"host-ctr":   {ID: id("c")},
			"broken-ctr": {ID: id("d"), Owner: "team-a"},
		},
		pods: map[string]createRefChainObject{
			"mine-pod":   {ID: id("4"), Owner: "team-a"},
			"theirs-pod": {ID: id("5"), Owner: "team-b"},
		},
		networks: map[string]createRefChainObject{
			createRefChainDefaultNet: {ID: id("6")},
			"mine-net":               {ID: id("7"), Owner: "team-a"},
			"theirs-net":             {ID: id("8"), Owner: "team-b"},
		},
		volumes: map[string]createRefChainObject{
			"mine-data":   {Owner: "team-a"},
			"theirs-data": {Owner: "team-b"},
			"host-data":   {},
		},
		images: map[string]createRefChainObject{
			"mine-img":   {ID: createRefChainMineImageID, Owner: "team-a"},
			"theirs-img": {ID: createRefChainTheirsImageID, Owner: "team-b"},
			"alpine":     {ID: createRefChainBaseImageID},
		},
		artifacts: []string{"theirs-artifact"},
	}
}

func (d *libpodCreateRefChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	normPath := apipath.NormalizePath(r.URL.Path)
	versioned := normPath != r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && normPath == "/version":
		_ = json.NewEncoder(w).Encode(engineChainVersion(true))
	case r.Method == http.MethodGet:
		d.inspect(w, normPath)
	case r.Method == http.MethodPost && normPath == "/libpod/containers/create" && versioned:
		d.createContainer(w, r)
	case r.Method == http.MethodPost && normPath == "/libpod/pods/create" && versioned:
		d.createPod(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *libpodCreateRefChainDaemon) inspect(w http.ResponseWriter, normPath string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		kind, reference string
		object          createRefChainObject
		err             error
		nested          bool
	)
	switch {
	case strings.HasPrefix(normPath, "/containers/") && strings.HasSuffix(normPath, "/json"):
		kind, nested = "containers", true
		reference = strings.TrimSuffix(strings.TrimPrefix(normPath, "/containers/"), "/json")
		_, object, err = createRefChainLookup(d.containers, reference)
	case strings.HasPrefix(normPath, "/libpod/pods/") && strings.HasSuffix(normPath, "/json"):
		kind = "pods"
		reference = strings.TrimSuffix(strings.TrimPrefix(normPath, "/libpod/pods/"), "/json")
		_, object, err = createRefChainLookup(d.pods, reference)
	case strings.HasPrefix(normPath, "/images/") && strings.HasSuffix(normPath, "/json"):
		kind, nested = "images", true
		reference = strings.TrimSuffix(strings.TrimPrefix(normPath, "/images/"), "/json")
		_, object, err = d.lookupImageLocked(reference)
	case strings.HasPrefix(normPath, "/networks/"):
		kind = "networks"
		reference = strings.TrimPrefix(normPath, "/networks/")
		name := reference
		if name == "bridge" {
			name = createRefChainDefaultNet
		}
		_, object, err = createRefChainLookup(d.networks, name)
	case strings.HasPrefix(normPath, "/volumes/"):
		kind = "volumes"
		reference = strings.TrimPrefix(normPath, "/volumes/")
		var ok bool
		if object, ok = d.volumes[reference]; !ok {
			err = errCreateRefChainNotFound
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	d.lookups = append(d.lookups, kind+"/"+reference)

	switch {
	case errors.Is(err, errCreateRefChainNotFound):
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil, reference == "broken-ctr":
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	labels := map[string]string{}
	if object.Owner != "" {
		labels["com.sockguard.owner"] = object.Owner
	}
	if nested {
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": object.ID, "Config": map[string]any{"Labels": labels}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"Id": object.ID, "Name": reference, "Labels": labels})
}

// createRefChainLookup is LookupContainer, LookupPod and NetworkInspect: an
// exact name, then the one object whose ID starts with the reference.
func createRefChainLookup(store map[string]createRefChainObject, reference string) (string, createRefChainObject, error) {
	if reference == "" {
		return "", createRefChainObject{}, errCreateRefChainNotFound
	}
	if object, ok := store[reference]; ok {
		return reference, object, nil
	}
	var (
		foundName string
		found     createRefChainObject
		exists    bool
	)
	for name, object := range store {
		if !strings.HasPrefix(object.ID, reference) {
			continue
		}
		if exists {
			return "", createRefChainObject{}, errCreateRefChainAmbiguous
		}
		foundName, found, exists = name, object, true
	}
	if !exists {
		return "", createRefChainObject{}, errCreateRefChainNotFound
	}
	return foundName, found, nil
}

// lookupImageLocked is libimage's LookupImage, as far as these tests go: a
// full ID, with or without "sha256:", matches that image and nothing else,
// and anything else matches a name before it matches an ID prefix
// (go.podman.io/common v0.67.1 libimage/runtime.go:274-345).
func (d *libpodCreateRefChainDaemon) lookupImageLocked(reference string) (string, createRefChainObject, error) {
	if id := strings.TrimPrefix(reference, "sha256:"); len(id) == 64 {
		for name, image := range d.images {
			if image.ID == id {
				return name, image, nil
			}
		}
		return "", createRefChainObject{}, errCreateRefChainNotFound
	}
	return createRefChainLookup(d.images, reference)
}

func (d *libpodCreateRefChainDaemon) createContainer(w http.ResponseWriter, r *http.Request) {
	var spec createRefChainSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		createRefChainFail(w, fmt.Errorf("decode(): %w", err))
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	uses, err := d.attachLocked(&spec)
	if err != nil {
		createRefChainFail(w, err)
		return
	}
	d.recordLocked(w, "container", spec.Labels, uses)
}

func (d *libpodCreateRefChainDaemon) createPod(w http.ResponseWriter, r *http.Request) {
	var pod createRefChainPodSpec
	if err := json.NewDecoder(r.Body).Decode(&pod); err != nil {
		createRefChainFail(w, fmt.Errorf("failed to decode specgen: %w", err))
		return
	}
	var infra createRefChainSpec
	if !pod.NoInfra {
		matching, err := json.Marshal(pod)
		if err == nil {
			err = json.Unmarshal(matching, &infra)
		}
		if err != nil {
			createRefChainFail(w, fmt.Errorf("failed to decode specgen: %w", err))
			return
		}
	}
	// PodSpecGenerator.Validate (pkg/specgen/pod_validate.go:40-48).
	if pod.NoInfra && len(pod.Networks) > 0 {
		createRefChainFail(w, errors.New("cannot set networks options without infra container"))
		return
	}
	if pod.NetNS.NSMode == "container" {
		createRefChainFail(w, errors.New("pods presently do not support network mode container"))
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	var uses []string
	if pod.ServiceContainerID != "" {
		name, service, err := createRefChainLookup(d.containers, pod.ServiceContainerID)
		if err != nil {
			createRefChainFail(w, fmt.Errorf("looking up service container: %w", err))
			return
		}
		uses = append(uses, createRefChainUse("service-container", name, service))
	}
	if !pod.NoInfra {
		infraUses, err := d.attachLocked(&infra)
		if err != nil {
			createRefChainFail(w, err)
			return
		}
		uses = append(uses, infraUses...)
	}
	d.recordLocked(w, "pod", pod.Labels, uses)
}

// attachLocked resolves every reference in spec the way MakeContainer does and
// returns what the container was attached to. The first reference that
// doesn't resolve fails the create.
func (d *libpodCreateRefChainDaemon) attachLocked(spec *createRefChainSpec) ([]string, error) {
	var uses []string
	container := func(how, reference string) error {
		name, object, err := createRefChainLookup(d.containers, reference)
		if err != nil {
			return fmt.Errorf("looking up container %q for %s: %w", reference, how, err)
		}
		uses = append(uses, createRefChainUse(how, name, object))
		return nil
	}

	if spec.Pod != "" {
		name, pod, err := createRefChainLookup(d.pods, spec.Pod)
		if err != nil {
			return nil, fmt.Errorf("retrieving pod %s: %w", spec.Pod, err)
		}
		uses = append(uses, createRefChainUse("pod", name, pod))
	}
	if spec.Image != "" {
		if _, _, err := d.lookupImageLocked(spec.Image); err != nil {
			return nil, fmt.Errorf("no such image %q: %w", spec.Image, err)
		}
	}
	for _, namespace := range []struct {
		how string
		ns  createRefChainNamespace
	}{
		{"pidns", spec.PidNS}, {"ipcns", spec.IpcNS}, {"utsns", spec.UtsNS},
		{"userns", spec.UserNS}, {"cgroupns", spec.CgroupNS}, {"netns", spec.NetNS},
	} {
		if namespace.ns.NSMode != "container" {
			continue
		}
		if err := container(namespace.how, namespace.ns.Value); err != nil {
			return nil, err
		}
	}
	for _, entry := range spec.VolumesFrom {
		reference, _, _ := strings.Cut(entry, ":")
		if err := container("volumes-from", reference); err != nil {
			return nil, err
		}
	}
	for _, reference := range spec.DependencyContainers {
		if err := container("depends-on", reference); err != nil {
			return nil, err
		}
	}
	for _, volume := range spec.Volumes {
		switch {
		case volume == nil:
			return nil, errors.New("nil named volume")
		case volume.Name == "":
			continue
		}
		existing, ok := d.volumes[volume.Name]
		if !ok {
			d.volumes[volume.Name] = createRefChainObject{}
			uses = append(uses, "volume "+volume.Name+" (created)")
			continue
		}
		uses = append(uses, createRefChainUse("volume", volume.Name, existing))
	}
	for _, volume := range spec.ImageVolumes {
		if volume == nil {
			return nil, errors.New("nil image volume")
		}
		if name, image, err := d.lookupImageLocked(volume.Source); err == nil {
			uses = append(uses, createRefChainUse("image-volume", name, image))
		}
	}
	for _, volume := range spec.ArtifactVolumes {
		if volume == nil {
			return nil, errors.New("nil artifact volume")
		}
		if slices.Contains(d.artifacts, volume.Source) {
			uses = append(uses, "artifact "+volume.Source)
		}
	}

	switch spec.NetNS.NSMode {
	case "", "default", "private", "bridge":
		networks := slices.Sorted(maps.Keys(spec.Networks))
		if len(networks) == 0 {
			networks = spec.CNINetworks
		}
		for _, reference := range networks {
			if reference == "default" {
				reference = createRefChainDefaultNet
			}
			name, network, err := createRefChainLookup(d.networks, reference)
			if err != nil {
				return nil, fmt.Errorf("unable to find network with name or ID %s: %w", reference, err)
			}
			uses = append(uses, createRefChainUse("network", name, network))
		}
	}
	return uses, nil
}

func (d *libpodCreateRefChainDaemon) recordLocked(w http.ResponseWriter, kind string, labels map[string]string, uses []string) {
	if uses == nil {
		uses = []string{}
	}
	slices.Sort(uses)
	d.created = append(d.created, createRefChainCreated{Kind: kind, Owner: labels["com.sockguard.owner"], Uses: uses})
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"Id": fmt.Sprintf("%064d", len(d.created)), "Warnings": []string{}})
}

func createRefChainUse(how, name string, object createRefChainObject) string {
	owner := object.Owner
	if owner == "" {
		owner = "unlabeled"
	}
	return fmt.Sprintf("%s %s (%s)", how, name, owner)
}

func createRefChainFail(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"cause": err.Error()})
}

func (d *libpodCreateRefChainDaemon) made() []createRefChainCreated {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.created)
}

func (d *libpodCreateRefChainDaemon) lookedUp() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.lookups)
}

// TestServeChainLibpodCreateReferencesAreOwnerChecked sends libpod container
// and pod creates from team-a through the production chain to a daemon that
// resolves their references the way Podman does. It asserts on what the daemon
// attached to whatever it created, and on which inspects owner isolation made
// first.
//
// Owner isolation used to check a create's image, its pod and five of its
// namespace targets, and read nothing else in the body. A container create
// naming another owner's named volume, container (through volumes_from,
// dependencyContainers or cgroupns), network or image volume went to Podman
// with no lookup of that resource, and so did a pod create naming one, or a
// container for the pod's service container.
//
// Every one of those now has to resolve to something carrying the caller's
// owner label. A named volume nothing holds is refused as unresolved, as on
// the Docker-compatible create: Podman would create it with no labels, which
// leaves a volume no owner can use. The network key "default" is the only
// reference that isn't looked up, because Podman reads it as the network a
// create naming none joins.
//
// An image volume has to name its image by full ID. Podman looks the source up
// again at every start, by name before ID prefix, so team-a could pass the
// check with an image of its own, untag it, and have the next start mount
// whatever the name resolves to by then. An artifact volume is refused
// outright: an artifact carries no labels to check.
func TestServeChainLibpodCreateReferencesAreOwnerChecked(t *testing.T) {
	const (
		containerURL = "/v5.0.0/libpod/containers/create"
		podURL       = "/v5.0.0/libpod/pods/create"
		alpine       = "images/alpine"
		theirsCtr    = "containers/theirs-ctr"
		deniedTarget = `libpod owner policy denied access to namespace-sharing target container "theirs-ctr"`
		lookupFailed = "owner policy lookup failed"
	)
	denied := func(kind, reference, source string) string {
		return fmt.Sprintf("libpod owner policy denied access to %s %q referenced by %s", kind, reference, source)
	}
	unresolved := func(kind, reference, source string) string {
		return fmt.Sprintf("libpod owner policy could not resolve %s %q referenced by %s", kind, reference, source)
	}
	unreadable := func(create, field string) string {
		return fmt.Sprintf("libpod owner policy denied %s with a %s reference it can't look up", create, field)
	}
	imageByName := func(create string) string {
		return "libpod owner policy denied " + create + " with an image volume that doesn't name its image by full ID, which Podman looks up again at every start"
	}
	imageVolume := func(source string) string {
		return `"image_volumes":[{"Source":"` + source + `","Destination":"/img"}]`
	}
	container := func(fields string) string {
		return `{"image":"alpine","systemd":"false",` + fields + `}`
	}
	pod := func(fields string) string {
		return `{"name":"web",` + fields + `}`
	}
	var manyContainers []string
	for i := range 257 {
		manyContainers = append(manyContainers, fmt.Sprintf(`"ctr-%d"`, i))
	}
	tests := []struct {
		name string
		// owner is "none" for a chain without owner isolation.
		owner      string
		rollout    string
		target     string
		body       string
		wantStatus int
		wantReason string
		// wantLookups is every inspect owner isolation made, in order.
		wantLookups []string
		// wantUses is what the one container or pod the daemon created was
		// attached to. Nil means the daemon created nothing.
		wantUses []string
	}{
		{
			name:        "container with another owner's named volume",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "theirs-data", "container create volumes"),
			wantLookups: []string{alpine, "volumes/theirs-data"},
		},
		{
			// podman-remote sends every NamedVolume field, with Go's names.
			name:        "podman-remote shape naming another owner's volume",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"theirs-data","Dest":"/data","Options":null,"IsAnonymous":false,"SubPath":""}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "theirs-data", "container create volumes"),
			wantLookups: []string{alpine, "volumes/theirs-data"},
		},
		{
			name:        "container with the volumes of another owner's container",
			target:      containerURL,
			body:        container(`"volumes_from":["theirs-ctr:ro"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "container create volumes_from"),
			wantLookups: []string{alpine, theirsCtr},
		},
		{
			name:        "container with the volumes of another owner's container by ID prefix",
			target:      containerURL,
			body:        container(`"volumes_from":["bbbb"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "bbbb", "container create volumes_from"),
			wantLookups: []string{alpine, "containers/bbbb"},
		},
		{
			name:        "container on another owner's network",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"Networks":{"theirs-net":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "container create Networks"),
			wantLookups: []string{alpine, "networks/theirs-net"},
		},
		{
			name:        "container on another owner's network by ID prefix",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"Networks":{"8888":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "8888", "container create Networks"),
			wantLookups: []string{alpine, "networks/8888"},
		},
		{
			name:        "container on another owner's network through cni_networks",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"cni_networks":["theirs-net"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "container create cni_networks"),
			wantLookups: []string{alpine, "networks/theirs-net"},
		},
		{
			// Podman reads cni_networks only when Networks is empty, and
			// owner isolation checks it either way.
			name:        "container with cni_networks naming another owner's network beside its own",
			target:      containerURL,
			body:        container(`"Networks":{"mine-net":{}},"cni_networks":["theirs-net"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "container create cni_networks"),
			wantLookups: []string{alpine, "networks/mine-net", "networks/theirs-net"},
		},
		{
			name:        "container with another owner's image as a volume",
			target:      containerURL,
			body:        container(imageVolume(createRefChainTheirsImageID)),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("image", createRefChainTheirsImageID, "container create image_volumes"),
			wantLookups: []string{alpine, "images/" + createRefChainTheirsImageID},
		},
		{
			name:        "container with another owner's image as a volume by name",
			target:      containerURL,
			body:        container(imageVolume("theirs-img")),
			wantStatus:  http.StatusForbidden,
			wantReason:  imageByName("container create"),
			wantLookups: []string{alpine},
		},
		{
			// A name is refused whoever holds it today: Podman reads it again
			// at every start.
			name:        "container with its own image as a volume by name",
			target:      containerURL,
			body:        container(imageVolume("mine-img")),
			wantStatus:  http.StatusForbidden,
			wantReason:  imageByName("container create"),
			wantLookups: []string{alpine},
		},
		{
			// Once nothing holds the name "2222", it's a prefix of the other
			// owner's image ID.
			name:        "container with an image volume by ID prefix",
			target:      containerURL,
			body:        container(imageVolume("2222")),
			wantStatus:  http.StatusForbidden,
			wantReason:  imageByName("container create"),
			wantLookups: []string{alpine},
		},
		{
			name:        "container depending on another owner's container",
			target:      containerURL,
			body:        container(`"dependencyContainers":["theirs-ctr"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "container create dependencyContainers"),
			wantLookups: []string{alpine, theirsCtr},
		},
		{
			name:        "container in another owner's cgroup namespace",
			target:      containerURL,
			body:        container(`"cgroupns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			// Artifacts carry no labels, so there's no owner to look up.
			name:        "container with an artifact as a volume",
			target:      containerURL,
			body:        container(`"artifact_volumes":[{"source":"theirs-artifact","destination":"/artifact"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  "libpod owner policy denied container create with an artifact volume: an artifact carries no owner label to check",
			wantLookups: []string{alpine},
		},
		{
			// Podman 5.8.6 decodes devices_from and never reads it.
			name:        "container with devices_from naming another owner's container",
			target:      containerURL,
			body:        container(`"devices_from":["theirs-ctr"]`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine},
			wantUses:    []string{},
		},

		{
			name:        "container with a volume nobody owns",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"host-data","Dest":"/data"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "host-data", "container create volumes"),
			wantLookups: []string{alpine, "volumes/host-data"},
		},
		{
			name:        "container with the volumes of a container nobody owns",
			target:      containerURL,
			body:        container(`"volumes_from":["host-ctr"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "host-ctr", "container create volumes_from"),
			wantLookups: []string{alpine, "containers/host-ctr"},
		},
		{
			name:        "container on the default network by its own name",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"Networks":{"podman":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "podman", "container create Networks"),
			wantLookups: []string{alpine, "networks/podman"},
		},
		{
			// The inspect reads "bridge" as the default network, and the
			// create reads it as a network of that name.
			name:        "container on a network called bridge",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"Networks":{"bridge":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "bridge", "container create Networks"),
			wantLookups: []string{alpine, "networks/bridge"},
		},
		{
			// With allow_unowned_images, the default, an image with no owner
			// label is anyone's to use.
			name:        "container with an image nobody owns as a volume",
			target:      containerURL,
			body:        container(imageVolume(createRefChainBaseImageID)),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine, "images/" + createRefChainBaseImageID},
			wantUses:    []string{"image-volume alpine (unlabeled)"},
		},
		{
			name:        "container with an image volume by an ID nothing holds",
			target:      containerURL,
			body:        container(imageVolume(strings.Repeat("9", 64))),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("image", strings.Repeat("9", 64), "container create image_volumes"),
			wantLookups: []string{alpine, "images/" + strings.Repeat("9", 64)},
		},

		{
			// Podman would create it on the spot with no labels.
			name:        "container with a named volume nothing holds",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"fresh-data","Dest":"/data"}]`),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("volume", "fresh-data", "container create volumes"),
			wantLookups: []string{alpine, "volumes/fresh-data"},
		},
		{
			// The volume lookup is by exact name, as Podman's is.
			name:        "container with a named volume that is a prefix of another owner's",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"theirs","Dest":"/data"}]`),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("volume", "theirs", "container create volumes"),
			wantLookups: []string{alpine, "volumes/theirs"},
		},
		{
			name:        "container depending on a container nothing holds",
			target:      containerURL,
			body:        container(`"dependencyContainers":["gone-ctr"]`),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("container", "gone-ctr", "container create dependencyContainers"),
			wantLookups: []string{alpine, "containers/gone-ctr"},
		},
		{
			name:        "container on a network nothing holds",
			target:      containerURL,
			body:        container(`"Networks":{"gone-net":{}}`),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("network", "gone-net", "container create Networks"),
			wantLookups: []string{alpine, "networks/gone-net"},
		},
		{
			name:        "container whose reference can't be looked up",
			target:      containerURL,
			body:        container(`"volumes_from":["broken-ctr"]`),
			wantStatus:  http.StatusBadGateway,
			wantReason:  lookupFailed,
			wantLookups: []string{alpine, "containers/broken-ctr"},
		},

		{
			name:       "container with its own resources",
			target:     containerURL,
			body:       container(`"volumes":[{"Name":"mine-data","Dest":"/data"}],"volumes_from":["mine-ctr:ro"],"dependencyContainers":["mine-ctr"],"cgroupns":{"nsmode":"container","value":"mine-ctr"},"netns":{"nsmode":"bridge"},"Networks":{"mine-net":{}},` + imageVolume("sha256:"+createRefChainMineImageID)),
			wantStatus: http.StatusCreated,
			wantLookups: []string{
				"containers/mine-ctr", alpine,
				"containers/mine-ctr", "networks/mine-net", "volumes/mine-data", "images/sha256:" + createRefChainMineImageID,
			},
			wantUses: []string{
				"cgroupns mine-ctr (team-a)",
				"depends-on mine-ctr (team-a)",
				"image-volume mine-img (team-a)",
				"network mine-net (team-a)",
				"volume mine-data (team-a)",
				"volumes-from mine-ctr (team-a)",
			},
		},
		{
			name:        "container with an anonymous volume",
			target:      containerURL,
			body:        container(`"volumes":[{"Dest":"/scratch"}]`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine},
			wantUses:    []string{},
		},
		{
			// Podman renames the key to the default network, which is where
			// a create naming no network lands anyway.
			name:        "container on the network key default",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"Networks":{"default":{}}`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine},
			wantUses:    []string{"network podman (unlabeled)"},
		},
		{
			// podman-remote sends the fields it has nothing for as null.
			name:        "container with every reference field null",
			target:      containerURL,
			body:        container(`"volumes":null,"volumes_from":null,"dependencyContainers":null,"Networks":null,"cni_networks":null,"image_volumes":null,"artifact_volumes":null,"cgroupns":{}`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine},
			wantUses:    []string{},
		},

		{
			name:        "container with volumes in another case",
			target:      containerURL,
			body:        container(`"VOLUMES":[{"name":"theirs-data","dest":"/data"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "theirs-data", "container create volumes"),
			wantLookups: []string{alpine, "volumes/theirs-data"},
		},
		{
			// Networks has no JSON tag, so its lowercase spelling matches too.
			name:        "container with networks in lowercase",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"bridge"},"networks":{"theirs-net":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "container create Networks"),
			wantLookups: []string{alpine, "networks/theirs-net"},
		},
		{
			name:        "container with dependencyContainers in another case",
			target:      containerURL,
			body:        container(`"DEPENDENCYCONTAINERS":["theirs-ctr"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "container create dependencyContainers"),
			wantLookups: []string{alpine, theirsCtr},
		},
		{
			// encoding/json folds U+017F, the long s, onto "s", and Podman
			// 6's decoder doesn't. The body is refused before either reads it.
			name:       "container with volumes_from spelled with a long s",
			target:     containerURL,
			body:       container(`"volumeſ_from":["theirs-ctr"]`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: ambiguous JSON object key "volume\u017f_from": U+017F matches a field name in some JSON decoders and not in others`,
		},
		{
			name:       "container with volumes spelled two ways",
			target:     containerURL,
			body:       container(`"volumes":[{"Name":"mine-data","Dest":"/data"}],"Volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "volumes" and "Volumes"`,
		},
		{
			// Podman would merge the two lists element by element and mount
			// theirs-data, and a map decode keeps the last one only. A body
			// that reads two ways is refused, whichever comes last.
			name:       "container with volumes given twice, another owner's first",
			target:     containerURL,
			body:       container(`"volumes":[{"Name":"theirs-data","Dest":"/data"}],"volumes":[{"Dest":"/data"}]`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "volumes" and "volumes"`,
		},
		{
			name:       "container with volumes given twice, another owner's last",
			target:     containerURL,
			body:       container(`"volumes":[{"Dest":"/data"}],"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "volumes" and "volumes"`,
		},
		{
			// Podman would merge the two maps and join both networks.
			name:       "container with Networks given twice, another owner's first",
			target:     containerURL,
			body:       container(`"netns":{"nsmode":"bridge"},"Networks":{"theirs-net":{}},"Networks":{"mine-net":{}}`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "Networks" and "Networks"`,
		},

		{
			// Podman's decode fails on this, and it's refused here instead of
			// being forwarded on the strength of that.
			name:        "container with volumes_from that isn't a list",
			target:      containerURL,
			body:        container(`"volumes_from":"theirs-ctr"`),
			wantStatus:  http.StatusForbidden,
			wantReason:  unreadable("container create", "volumes_from"),
			wantLookups: []string{alpine},
		},
		{
			name:        "container with an empty volumes_from entry",
			target:      containerURL,
			body:        container(`"volumes_from":[":ro"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  unreadable("container create", "volumes_from"),
			wantLookups: []string{alpine},
		},
		{
			name:        "container on a network with an empty name",
			target:      containerURL,
			body:        container(`"Networks":{"":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  unreadable("container create", "Networks"),
			wantLookups: []string{alpine},
		},
		{
			name:        "container naming more containers than owner isolation will look up",
			target:      containerURL,
			body:        container(`"volumes_from":[` + strings.Join(manyContainers, ",") + `]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  "libpod owner policy denied container create that names more resources than it can authorize",
			wantLookups: []string{alpine},
		},

		{
			name:        "another owner's named volume in warn mode",
			rollout:     "warn",
			target:      containerURL,
			body:        container(`"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{alpine, "volumes/theirs-data"},
			wantUses:    []string{"volume theirs-data (team-b)"},
		},
		{
			name:       "another owner's resources without owner isolation",
			owner:      "none",
			target:     containerURL,
			body:       container(`"volumes":[{"Name":"theirs-data","Dest":"/data"}],"volumes_from":["theirs-ctr"]`),
			wantStatus: http.StatusCreated,
			wantUses:   []string{"volume theirs-data (team-b)", "volumes-from theirs-ctr (team-b)"},
		},

		{
			name:        "pod with another owner's named volume",
			target:      podURL,
			body:        pod(`"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "theirs-data", "pod create volumes"),
			wantLookups: []string{"volumes/theirs-data"},
		},
		{
			name:        "pod with the volumes of another owner's container",
			target:      podURL,
			body:        pod(`"volumes_from":["theirs-ctr"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "pod create volumes_from"),
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod on another owner's network",
			target:      podURL,
			body:        pod(`"netns":{"nsmode":"bridge"},"Networks":{"theirs-net":{}}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "pod create Networks"),
			wantLookups: []string{"networks/theirs-net"},
		},
		{
			name:        "pod on another owner's network through cni_networks",
			target:      podURL,
			body:        pod(`"netns":{"nsmode":"bridge"},"cni_networks":["theirs-net"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("network", "theirs-net", "pod create cni_networks"),
			wantLookups: []string{"networks/theirs-net"},
		},
		{
			name:        "pod with another owner's image as a volume",
			target:      podURL,
			body:        pod(imageVolume(createRefChainTheirsImageID)),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("image", createRefChainTheirsImageID, "pod create image_volumes"),
			wantLookups: []string{"images/" + createRefChainTheirsImageID},
		},
		{
			name:       "pod with its own image as a volume by name",
			target:     podURL,
			body:       pod(imageVolume("mine-img")),
			wantStatus: http.StatusForbidden,
			wantReason: imageByName("pod create"),
		},
		{
			name:        "pod with another owner's container as its service container",
			target:      podURL,
			body:        pod(`"serviceContainerID":"theirs-ctr"`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "pod create serviceContainerID"),
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod with a named volume nothing holds",
			target:      podURL,
			body:        pod(`"volumes":[{"Name":"fresh-data","Dest":"/data"}]`),
			wantStatus:  http.StatusNotFound,
			wantReason:  unresolved("volume", "fresh-data", "pod create volumes"),
			wantLookups: []string{"volumes/fresh-data"},
		},
		{
			name:        "pod with a service container that isn't a string",
			target:      podURL,
			body:        pod(`"serviceContainerID":["theirs-ctr"]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  unreadable("pod create", "serviceContainerID"),
			wantLookups: nil,
		},
		{
			name:       "pod with its own resources",
			target:     podURL,
			body:       pod(`"volumes":[{"Name":"mine-data","Dest":"/data"}],"volumes_from":["mine-ctr"],"serviceContainerID":"mine-ctr","netns":{"nsmode":"bridge"},"Networks":{"mine-net":{}},` + imageVolume(createRefChainMineImageID)),
			wantStatus: http.StatusCreated,
			wantLookups: []string{
				"containers/mine-ctr", "networks/mine-net", "volumes/mine-data", "images/" + createRefChainMineImageID,
			},
			wantUses: []string{
				"image-volume mine-img (team-a)",
				"network mine-net (team-a)",
				"service-container mine-ctr (team-a)",
				"volume mine-data (team-a)",
				"volumes-from mine-ctr (team-a)",
			},
		},
		{
			// A pod with no infra container has nothing to hand its volumes
			// and networks to. Podman never reads them, so there's nothing
			// to check.
			name:       "pod with no infra container naming another owner's resources",
			target:     podURL,
			body:       pod(`"no_infra":true,"volumes":[{"Name":"theirs-data","Dest":"/data"}],"volumes_from":["theirs-ctr"],"cni_networks":["theirs-net"],` + imageVolume("theirs-img")),
			wantStatus: http.StatusCreated,
			wantUses:   []string{},
		},
		{
			name:       "pod with no infra container under an upper-case key",
			target:     podURL,
			body:       pod(`"NO_INFRA":true,"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus: http.StatusCreated,
			wantUses:   []string{},
		},
		{
			// A repeated key is refused whichever value comes last.
			name:       "pod with no_infra given twice, true last",
			target:     podURL,
			body:       pod(`"no_infra":false,"volumes":[{"Name":"theirs-data","Dest":"/data"}],"no_infra":true`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "no_infra" and "no_infra"`,
		},
		{
			name:       "pod with no_infra given twice, false last",
			target:     podURL,
			body:       pod(`"no_infra":true,"volumes":[{"Name":"theirs-data","Dest":"/data"}],"no_infra":false`),
			wantStatus: http.StatusBadRequest,
			wantReason: `request body denied: duplicate case-variant JSON keys "no_infra" and "no_infra"`,
		},
		{
			name:        "pod with no_infra false naming another owner's volume",
			target:      podURL,
			body:        pod(`"no_infra":false,"volumes":[{"Name":"theirs-data","Dest":"/data"}]`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("volume", "theirs-data", "pod create volumes"),
			wantLookups: []string{"volumes/theirs-data"},
		},
		{
			// The service container is the pod's own reference, infra
			// container or not.
			name:        "pod with no infra container and another owner's service container",
			target:      podURL,
			body:        pod(`"no_infra":true,"serviceContainerID":"theirs-ctr"`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("container", "theirs-ctr", "pod create serviceContainerID"),
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod with no infra container and its own service container",
			target:      podURL,
			body:        pod(`"no_infra":true,"serviceContainerID":"mine-ctr","volumes_from":["theirs-ctr"]`),
			wantStatus:  http.StatusCreated,
			wantLookups: []string{"containers/mine-ctr"},
			wantUses:    []string{"service-container mine-ctr (team-a)"},
		},
		{
			// Podman refuses networks on a pod with no infra container
			// before it looks any of them up.
			name:       "pod with no infra container naming another owner's network",
			target:     podURL,
			body:       pod(`"no_infra":true,"Networks":{"theirs-net":{}}`),
			wantStatus: http.StatusInternalServerError,
		},
		{
			// PodSpecGenerator has no field for either, so Podman drops them
			// and there's nothing to check.
			name:       "pod with references only a container has",
			target:     podURL,
			body:       pod(`"dependencyContainers":["theirs-ctr"],"artifact_volumes":[{"source":"theirs-artifact","destination":"/artifact"}]`),
			wantStatus: http.StatusCreated,
			wantUses:   []string{},
		},
		{
			// A pod spec has no cgroupns either. Its target is checked with
			// the other namespaces all the same.
			name:        "pod with a cgroup namespace in another owner's container",
			target:      podURL,
			body:        pod(`"cgroupns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},

		{
			name:        "container in another owner's pod",
			target:      containerURL,
			body:        container(`"pod":"theirs-pod"`),
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("pod", "theirs-pod", "libpod container create pod"),
			wantLookups: []string{alpine, "pods/theirs-pod"},
		},
		{
			name:        "container from another owner's image",
			target:      containerURL,
			body:        `{"image":"theirs-img","systemd":"false"}`,
			wantStatus:  http.StatusForbidden,
			wantReason:  denied("image", "theirs-img", "libpod container create image"),
			wantLookups: []string{"images/theirs-img"},
		},
		{
			name:        "container in another owner's network namespace",
			target:      containerURL,
			body:        container(`"netns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "container in another owner's PID namespace",
			target:      containerURL,
			body:        container(`"pidns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "container in another owner's IPC namespace",
			target:      containerURL,
			body:        container(`"ipcns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "container in another owner's UTS namespace",
			target:      containerURL,
			body:        container(`"utsns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "container in another owner's user namespace",
			target:      containerURL,
			body:        container(`"userns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod in another owner's PID namespace",
			target:      podURL,
			body:        pod(`"pidns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod in another owner's IPC namespace",
			target:      podURL,
			body:        pod(`"ipcns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod in another owner's UTS namespace",
			target:      podURL,
			body:        pod(`"utsns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			name:        "pod in another owner's user namespace",
			target:      podURL,
			body:        pod(`"userns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
		{
			// Podman refuses a pod whose netns joins a container anyway.
			name:        "pod in another owner's network namespace",
			target:      podURL,
			body:        pod(`"netns":{"nsmode":"container","value":"theirs-ctr"}`),
			wantStatus:  http.StatusForbidden,
			wantReason:  deniedTarget,
			wantLookups: []string{theirsCtr},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newLibpodCreateRefChainDaemon()
			wantOwner := "team-a"
			addr := newEngineChain(t, "create-ref", daemon, func(cfg *config.Config) {
				cfg.Response.DenyVerbosity = "verbose"
				cfg.Ownership.Owner = "team-a"
				if tt.owner == "none" {
					cfg.Ownership.Owner, wantOwner = "", ""
				}
				cfg.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/pods/create"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
				}
				if tt.rollout != "" {
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "rollout", Mode: tt.rollout, Rules: cfg.Rules}}
					cfg.Clients.DefaultProfile = "rollout"
				}
			})

			status, body := postLibpodCreateRefChainJSON(t, "http://"+addr+tt.target, tt.body)

			created := daemon.made()
			switch {
			case tt.wantUses == nil && len(created) != 0:
				t.Errorf("daemon created %+v, want nothing", created)
			case tt.wantUses != nil && len(created) != 1:
				t.Errorf("daemon created %+v, want one", created)
			case tt.wantUses != nil:
				if !slices.Equal(created[0].Uses, tt.wantUses) {
					t.Errorf("created %s uses %q, want %q", created[0].Kind, created[0].Uses, tt.wantUses)
				}
				if created[0].Owner != wantOwner {
					t.Errorf("created %s owner = %q, want %q", created[0].Kind, created[0].Owner, wantOwner)
				}
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", status, tt.wantStatus, body)
			}
			if status != http.StatusCreated && strings.Contains(string(body), "team-b") {
				t.Errorf("refusal body names the other owner: %s", body)
			}
			if lookups := daemon.lookedUp(); !slices.Equal(lookups, tt.wantLookups) {
				t.Errorf("owner isolation looked up %q, want %q", lookups, tt.wantLookups)
			}
			assertLibpodCreateRefChainReason(t, tt.wantStatus, tt.wantReason, body)
		})
	}
}

func postLibpodCreateRefChainJSON(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func assertLibpodCreateRefChainReason(t *testing.T, wantStatus int, wantReason string, body []byte) {
	t.Helper()
	if (wantStatus == http.StatusForbidden || wantStatus == http.StatusNotFound) && wantReason == "" {
		t.Fatal("a denied case must name the reason it is denied for")
	}
	if wantReason == "" {
		return
	}
	// Owner isolation answers with the reason as the message. The filter in
	// front of it answers with a fixed message and the reason beside it.
	var denial struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(body, &denial); err != nil || (denial.Message != wantReason && denial.Reason != wantReason) {
		t.Errorf("body = %s, want message or reason %q", body, wantReason)
	}
}
