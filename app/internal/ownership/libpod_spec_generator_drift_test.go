package ownership

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/testhelp/podmanspec"
)

// This file is the drift guard for the references owner isolation reads out of
// POST /libpod/containers/create.
//
// Owner isolation reads a fixed list of SpecGenerator fields (see
// libpodContainerCreateReferences). A field Podman adds later that names an
// existing resource would reach the daemon unchecked, and nothing would say so.
// Every root field of the pinned SpecGenerator is classified below as one that
// names an existing resource, one that names a host path (the request-body
// inspector's job), or one that names nothing, and a field that appears in the
// snapshot without a classification fails the test. Refreshing the snapshot to
// a newer Podman is where that failure shows up.

const (
	libpodSpecGeneratorSnapshotPath    = "../../testdata/podman-api/spec-generator-root-fields.json"
	libpodPodSpecGeneratorSnapshotPath = "../../testdata/podman-api/pod-spec-generator-root-fields.json"
)

// specGeneratorReferenceFields are the SpecGenerator fields that name an
// existing container, pod, network, volume, image, artifact or secret. The
// value is a body fragment naming one; TestLibpodSpecGeneratorReferenceFields
// AreRead checks that each draws a lookup or a refusal.
var specGeneratorReferenceFields = map[string]string{
	"pod":                  `"pod":"p"`,
	"image":                `"image":"i"`,
	"volumes":              `"volumes":[{"Name":"v","Dest":"/d"}]`,
	"volumes_from":         `"volumes_from":["c"]`,
	"image_volumes":        `"image_volumes":[{"Source":"i","Destination":"/d"}]`,
	"artifact_volumes":     `"artifact_volumes":[{"source":"a","destination":"/d"}]`,
	"Networks":             `"Networks":{"n":{}}`,
	"dependencyContainers": `"dependencyContainers":["c"]`,
	"cgroupns":             `"cgroupns":{"nsmode":"container","value":"c"}`,
	"ipcns":                `"ipcns":{"nsmode":"container","value":"c"}`,
	"netns":                `"netns":{"nsmode":"container","value":"c"}`,
	"pidns":                `"pidns":{"nsmode":"container","value":"c"}`,
	"userns":               `"userns":{"nsmode":"container","value":"c"}`,
	"utsns":                `"utsns":{"nsmode":"container","value":"c"}`,
	"secrets":              `"secrets":[{"Source":"s"}]`,
	"secret_env":           `"secret_env":{"E":"s"}`,
}

// specGeneratorRetiredReferenceFields are references Podman removed from the
// SpecGenerator after the oldest line Sockguard still fronts. The pinned
// snapshot no longer carries them, but a Podman that still decodes one would
// resolve it, so the mutator keeps reading it and the read test keeps checking
// that. "cni_networks" is gone at v6.2.0 (Podman 5.8.1 had it).
var specGeneratorRetiredReferenceFields = map[string]string{
	"cni_networks": `"cni_networks":["n"]`,
}

// specGeneratorHostPathFields name something on the daemon host or a runtime
// object with no owner label. The request-body inspector holds them to
// allowed_bind_mounts or refuses them; owner isolation has nothing to look up.
// "devices_from" is decoded and never read by Podman 5.8.1.
var specGeneratorHostPathFields = []string{
	"rootfs", "rootfs_overlay", "rootfs_mapping", "rootfs_propagation", "overlay_volumes", "mounts",
	"devices", "devices_from", "host_device_list", "init_path", "base_hosts_file", "seccomp_profile_path",
	"conmon_pid_file", "cgroup_parent", "oci_runtime", "chroot_directories", "healthLogDestination",
	"log_configuration", "storage_opts", "unified",
	// gpus is resolved to CDI device paths on the host; the create inspector
	// holds it to allow_device_requests. seccomp_profile is the inline profile
	// Podman 6.2 reads ahead of seccomp_profile_path; the inspector holds it to
	// deny_unconfined_seccomp and allowed_seccomp_profiles.
	"gpus", "seccomp_profile",
}

// specGeneratorInertFields name no existing resource: scalar settings, lists of
// literals and maps whose keys are not resource names.
var specGeneratorInertFields = []string{
	"annotations", "apparmor_profile", "cap_add", "cap_drop", "cgroups_mode", "command",
	"containerCreateCommand", "create_working_dir", "device_cgroup_rule", "dns_option", "dns_search",
	"dns_server", "entrypoint", "env", "env_host", "envmerge", "expose", "group_entry", "groups",
	"healthMaxLogCount", "healthMaxLogSize", "health_check_on_failure_action", "healthconfig",
	"hostadd", "hostname", "hostusers", "httpproxy", "idmappings", "image_arch", "image_os",
	"image_variant", "image_volume_mode", "init", "init_container_type", "intelRdt", "label_nested",
	"labels", "manage_password", "mask", "name", "networkOrder", "network_options", "no_new_privileges", "oom_score_adj",
	"passwd_entry", "personality", "portmappings", "privileged", "procfs_opts", "publish_image_ports",
	"r_limits", "raw_image_name", "read_only_filesystem", "read_write_tmpfs", "remove", "removeImage",
	"resource_limits", "restart_policy", "restart_tries", "sdnotifyMode", "seccomp_policy",
	"selinux_opts", "shm_size", "shm_size_systemd", "startupHealthConfig", "stdin", "stop_signal",
	"stop_timeout", "sysctl", "systemd", "terminal", "throttleReadBpsDevice", "throttleReadIOPSDevice",
	"throttleWriteBpsDevice", "throttleWriteIOPSDevice", "timeout", "timezone", "umask", "unmask",
	"unsetenv", "unsetenvall", "use_image_hostname", "use_image_hosts", "use_image_resolve_conf", "user",
	"volatile", "weightDevice", "work_dir",
}

func readLibpodRootFieldSnapshot(t *testing.T, path string) (tag string, fields []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var snapshot struct {
		PodmanTag  string   `json:"podman_tag"`
		RootFields []string `json:"root_fields"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if snapshot.PodmanTag == "" || len(snapshot.RootFields) == 0 {
		t.Fatalf("%s records no podman_tag or no root_fields", path)
	}
	return snapshot.PodmanTag, snapshot.RootFields
}

// TestLibpodSpecGeneratorFieldsAreAllClassified fails when the pinned
// SpecGenerator and the three classifications disagree in either direction,
// naming every field that moved. A field only in the snapshot is the
// dangerous direction: if it names an existing resource, a create can reach
// that resource with no owner check.
func TestLibpodSpecGeneratorFieldsAreAllClassified(t *testing.T) {
	references := make([]string, 0, len(specGeneratorReferenceFields))
	for field := range specGeneratorReferenceFields {
		references = append(references, field)
	}
	checkLibpodRootFieldsClassified(t, "SpecGenerator", libpodSpecGeneratorSnapshotPath, "specGeneratorReferenceFields", "specGeneratorHostPathFields", "specGeneratorInertFields",
		references, specGeneratorHostPathFields, specGeneratorInertFields, mapKeys(specGeneratorRetiredReferenceFields))
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// checkLibpodRootFieldsClassified compares one snapshot with its three
// classifications. retired fields are classified but absent from the snapshot
// on purpose, so the stale check skips them.
func checkLibpodRootFieldsClassified(t *testing.T, rootType, snapshotPath, referenceName, hostPathName, inertName string, references, hostPaths, inert, retired []string) {
	t.Helper()
	tag, snapshot := readLibpodRootFieldSnapshot(t, snapshotPath)

	classified := map[string]string{}
	add := func(class, field string) {
		folded := strings.ToLower(field)
		if previous, ok := classified[folded]; ok {
			t.Errorf("%q is classified twice (%s and %s)", field, previous, class)
		}
		classified[folded] = class
	}
	for _, field := range references {
		add("reference", field)
	}
	for _, field := range hostPaths {
		add("host path", field)
	}
	for _, field := range inert {
		add("inert", field)
	}
	retiredFolded := map[string]bool{}
	for _, field := range retired {
		retiredFolded[strings.ToLower(field)] = true
	}

	upstream := map[string]bool{}
	var unclassified []string
	for _, field := range snapshot {
		folded := strings.ToLower(field)
		upstream[folded] = true
		if _, ok := classified[folded]; !ok {
			unclassified = append(unclassified, field)
		}
	}
	if len(unclassified) > 0 {
		slices.Sort(unclassified)
		t.Errorf("Podman %s %s carries root field(s) owner isolation has not classified: %s.\n"+
			"If one names an existing container, pod, network, volume, image, artifact or secret, add it to %s and make the create reference reader (or the mutator) look it up. If it names a host path, add it to %s and check the request-body inspector holds it. Otherwise add it to %s. %s is the pinned upstream set.",
			tag, rootType, strings.Join(unclassified, ", "), referenceName, hostPathName, inertName, snapshotPath)
	}

	var stale []string
	for folded := range classified {
		if !upstream[folded] && !retiredFolded[folded] {
			stale = append(stale, folded)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		t.Errorf("classifications name root field(s) Podman %s %s does not have: %s. Fix the spelling or drop the entry, and refresh %s if the removal is real.",
			tag, rootType, strings.Join(stale, ", "), snapshotPath)
	}
}

// TestLibpodSpecGeneratorReferenceFieldsAreRead pins that every field classified
// as a reference draws a lookup or a refusal from the container-create
// mutator, so the classification can't claim a field the code doesn't read.
func TestLibpodSpecGeneratorReferenceFieldsAreRead(t *testing.T) {
	fragments := map[string]string{}
	for field, fragment := range specGeneratorReferenceFields {
		fragments[field] = fragment
	}
	for field, fragment := range specGeneratorRetiredReferenceFields {
		fragments[field] = fragment
	}
	for field, fragment := range fragments {
		t.Run(field, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://docker/libpod/containers/create", strings.NewReader("{"+fragment+"}"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			refs, err := mutateLibpodContainerCreateOwnershipBody(req, DefaultLabelKey, "team-a")
			if err != nil {
				t.Fatalf("mutateLibpodContainerCreateOwnershipBody() error = %v", err)
			}
			read := len(refs.namespaceContainers) > 0 || len(refs.embeddedResources) > 0 || refs.denyReason != "" ||
				refs.libpodCreate.count() > 0 || (refs.libpodCreate != nil && refs.libpodCreate.denyReason != "")
			if !read {
				t.Errorf("a create with %s draws no lookup and no refusal from owner isolation", fragment)
			}
		})
	}
}

// TestLibpodSpecGeneratorSnapshotMatchesUpstreamPodman re-derives the
// SpecGenerator root field set from Podman's own source at
// SOCKGUARD_TEST_PODMAN_UPSTREAM_REF and fails when it disagrees with the
// committed snapshot. Skipped without the env var, so the rest of the suite
// stays offline.
func TestLibpodSpecGeneratorSnapshotMatchesUpstreamPodman(t *testing.T) {
	checkLibpodRootFieldSnapshotAgainstUpstream(t, libpodSpecGeneratorSnapshotPath, "pkg/specgen/specgen.go", "SpecGenerator")
}

// TestLibpodPodSpecGeneratorSnapshotMatchesUpstreamPodman is the same check for
// the PodSpecGenerator behind POST /libpod/pods/create.
func TestLibpodPodSpecGeneratorSnapshotMatchesUpstreamPodman(t *testing.T) {
	checkLibpodRootFieldSnapshotAgainstUpstream(t, libpodPodSpecGeneratorSnapshotPath, "pkg/specgen/podspecgen.go", "PodSpecGenerator")
}

func checkLibpodRootFieldSnapshotAgainstUpstream(t *testing.T, snapshotPath, upstreamFile, rootType string) {
	t.Helper()

	ref := podmanspec.UpstreamRef()
	if ref == "" {
		t.Skipf("set %s to a containers/podman ref (a tag such as v6.2.0, or main) to check %s against upstream; this test fetches over the network", podmanspec.RefEnvVar, snapshotPath)
	}
	tag, recorded := readLibpodRootFieldSnapshot(t, snapshotPath)

	ctx, cancel := context.WithTimeout(t.Context(), podmanspec.FetchTimeout)
	defer cancel()

	owners := podmanspec.ParseStructs(t, podmanspec.FetchSource(ctx, t, "containers/podman", ref, upstreamFile))
	if _, ok := owners[rootType]; !ok {
		t.Fatalf("containers/podman@%s no longer declares %s in %s; the request body has been restructured and %s must be regenerated by hand", ref, rootType, upstreamFile, snapshotPath)
	}

	fields := map[string]struct{}{}
	podmanspec.FlattenRootFields(t, rootType, owners, map[string]bool{}, fields)

	upstream, added, removed, equal := podmanspec.DiffSorted(fields, recorded)
	if equal {
		return
	}
	t.Errorf("containers/podman@%s %s no longer matches %s (pinned at %s).\nAdded upstream: %s\nGone upstream: %s\nUpdate the snapshot's root_fields to the sorted list below, classify every new field in this file, and re-run the offline drift test:\n%s",
		ref, rootType, snapshotPath, tag,
		podmanspec.JoinOrNone(added), podmanspec.JoinOrNone(removed), podmanspec.FormatRootFields(upstream))
}

// podSpecGeneratorReferenceFields are the PodSpecGenerator fields that name an
// existing resource, with a body fragment naming one. Podman copies the pod
// spec onto its infra container, so the first group resolves exactly as a
// container create's does. infra_image is looked up as an image,
// serviceContainerID as a container, and the namespace objects as the
// container they join.
var podSpecGeneratorReferenceFields = map[string]string{
	"volumes_from":       `"volumes_from":["c"]`,
	"volumes":            `"volumes":[{"Name":"v","Dest":"/d"}]`,
	"image_volumes":      `"image_volumes":[{"Source":"i","Destination":"/d"}]`,
	"Networks":           `"Networks":{"n":{}}`,
	"serviceContainerID": `"serviceContainerID":"c"`,
	"infra_image":        `"infra_image":"i"`,
	"ipcns":              `"ipcns":{"nsmode":"container","value":"c"}`,
	"netns":              `"netns":{"nsmode":"container","value":"c"}`,
	"pidns":              `"pidns":{"nsmode":"container","value":"c"}`,
	"userns":             `"userns":{"nsmode":"container","value":"c"}`,
	"utsns":              `"utsns":{"nsmode":"container","value":"c"}`,
}

// podSpecGeneratorHostPathFields name something on the daemon host, or carry a
// policy the request-body inspector (internal/filter, libpod_pod_create.go and
// libpod_pod_create_inherited.go) holds: they land on the infra container and
// are inherited by every member.
var podSpecGeneratorHostPathFields = []string{
	"mounts", "overlay_volumes", "pod_devices", "cgroup_parent", "infra_conmon_pid_file", "hostsFile",
	"security_opt", "idmappings", "sysctl", "resource_limits", "shared_namespaces",
}

// podSpecGeneratorInertFields name no existing resource. "labels" is where
// the owner label is injected, which the mutator does for every pod create.
var podSpecGeneratorInertFields = []string{
	"dns_option", "dns_search", "dns_server", "exit_policy", "hostadd", "hostname", "infra_command",
	"infra_name", "labels", "name", "network_options", "no_infra", "no_manage_hostname", "no_manage_hosts",
	"no_manage_resolv_conf", "pod_create_command", "portmappings", "restart_policy", "restart_tries",
	"share_parent", "shm_size", "shm_size_systemd",
}

// TestLibpodPodSpecGeneratorFieldsAreAllClassified is the pod-create twin of
// TestLibpodSpecGeneratorFieldsAreAllClassified.
func TestLibpodPodSpecGeneratorFieldsAreAllClassified(t *testing.T) {
	references := make([]string, 0, len(podSpecGeneratorReferenceFields))
	for field := range podSpecGeneratorReferenceFields {
		references = append(references, field)
	}
	checkLibpodRootFieldsClassified(t, "PodSpecGenerator", libpodPodSpecGeneratorSnapshotPath, "podSpecGeneratorReferenceFields", "podSpecGeneratorHostPathFields", "podSpecGeneratorInertFields",
		references, podSpecGeneratorHostPathFields, podSpecGeneratorInertFields, nil)
}

// TestLibpodPodSpecGeneratorReferenceFieldsAreRead pins that every pod field
// classified as a reference draws a lookup or a refusal from the pod-create
// mutator.
func TestLibpodPodSpecGeneratorReferenceFieldsAreRead(t *testing.T) {
	for field, fragment := range podSpecGeneratorReferenceFields {
		t.Run(field, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://docker/libpod/pods/create", strings.NewReader("{"+fragment+"}"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			refs, err := mutateLibpodPodCreateOwnershipBody(req, DefaultLabelKey, "team-a")
			if err != nil {
				t.Fatalf("mutateLibpodPodCreateOwnershipBody() error = %v", err)
			}
			read := len(refs.namespaceContainers) > 0 || len(refs.embeddedResources) > 0 || refs.denyReason != "" ||
				refs.libpodCreate.count() > 0 || (refs.libpodCreate != nil && refs.libpodCreate.denyReason != "")
			if !read {
				t.Errorf("a pod create with %s draws no lookup and no refusal from owner isolation", fragment)
			}
		})
	}
}
