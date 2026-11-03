package ownership

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
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

const libpodSpecGeneratorSnapshotPath = "../../testdata/podman-api/spec-generator-root-fields.json"

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
	"cni_networks":         `"cni_networks":["n"]`,
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

// specGeneratorHostPathFields name something on the daemon host or a runtime
// object with no owner label. The request-body inspector holds them to
// allowed_bind_mounts or refuses them; owner isolation has nothing to look up.
// "devices_from" is decoded and never read by Podman 5.8.1.
var specGeneratorHostPathFields = []string{
	"rootfs", "rootfs_overlay", "rootfs_mapping", "rootfs_propagation", "overlay_volumes", "mounts",
	"devices", "devices_from", "host_device_list", "init_path", "base_hosts_file", "seccomp_profile_path",
	"conmon_pid_file", "cgroup_parent", "oci_runtime", "chroot_directories", "healthLogDestination",
	"log_configuration", "storage_opts", "unified",
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
	"labels", "manage_password", "mask", "name", "network_options", "no_new_privileges", "oom_score_adj",
	"passwd_entry", "personality", "portmappings", "privileged", "procfs_opts", "publish_image_ports",
	"r_limits", "raw_image_name", "read_only_filesystem", "read_write_tmpfs", "remove", "removeImage",
	"resource_limits", "restart_policy", "restart_tries", "sdnotifyMode", "seccomp_policy",
	"selinux_opts", "shm_size", "shm_size_systemd", "startupHealthConfig", "stdin", "stop_signal",
	"stop_timeout", "sysctl", "systemd", "terminal", "throttleReadBpsDevice", "throttleReadIOPSDevice",
	"throttleWriteBpsDevice", "throttleWriteIOPSDevice", "timeout", "timezone", "umask", "unmask",
	"unsetenv", "unsetenvall", "use_image_hostname", "use_image_hosts", "use_image_resolve_conf", "user",
	"volatile", "weightDevice", "work_dir",
}

func readLibpodSpecGeneratorSnapshot(t *testing.T) (tag string, fields []string) {
	t.Helper()
	raw, err := os.ReadFile(libpodSpecGeneratorSnapshotPath)
	if err != nil {
		t.Fatalf("read %s: %v", libpodSpecGeneratorSnapshotPath, err)
	}
	var snapshot struct {
		PodmanTag  string   `json:"podman_tag"`
		RootFields []string `json:"root_fields"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode %s: %v", libpodSpecGeneratorSnapshotPath, err)
	}
	if snapshot.PodmanTag == "" || len(snapshot.RootFields) == 0 {
		t.Fatalf("%s records no podman_tag or no root_fields", libpodSpecGeneratorSnapshotPath)
	}
	return snapshot.PodmanTag, snapshot.RootFields
}

// TestLibpodSpecGeneratorFieldsAreAllClassified fails when the pinned
// SpecGenerator and the three classifications disagree in either direction,
// naming every field that moved. A field only in the snapshot is the
// dangerous direction: if it names an existing resource, a create can reach
// that resource with no owner check.
func TestLibpodSpecGeneratorFieldsAreAllClassified(t *testing.T) {
	tag, snapshot := readLibpodSpecGeneratorSnapshot(t)

	classified := map[string]string{}
	add := func(class, field string) {
		folded := strings.ToLower(field)
		if previous, ok := classified[folded]; ok {
			t.Errorf("%q is classified twice (%s and %s)", field, previous, class)
		}
		classified[folded] = class
	}
	for field := range specGeneratorReferenceFields {
		add("reference", field)
	}
	for _, field := range specGeneratorHostPathFields {
		add("host path", field)
	}
	for _, field := range specGeneratorInertFields {
		add("inert", field)
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
		t.Errorf("Podman %s SpecGenerator carries root field(s) owner isolation has not classified: %s.\n"+
			"If one names an existing container, pod, network, volume, image, artifact or secret, add it to specGeneratorReferenceFields and make libpodContainerCreateReferences (or the mutator) look it up. If it names a host path, add it to specGeneratorHostPathFields and check the request-body inspector holds it. Otherwise add it to specGeneratorInertFields. %s is the pinned upstream set.",
			tag, strings.Join(unclassified, ", "), libpodSpecGeneratorSnapshotPath)
	}

	var stale []string
	for folded := range classified {
		if !upstream[folded] {
			stale = append(stale, folded)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		t.Errorf("classifications name root field(s) Podman %s does not have: %s. Fix the spelling or drop the entry, and refresh %s if the removal is real.",
			tag, strings.Join(stale, ", "), libpodSpecGeneratorSnapshotPath)
	}
}

// TestLibpodSpecGeneratorReferenceFieldsAreRead pins that every field classified
// as a reference draws a lookup or a refusal from the container-create
// mutator, so the classification can't claim a field the code doesn't read.
func TestLibpodSpecGeneratorReferenceFieldsAreRead(t *testing.T) {
	for field, fragment := range specGeneratorReferenceFields {
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
