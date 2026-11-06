package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLibpodPodCreateInheritedFieldsUseTheContainerGates(t *testing.T) {
	tests := []struct {
		name       string
		container  LibpodContainerCreateOptions
		body       string
		wantReason string
	}{
		{name: "no inherited fields", body: `{"name":"p"}`},
		{name: "image allowlist without image volumes", container: LibpodContainerCreateOptions{AllowedImages: []string{"alpine:3"}}, body: `{"name":"p"}`},
		{name: "bind mount refused by default", body: `{"mounts":[{"type":"bind","source":"/etc","destination":"/h"}]}`, wantReason: `libpod pod create denied: bind mount source "/etc" is not allowlisted`},
		{name: "bind mount on the allowlist", container: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv"}}, body: `{"mounts":[{"type":"bind","source":"/srv/data","destination":"/d"}]}`},
		{name: "bind mount off the allowlist", container: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv"}}, body: `{"mounts":[{"type":"bind","source":"/etc","destination":"/d"}]}`, wantReason: `libpod pod create denied: bind mount source "/etc" is not allowlisted`},
		{name: "relative bind source", container: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv"}}, body: `{"mounts":[{"type":"bind","source":"../etc","destination":"/d"}]}`, wantReason: `libpod pod create denied: bind mount source "../etc" is not an absolute path`},
		{name: "rbind option on another type", body: `{"mounts":[{"type":"none","source":"/","destination":"/h","options":["rbind"]}]}`, wantReason: `libpod pod create denied: bind mount source "/" is not allowlisted`},
		{name: "tmpfs mount with noexec", body: `{"mounts":[{"type":"tmpfs","destination":"/t","options":["noexec"]}]}`},
		{name: "tmpfs mount without noexec refused", body: `{"mounts":[{"type":"tmpfs","destination":"/t"}]}`, wantReason: "libpod pod create denied: a tmpfs on a Podman upstream must set noexec: use --tmpfs /t:noexec or set request_body.libpod_container_create.allow_tmpfs_privileged_options"},
		{name: "tmpfs mount without noexec allowed with opt-in", container: LibpodContainerCreateOptions{AllowTmpfsPrivilegedOptions: true}, body: `{"mounts":[{"type":"tmpfs","destination":"/t"}]}`},
		{name: "device refused by default", body: `{"pod_devices":["/dev/fuse"]}`, wantReason: `libpod pod create denied: device "/dev/fuse" is not allowlisted`},
		{name: "device on the allowlist", container: LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/fuse"}}, body: `{"pod_devices":["/dev/fuse:/dev/fuse:rwm"]}`},
		{name: "all devices", container: LibpodContainerCreateOptions{AllowAllDevices: true}, body: `{"pod_devices":["/dev/mem"]}`},
		{name: "sysctl refused by default", body: `{"sysctl":{"net.ipv4.ip_forward":"1"}}`, wantReason: "libpod pod create denied: setting sysctls is not allowed"},
		{name: "sysctl allowed", container: LibpodContainerCreateOptions{AllowSysctls: true}, body: `{"sysctl":{"net.ipv4.ip_forward":"1"}}`},
		{name: "uid map refused by default", body: `{"idmappings":{"UIDMap":[{"container_id":0,"host_id":0,"size":65536}]}}`, wantReason: "libpod pod create denied: custom UID/GID mappings are not allowed (set allow_custom_id_mappings: true)"},
		{name: "gid map refused by default", body: `{"idmappings":{"GIDMap":[{"container_id":0,"host_id":0,"size":1}]}}`, wantReason: "libpod pod create denied: custom UID/GID mappings are not allowed (set allow_custom_id_mappings: true)"},
		{name: "auto userns mapping refused by default", body: `{"idmappings":{"AutoUserNs":true}}`, wantReason: "libpod pod create denied: custom UID/GID mappings are not allowed (set allow_custom_id_mappings: true)"},
		{name: "uid map allowed with opt-in", container: LibpodContainerCreateOptions{AllowCustomIDMappings: true}, body: `{"idmappings":{"UIDMap":[{"container_id":0,"host_id":0,"size":65536}]}}`},
		{name: "default idmappings pass", body: `{"idmappings":{"HostUIDMapping":true,"HostGIDMapping":true}}`},
		{name: "empty sysctl map", body: `{"sysctl":{}}`},
		{name: "unconfined seccomp passes with no gate", body: `{"security_opt":["seccomp=unconfined"]}`},
		{name: "unconfined seccomp denied", container: LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, body: `{"security_opt":["seccomp=unconfined"]}`, wantReason: "libpod pod create denied: unconfined seccomp profile is not allowed"},
		{name: "unconfined seccomp, colon spelling", container: LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, body: `{"security_opt":["seccomp:Unconfined"]}`, wantReason: "libpod pod create denied: unconfined seccomp profile is not allowed"},
		{name: "seccomp profile off the list", container: LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"default"}}, body: `{"security_opt":["seccomp=/tmp/p.json"]}`, wantReason: `libpod pod create denied: seccomp profile "/tmp/p.json" is not in the allowed list`},
		{name: "seccomp profile on the list", container: LibpodContainerCreateOptions{AllowedSeccompProfiles: []string{"/etc/p.json"}}, body: `{"security_opt":["seccomp=/etc/p.json"]}`},
		{name: "unconfined apparmor denied", container: LibpodContainerCreateOptions{DenyUnconfinedAppArmor: true}, body: `{"security_opt":["apparmor=unconfined"]}`, wantReason: "libpod pod create denied: unconfined apparmor profile is not allowed"},
		{name: "apparmor profile off the list", container: LibpodContainerCreateOptions{AllowedAppArmorProfiles: []string{"default"}}, body: `{"security_opt":["apparmor=custom"]}`, wantReason: `libpod pod create denied: apparmor profile "custom" is not in the allowed list`},
		{name: "selinux disable denied", container: LibpodContainerCreateOptions{DenySelinuxDisable: true}, body: `{"security_opt":["label=disable"]}`, wantReason: "libpod pod create denied: selinux disable is not allowed"},
		{name: "selinux disable, colon spelling", container: LibpodContainerCreateOptions{DenySelinuxDisable: true}, body: `{"security_opt":["label:disable"]}`, wantReason: "libpod pod create denied: selinux disable is not allowed"},
		{name: "selinux type label passes", container: LibpodContainerCreateOptions{DenySelinuxDisable: true}, body: `{"security_opt":["label=type:spc_t"]}`},
		{name: "unmask denied", container: LibpodContainerCreateOptions{DenyUnconfinedSystemPaths: true}, body: `{"security_opt":["unmask=ALL"]}`, wantReason: "libpod pod create denied: unmask (systempaths=unconfined equivalent) is not allowed"},
		{name: "unmask without the gate", body: `{"security_opt":["unmask=ALL"]}`},
		{name: "no-new-privileges passes", container: LibpodContainerCreateOptions{DenyUnconfinedSeccomp: true}, body: `{"security_opt":["no-new-privileges"]}`},
		{name: "joining a container passes while sharing is unrestricted", body: `{"netns":{"nsmode":"container","value":"victim"}}`},
		{name: "joining a container refused while restricted", container: LibpodContainerCreateOptions{RestrictNamespaceSharing: true}, body: `{"netns":{"nsmode":"container","value":"victim"}}`, wantReason: "libpod pod create denied: network namespace sharing with another container is not allowed"},
		{name: "joining a listed container", container: LibpodContainerCreateOptions{RestrictNamespaceSharing: true, AllowedNamespaceSharingContainers: []string{"proxy"}}, body: `{"utsns":{"nsmode":"container","value":"proxy"}}`},
		{name: "joining an unlisted container", container: LibpodContainerCreateOptions{RestrictNamespaceSharing: true, AllowedNamespaceSharingContainers: []string{"proxy"}}, body: `{"pidns":{"nsmode":"container","value":"victim"}}`, wantReason: `libpod pod create denied: namespace-sharing target "victim" is not in the allowed list`},
		{name: "ipc and user namespaces are covered", container: LibpodContainerCreateOptions{RestrictNamespaceSharing: true}, body: `{"userns":{"nsmode":"container","value":"victim"}}`, wantReason: "libpod pod create denied: user namespace sharing with another container is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{Container: tt.container})
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("inspect() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestLibpodPodCreateOptionsWithContainerCarriesTheContainerBlock pins the
// wiring: the pod inspector built by the middleware reads the container
// create options.
func TestLibpodPodCreateOptionsWithContainerCarriesTheContainerBlock(t *testing.T) {
	cfg := PolicyConfig{
		LibpodContainerCreate: LibpodContainerCreateOptions{AllowSysctls: true},
		LibpodPodCreate:       LibpodPodCreateOptions{AllowHostNetwork: true},
	}
	opts := libpodPodCreateOptionsWithContainer(cfg)
	if !opts.Container.AllowSysctls || !opts.AllowHostNetwork {
		t.Fatalf("options = %+v, want both blocks carried", opts)
	}
}

func TestLibpodPodCreateInheritedVolumeFieldsUseTheContainerGates(t *testing.T) {
	tests := []struct {
		name         string
		container    LibpodContainerCreateOptions
		body         string
		wantContains string
	}{
		{name: "overlay volume source off the allowlist", body: `{"overlay_volumes":[{"source":"/etc","destination":"/o"}]}`, wantContains: `libpod pod create denied: overlay volume source "/etc" is not allowlisted`},
		{name: "overlay volume source on the allowlist", container: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv"}}, body: `{"overlay_volumes":[{"source":"/srv/a","destination":"/o"}]}`},
		{name: "overlay volume upperdir off the allowlist", container: LibpodContainerCreateOptions{AllowedBindMounts: []string{"/srv"}}, body: `{"overlay_volumes":[{"source":"/srv/a","destination":"/o","options":["upperdir=/etc"]}]}`, wantContains: "libpod pod create denied"},
		{name: "named volume overlay upperdir off the allowlist", body: `{"volumes":[{"Name":"v","Dest":"/v","Options":["O","upperdir=/etc","workdir=/etc"]}]}`, wantContains: "libpod pod create denied"},
		{name: "named volume without host options", body: `{"volumes":[{"Name":"v","Dest":"/v"}]}`},
		{name: "volumes_from refused", body: `{"volumes_from":["other"]}`, wantContains: "libpod pod create denied: VolumesFrom is not allowed"},
		{name: "cgroup_parent refused", body: `{"cgroup_parent":"/system.slice"}`, wantContains: "libpod pod create denied: custom cgroup parent is not allowed"},
		{name: "device cgroup rule in resource_limits refused", body: `{"resource_limits":{"devices":[{"allow":true,"type":"a","access":"rwm"}]}}`, wantContains: "libpod resource_limits.devices"},
		{name: "memory limit not required on a pod", container: LibpodContainerCreateOptions{RequireMemoryLimit: true, RequireCPULimit: true, RequireCPULimitHard: true}, body: `{"name":"p"}`},
		{name: "memory limit set", container: LibpodContainerCreateOptions{RequireMemoryLimit: true}, body: `{"resource_limits":{"memory":{"limit":1048576}}}`},
		{name: "pids limit not required on a pod", container: LibpodContainerCreateOptions{RequirePidsLimit: true}, body: `{"resource_limits":{}}`},
		{name: "image volume refused with allowed_images", container: LibpodContainerCreateOptions{AllowedImages: []string{"docker.io/library/alpine:3"}}, body: `{"image_volumes":[{"source":"x","destination":"/i"}]}`, wantContains: "libpod pod create denied: image volumes are not supported with allowed_images"},
		{name: "image mount refused with allowed_images", container: LibpodContainerCreateOptions{AllowedImages: []string{"docker.io/library/alpine:3"}}, body: `{"mounts":[{"type":"image","source":"x","destination":"/i"}]}`, wantContains: "libpod pod create denied: mount type \"image\" is not supported"},
		{name: "image volume passes without allowed_images", body: `{"image_volumes":[{"source":"x","destination":"/i"}]}`},
		{name: "systempaths=unconfined denied", container: LibpodContainerCreateOptions{DenyUnconfinedSystemPaths: true}, body: `{"security_opt":["systempaths=unconfined"]}`, wantContains: "systempaths=unconfined (unmask) is not allowed"},
		{name: "systempaths colon spelling denied", container: LibpodContainerCreateOptions{DenyUnconfinedSystemPaths: true}, body: `{"security_opt":["systempaths:Unconfined"]}`, wantContains: "systempaths=unconfined"},
		{name: "systempaths=unconfined without the gate", body: `{"security_opt":["systempaths=unconfined"]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newLibpodPodCreatePolicy(LibpodPodCreateOptions{Container: tt.container})
			req := httptest.NewRequest(http.MethodPost, "/libpod/pods/create", strings.NewReader(tt.body))
			reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if tt.wantContains == "" && reason != "" || !strings.Contains(reason, tt.wantContains) {
				t.Fatalf("inspect() reason = %q, want it to contain %q", reason, tt.wantContains)
			}
		})
	}
}
