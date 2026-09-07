package filter

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestLocalVolumeBindDevices pins the detection rule on its own: which local
// driver options maps name a host path the daemon will bind-mount, and which
// are ordinary volumes the bind allowlist must leave alone.
func TestLocalVolumeBindDevices(t *testing.T) {
	tests := []struct {
		name    string
		driver  string
		options map[string]string
		want    []string
	}{
		{
			name:    "type none with o bind",
			driver:  "local",
			options: map[string]string{"type": "none", "o": "bind", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "empty driver defaults to local",
			options: map[string]string{"type": "none", "o": "bind", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "driver name is case-insensitive",
			driver:  "Local",
			options: map[string]string{"type": "none", "o": "bind", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "o bind alone without a type",
			driver:  "local",
			options: map[string]string{"o": "bind", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "type none alone without an o",
			driver:  "local",
			options: map[string]string{"type": "none", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "type bind spelled directly",
			driver:  "local",
			options: map[string]string{"type": "bind", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "rbind token among other options",
			driver:  "local",
			options: map[string]string{"type": "ext4", "o": "rw,rbind,noatime", "device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "option keys are case-insensitive",
			driver:  "local",
			options: map[string]string{"Type": "none", "O": "bind", "Device": "/host/path"},
			want:    []string{"/host/path"},
		},
		{
			name:    "every device spelling is reported, sorted",
			driver:  "local",
			options: map[string]string{"o": "bind", "device": "/host/second", "Device": "/host/first"},
			want:    []string{"/host/first", "/host/second"},
		},
		{
			name:    "tmpfs options are not a bind",
			driver:  "local",
			options: map[string]string{"type": "tmpfs", "o": "size=100m,uid=1000", "device": "tmpfs"},
		},
		{
			name:    "nfs address containing bind is not a bind token",
			driver:  "local",
			options: map[string]string{"type": "nfs", "o": "addr=bind.example.com,rw", "device": ":/exports/data"},
		},
		{
			name:    "size-only quota options are not a bind",
			driver:  "local",
			options: map[string]string{"size": "10g"},
		},
		{
			name:    "non-local driver is untouched",
			driver:  "rexray",
			options: map[string]string{"type": "none", "o": "bind", "device": "/host/path"},
		},
		{
			name:    "bind requested without a device",
			driver:  "local",
			options: map[string]string{"type": "none", "o": "bind"},
		},
		{
			name:   "no options at all",
			driver: "local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := localVolumeBindDevices(tt.driver, tt.options)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("localVolumeBindDevices() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestContainerCreateVolumeMountInlineBind proves a HostConfig.Mounts entry of
// Type "volume" whose VolumeOptions.DriverConfig asks the local driver for a
// bind is checked against AllowedBindMounts exactly as a Type "bind" mount is,
// and that the ordinary volume, tmpfs and third-party-driver cases still pass
// through untouched.
func TestContainerCreateVolumeMountInlineBind(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name: "allowlisted device passes",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/safe/data"}}}}]}}`,
		},
		{
			name:       "device outside the allowlist is denied",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]}}`,
			wantReason: `container create denied: bind mount source "/" is not allowlisted`,
		},
		{
			name:       "traversal out of the allowlist is normalized before the check",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/safe/../etc"}}}}]}}`,
			wantReason: `container create denied: bind mount source "/etc" is not allowlisted`,
		},
		{
			name:       "traversal back into the allowlist passes",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/etc/../safe/data"}}}}]}}`,
			wantReason: "",
		},
		{
			name:       "relative device is denied rather than skipped",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"o":"bind","device":"etc"}}}}]}}`,
			wantReason: `container create denied: bind mount source "etc" is not allowlisted`,
		},
		{
			name:       "empty driver name is still the local driver",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Options":{"type":"none","o":"bind","device":"/denied"}}}}]}}`,
			wantReason: `container create denied: bind mount source "/denied" is not allowlisted`,
		},
		{
			name:       "rbind is a bind",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"o":"rw,rbind","device":"/denied"}}}}]}}`,
			wantReason: `container create denied: bind mount source "/denied" is not allowlisted`,
		},
		{
			name: "non-bind local options are untouched",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"tmpfs","o":"size=100m","device":"tmpfs"}}}}]}}`,
		},
		{
			name: "non-local driver is untouched",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"rexray","Options":{"type":"none","o":"bind","device":"/denied"}}}}]}}`,
		},
		{
			name: "plain named volume without a driver config is untouched",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol"}]}}`,
		},
		{
			name: "allowlisted bind mount still passes",
			body: `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/safe/data"}]}}`,
		},
		{
			name:       "denied bind mount still denies",
			body:       `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/denied"}]}}`,
			wantReason: `container create denied: bind mount source "/denied" is not allowlisted`,
		},
		{
			name: "allowlisted Binds entry is unaffected",
			body: `{"HostConfig":{"Binds":["/safe/data:/data:ro"]}}`,
		},
		{
			name:       "denied Binds entry still denies",
			body:       `{"HostConfig":{"Binds":["/denied:/data:ro"]}}`,
			wantReason: `container create denied: bind mount source "/denied" is not allowlisted`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: []string{"/safe"}})
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestServiceMountInlineBind is the swarm half of the same bypass. A
// ContainerSpec mount of Type "volume" whose VolumeOptions.DriverConfig asks
// the local driver for a bind reaches the host path a Type "bind" mount would,
// so POST /services/create and POST /services/{id}/update check its device
// against service.allowed_bind_mounts exactly as they check a bind source.
func TestServiceMountInlineBind(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantReason string
	}{
		{
			name: "allowlisted device passes on create",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/safe/data"}}}}]}}}`,
		},
		{
			name:       "device outside the allowlist is denied on create",
			path:       "/services/create",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]}}}`,
			wantReason: `service denied: bind mount source "/" is not allowlisted`,
		},
		{
			name:       "device outside the allowlist is denied on update",
			path:       "/v1.53/services/web/update?version=7",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"o":"rw,rbind","device":"/var/run"}}}}]}}}`,
			wantReason: `service denied: bind mount source "/var/run" is not allowlisted`,
		},
		{
			name: "non-bind local options are untouched",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"tmpfs","o":"size=100m","device":"tmpfs"}}}}]}}}`,
		},
		{
			name: "non-local driver is untouched",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"rexray","Options":{"type":"none","o":"bind","device":"/var/run"}}}}]}}}`,
		},
		{
			name: "plain named volume without a driver config is untouched",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol"}]}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newServicePolicy(ServiceOptions{AllowOfficial: true, AllowedBindMounts: []string{"/safe"}})
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestVolumeCreateInlineBind covers the pre-created half of the same bypass:
// POST /volumes/create with the local driver and bind driver options makes a
// named volume that mounts a host path, which a later container-create then
// references by name and the bind allowlist never sees.
func TestVolumeCreateInlineBind(t *testing.T) {
	tests := []struct {
		name       string
		opts       VolumeOptions
		body       string
		wantReason string
	}{
		{
			name:       "driver options stay denied outright when the knob is off",
			opts:       VolumeOptions{AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/safe/data"}}`,
			wantReason: "volume create denied: driver options are not allowed",
		},
		{
			name: "allowlisted device passes",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/safe/data"}}`,
		},
		{
			name:       "device outside the allowlist is denied",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/var/run"}}`,
			wantReason: `volume create denied: bind mount source "/var/run" is not allowlisted`,
		},
		{
			name:       "the Opts spelling is checked too",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Opts":{"type":"none","o":"bind","device":"/var/run"}}`,
			wantReason: `volume create denied: bind mount source "/var/run" is not allowlisted`,
		},
		{
			name:       "an empty allowlist denies every device",
			opts:       VolumeOptions{AllowDriverOpts: true},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/safe/data"}}`,
			wantReason: `volume create denied: bind mount source "/safe/data" is not allowlisted`,
		},
		{
			name: "non-bind local options are untouched",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","DriverOpts":{"type":"tmpfs","o":"size=100m","device":"tmpfs"}}`,
		},
		{
			name: "non-local driver is untouched",
			opts: VolumeOptions{AllowCustomDrivers: true, AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"rexray","DriverOpts":{"type":"none","o":"bind","device":"/var/run"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestLibpodVolumeCreateInlineBind is TestVolumeCreateInlineBind's libpod
// counterpart: Podman's local driver takes the same type/o/device options
// under the "Options" wire key, so the same allowlist applies there.
func TestLibpodVolumeCreateInlineBind(t *testing.T) {
	tests := []struct {
		name       string
		opts       VolumeOptions
		body       string
		wantReason string
	}{
		{
			name: "allowlisted device passes",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","Options":{"type":"none","o":"bind","device":"/safe/data"}}`,
		},
		{
			name:       "device outside the allowlist is denied",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","Options":{"type":"none","o":"bind","device":"/var/run"}}`,
			wantReason: `libpod volume create denied: bind mount source "/var/run" is not allowlisted`,
		},
		{
			name: "non-bind local options are untouched",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","Options":{"type":"tmpfs","o":"size=100m"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(tt.body))

			reason, err := policy.inspectLibpod(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestNewVolumePolicyNormalizesAndDeduplicatesAllowedBindMounts proves the
// volume policy pre-processes its allowlist the same way
// newContainerCreatePolicy does, so the two cannot drift into disagreeing
// about what "/srv/data/" or a repeated entry means.
func TestNewVolumePolicyNormalizesAndDeduplicatesAllowedBindMounts(t *testing.T) {
	policy := newVolumePolicy(VolumeOptions{
		AllowedBindMounts: []string{"/srv/data/", "/srv/data", "relative", "", "/var/lib/../lib/sockguard"},
	})

	want := []string{"/srv/data", "/var/lib/sockguard"}
	if !reflect.DeepEqual(policy.allowedBindMounts, want) {
		t.Fatalf("allowedBindMounts = %#v, want %#v", policy.allowedBindMounts, want)
	}
}

// TestLocalVolumeDeviceMounts pins the second half of the same policy: a
// local driver options map that names a real kernel filesystem over a /dev
// path is mounting the host's own storage, which is not a bind and so is
// invisible to every check above, but reaches the same data an allowlisted
// bind is there to bound.
func TestLocalVolumeDeviceMounts(t *testing.T) {
	allowed := []string{"/safe", "/dev/sdb1", "/dev/mapper"}

	tests := []struct {
		name       string
		driver     string
		options    map[string]string
		wantReason string
	}{
		{
			name:       "ext4 over a raw block device is denied",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "xfs over a raw block device is denied",
			driver:     "local",
			options:    map[string]string{"type": "xfs", "device": "/dev/nvme0n1p2"},
			wantReason: `volume create denied: local volume device "/dev/nvme0n1p2" is not allowlisted`,
		},
		{
			name:       "btrfs over a raw block device is denied",
			driver:     "local",
			options:    map[string]string{"type": "btrfs", "device": "/dev/vg0/data"},
			wantReason: `volume create denied: local volume device "/dev/vg0/data" is not allowlisted`,
		},
		{
			name:       "vfat over a raw block device is denied",
			driver:     "local",
			options:    map[string]string{"type": "vfat", "device": "/dev/sdc1"},
			wantReason: `volume create denied: local volume device "/dev/sdc1" is not allowlisted`,
		},
		{
			name:       "an empty driver name is still the local driver",
			options:    map[string]string{"type": "ext4", "device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "the option keys are case-insensitive",
			driver:     "Local",
			options:    map[string]string{"Type": "ext4", "Device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a doubled leading slash normalizes onto the same device",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "//dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a dot segment normalizes onto the same device",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev/./sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a traversal back into dev normalizes onto the same device",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev/../dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a relative device resolves against the daemon working directory",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "dev itself is a device path",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev"},
			wantReason: `volume create denied: local volume device "/dev" is not allowlisted`,
		},
		{
			name:       "a device token inside o is checked too",
			driver:     "local",
			options:    map[string]string{"type": "btrfs", "o": "rw,device=/dev/sdd,noatime", "device": "/safe/loopback"},
			wantReason: `volume create denied: local volume device "/dev/sdd" is not allowlisted`,
		},
		{
			name:       "the o device token is case-insensitive",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "o": "rw,Device=/dev/sdd"},
			wantReason: `volume create denied: local volume device "/dev/sdd" is not allowlisted`,
		},
		{
			name:       "the sorted device is the one reported",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev/sdz", "Device": "/dev/sda"},
			wantReason: `volume create denied: local volume device "/dev/sda" is not allowlisted`,
		},
		{
			name:       "a case-variant type key denies on the spelling that is not exempt",
			driver:     "local",
			options:    map[string]string{"type": "tmpfs", "Type": "ext4", "device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a device with no type is denied because the daemon would reject the bind-less mount anyway",
			driver:     "local",
			options:    map[string]string{"device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "an empty type is the absent-type case",
			driver:     "local",
			options:    map[string]string{"type": "", "device": "/dev/sda1"},
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a sibling of an allowlisted device is still denied",
			driver:     "local",
			options:    map[string]string{"type": "ext4", "device": "/dev/sdb10"},
			wantReason: `volume create denied: local volume device "/dev/sdb10" is not allowlisted`,
		},
		{
			name:       "a bind of a device node keeps the bind wording",
			driver:     "local",
			options:    map[string]string{"type": "none", "o": "bind", "device": "/dev/sda1"},
			wantReason: `volume create denied: bind mount source "/dev/sda1" is not allowlisted`,
		},
		{
			name:    "an allowlisted block device passes",
			driver:  "local",
			options: map[string]string{"type": "ext4", "device": "/dev/sdb1"},
		},
		{
			name:    "a device under an allowlisted directory passes",
			driver:  "local",
			options: map[string]string{"type": "ext4", "device": "/dev/mapper/vg0-data"},
		},
		{
			name:    "nfs is left alone even with a dev device",
			driver:  "local",
			options: map[string]string{"type": "nfs", "device": "/dev/sda1"},
		},
		{
			name:    "nfs4 is left alone even with a dev device",
			driver:  "local",
			options: map[string]string{"type": "nfs4", "device": "/dev/sda1"},
		},
		{
			name:    "cifs is left alone even with a dev device",
			driver:  "local",
			options: map[string]string{"type": "cifs", "device": "/dev/sda1"},
		},
		{
			name:    "smb3 is left alone even with a dev device",
			driver:  "local",
			options: map[string]string{"type": "smb3", "device": "/dev/sda1"},
		},
		{
			name:    "tmpfs is left alone even with a dev device",
			driver:  "local",
			options: map[string]string{"type": "tmpfs", "o": "size=100m", "device": "/dev/sda1"},
		},
		{
			name:    "an nfs addr option is not a device token",
			driver:  "local",
			options: map[string]string{"type": "nfs", "o": "addr=1.2.3.4,rw", "device": ":/exports/data"},
		},
		{
			name:    "a traversal out of dev leaves the device check",
			driver:  "local",
			options: map[string]string{"type": "ext4", "device": "/dev/../elsewhere"},
		},
		{
			name:    "a device outside dev is left to the daemon",
			driver:  "local",
			options: map[string]string{"type": "ext4", "device": "/srv/disk.img"},
		},
		{
			name:    "a non-local driver is untouched",
			driver:  "rexray",
			options: map[string]string{"type": "ext4", "device": "/dev/sda1"},
		},
		{
			name:    "a size-only quota map names no device",
			driver:  "local",
			options: map[string]string{"size": "10g"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyLocalVolumeBindDeviceReason(tt.driver, tt.options, allowed, "volume create")
			if got != tt.wantReason {
				t.Fatalf("denyLocalVolumeBindDeviceReason() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

// TestContainerCreateVolumeMountBlockDevice is the container-create surface of
// the device check: a Mounts entry of Type "volume" whose
// VolumeOptions.DriverConfig hands the local driver a filesystem type and a
// /dev path mounts the host's own storage, and is checked against the same
// AllowedBindMounts a bind source is.
func TestContainerCreateVolumeMountBlockDevice(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "an ext4 block device outside the allowlist is denied",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sda1"}}}}]}}`,
			wantReason: `container create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a device with no type is denied because the daemon would reject the bind-less mount anyway",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"device":"/dev/sda1"}}}}]}}`,
			wantReason: `container create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "a btrfs member device inside o is denied",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"btrfs","o":"device=/dev/sdd"}}}}]}}`,
			wantReason: `container create denied: local volume device "/dev/sdd" is not allowlisted`,
		},
		{
			name: "an allowlisted block device passes",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sdb1"}}}}]}}`,
		},
		{
			name: "an nfs export is untouched",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}}}]}}`,
		},
		{
			name: "a non-local driver is untouched",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"rexray","Options":{"type":"ext4","device":"/dev/sda1"}}}}]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: []string{"/safe", "/dev/sdb1"}})
			req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, "/containers/create")
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestServiceMountBlockDevice is the swarm surface of the device check, on
// both POST /services/create and POST /services/{id}/update.
func TestServiceMountBlockDevice(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantReason string
	}{
		{
			name:       "an ext4 block device is denied on create",
			path:       "/services/create",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sda1"}}}}]}}}`,
			wantReason: `service denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "an xfs block device is denied on update",
			path:       "/v1.53/services/web/update?version=7",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"xfs","device":"/dev/nvme0n1p2"}}}}]}}}`,
			wantReason: `service denied: local volume device "/dev/nvme0n1p2" is not allowlisted`,
		},
		{
			name: "an allowlisted block device passes",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"ext4","device":"/dev/sdb1"}}}}]}}}`,
		},
		{
			name: "an nfs export is untouched",
			path: "/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"vol","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}}}]}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newServicePolicy(ServiceOptions{AllowOfficial: true, AllowedBindMounts: []string{"/safe", "/dev/sdb1"}})
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestVolumeCreateBlockDevice covers the pre-created half: a volume made with
// a filesystem type over a /dev path is mounted by name later, which the bind
// allowlist never sees at that point.
func TestVolumeCreateBlockDevice(t *testing.T) {
	tests := []struct {
		name       string
		opts       VolumeOptions
		body       string
		wantReason string
	}{
		{
			name:       "driver options stay denied outright when the knob is off",
			opts:       VolumeOptions{AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"ext4","device":"/dev/sda1"}}`,
			wantReason: "volume create denied: driver options are not allowed",
		},
		{
			name:       "an ext4 block device is denied",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"ext4","device":"/dev/sda1"}}`,
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "the Opts spelling is checked too",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Opts":{"type":"xfs","device":"/dev/sda1"}}`,
			wantReason: `volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name:       "an empty allowlist denies every block device",
			opts:       VolumeOptions{AllowDriverOpts: true},
			body:       `{"Name":"vol","Driver":"local","DriverOpts":{"type":"ext4","device":"/dev/sdb1"}}`,
			wantReason: `volume create denied: local volume device "/dev/sdb1" is not allowlisted`,
		},
		{
			name: "an allowlisted block device passes",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/dev/sdb1"}},
			body: `{"Name":"vol","Driver":"local","DriverOpts":{"type":"ext4","device":"/dev/sdb1"}}`,
		},
		{
			name: "an nfs export is untouched",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","DriverOpts":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}`,
		},
		{
			name: "a non-local driver is untouched",
			opts: VolumeOptions{AllowCustomDrivers: true, AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"rexray","DriverOpts":{"type":"ext4","device":"/dev/sda1"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/volumes/create", strings.NewReader(tt.body))

			reason, err := policy.inspect(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspect() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestLibpodVolumeCreateBlockDevice is TestVolumeCreateBlockDevice's libpod
// counterpart: Podman's local driver takes the same type/device options under
// the "Options" wire key.
func TestLibpodVolumeCreateBlockDevice(t *testing.T) {
	tests := []struct {
		name       string
		opts       VolumeOptions
		body       string
		wantReason string
	}{
		{
			name:       "an xfs block device is denied",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","Options":{"type":"xfs","device":"/dev/nvme0n1"}}`,
			wantReason: `libpod volume create denied: local volume device "/dev/nvme0n1" is not allowlisted`,
		},
		{
			name:       "a device with no type is denied because the daemon would reject the bind-less mount anyway",
			opts:       VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body:       `{"Name":"vol","Driver":"local","Options":{"device":"/dev/sda1"}}`,
			wantReason: `libpod volume create denied: local volume device "/dev/sda1" is not allowlisted`,
		},
		{
			name: "an allowlisted block device passes",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/dev/sdb1"}},
			body: `{"Name":"vol","Driver":"local","Options":{"type":"ext4","device":"/dev/sdb1"}}`,
		},
		{
			name: "an nfs export is untouched",
			opts: VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: []string{"/safe"}},
			body: `{"Name":"vol","Driver":"local","Options":{"type":"nfs","o":"addr=1.2.3.4","device":":/exports/data"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newVolumePolicy(tt.opts)
			req := httptest.NewRequest(http.MethodPost, "/libpod/volumes/create", strings.NewReader(tt.body))

			reason, err := policy.inspectLibpod(testLogger(), req, NormalizePath(req.URL.Path))
			if err != nil {
				t.Fatalf("inspectLibpod() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}
