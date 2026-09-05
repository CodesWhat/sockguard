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
