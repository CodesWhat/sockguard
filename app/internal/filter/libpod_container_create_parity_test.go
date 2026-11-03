package filter

import (
	"strings"
	"testing"
)

// libpod_container_create_parity_test.go pins the libpod spellings of the
// fields container_create denies or gates, against the derived fixtures in
// testdata/libpod (see that README: derived from specgen.go, not captured).

func TestLibpodContainerCreateDockerParityDenials(t *testing.T) {
	tests := []struct {
		fixture string
		want    string
	}{
		{"volumes_from.json", "libpod container create denied: VolumesFrom is not allowed"},
		{"cgroup_parent.json", "libpod container create denied: custom cgroup parent is not allowed"},
		{"groups.json", "libpod container create denied: supplemental group IDs are not allowed"},
		{"hostadd.json", "libpod container create denied: ExtraHosts is not allowed"},
		{"oci_runtime.json", `libpod container create denied: runtime "runsc" is not allowlisted`},
		{"device_cgroup_rule.json", "libpod container create denied: device cgroup rules are not allowed"},
		{"gpus.json", "libpod container create denied: device requests are not allowed"},
	}
	// Permissive everywhere the opt-ins can reach, so only the unconditional
	// denials (and the unopted gates under test) can fire.
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			if got := inspectLibpod(t, policy, loadLibpodFixture(t, "specgen/"+tt.fixture)); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
	// Control: the baseline fixture the others derive from is allowed.
	if got := inspectLibpod(t, policy, loadLibpodFixture(t, "basic_create.json")); got != "" {
		t.Fatalf("basic_create denied: %q", got)
	}
}

func TestLibpodContainerCreateUnconditionalFieldsIgnoreOptIns(t *testing.T) {
	// No option lifts VolumesFrom, CgroupParent, GroupAdd or ExtraHosts on the
	// Docker side; the libpod spellings stay denied under the widest policy.
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
		AllowSystemdMode:         true,
		AllowPrivileged:          true,
		AllowAllDevices:          true,
		AllowAllCapabilities:     true,
		AllowedRuntimes:          []string{"runsc"},
		AllowDeviceCgroupRules:   true,
		AllowDeviceRequests:      true,
		AllowedDeviceCgroupRules: []string{"c 1:3 rwm"},
	})
	for _, fixture := range []string{"volumes_from.json", "cgroup_parent.json", "groups.json", "hostadd.json"} {
		if got := inspectLibpod(t, policy, loadLibpodFixture(t, "specgen/"+fixture)); got == "" {
			t.Errorf("%s allowed under the widest policy", fixture)
		}
	}
}

func TestLibpodContainerCreateOCIRuntimeAllowlist(t *testing.T) {
	body := loadLibpodFixture(t, "specgen/oci_runtime.json") // oci_runtime: runsc
	allowed := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true, AllowedRuntimes: []string{" runsc "}})
	if got := inspectLibpod(t, allowed, body); got != "" {
		t.Fatalf("allowlisted runtime denied: %q", got)
	}
	other := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true, AllowedRuntimes: []string{"kata"}})
	if got := inspectLibpod(t, other, body); !strings.Contains(got, `runtime "runsc" is not allowlisted`) {
		t.Fatalf("reason = %q", got)
	}
	// Empty oci_runtime selects the daemon default and is always permitted.
	if got := inspectLibpod(t, other, loadLibpodFixture(t, "basic_create.json")); got != "" {
		t.Fatalf("empty runtime denied: %q", got)
	}
}

func TestLibpodContainerCreateDeviceCgroupRuleOptIns(t *testing.T) {
	body := loadLibpodFixture(t, "specgen/device_cgroup_rule.json") // c 1:3 rwm
	tests := []struct {
		name string
		opts LibpodContainerCreateOptions
		want string
	}{
		{"blanket opt-in", LibpodContainerCreateOptions{AllowDeviceCgroupRules: true}, ""},
		{"allowlisted", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 mrw"}}, ""},
		{"wildcard allowlist", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:* rwm"}}, ""},
		{"different device", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:5 rwm"}}, `libpod container create denied: device cgroup rule "c 1:3 rwm" is not in the allowed list`},
		{"lesser perms", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 r"}}, `libpod container create denied: device cgroup rule "c 1:3 rwm" is not in the allowed list`},
		{"default", LibpodContainerCreateOptions{}, "libpod container create denied: device cgroup rules are not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.AllowSystemdMode = true
			if got := inspectLibpod(t, newLibpodContainerCreatePolicy(tt.opts), body); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLibpodContainerCreateDeviceCgroupRuleShapes(t *testing.T) {
	policy := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{
		AllowSystemdMode: true, AllowedDeviceCgroupRules: []string{"c *:* rwm", "a *:* rw"},
	})
	tests := []struct {
		name string
		rule string
		want string
	}{
		{"wildcards via null", `{"type":"c","major":null,"minor":null,"access":"rwm"}`, ""},
		{"empty type is all", `{"type":"","access":"rw"}`, ""},
		{"empty access is malformed", `{"type":"c","major":1,"minor":3,"access":""}`, `libpod container create denied: device cgroup rule "c 1:3 " is malformed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{"image":"alpine","systemd":"false","device_cgroup_rule":[` + tt.rule + `]}`)
			if got := inspectLibpod(t, policy, body); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLibpodContainerCreateGPUsOptIn(t *testing.T) {
	body := loadLibpodFixture(t, "specgen/gpus.json")
	on := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true, AllowDeviceRequests: true})
	if got := inspectLibpod(t, on, body); got != "" {
		t.Fatalf("allow_device_requests did not permit gpus: %q", got)
	}
}

func TestLibpodContainerCreateUnmaskSystemPathsGate(t *testing.T) {
	body := loadLibpodFixture(t, "specgen/unmask.json") // unmask: ["ALL"]
	deny := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true, DenyUnconfinedSystemPaths: true})
	want := "libpod container create denied: unmask (systempaths=unconfined equivalent) is not allowed"
	if got := inspectLibpod(t, deny, body); got != want {
		t.Fatalf("reason = %q, want %q", got, want)
	}
	// Docker's systempaths gate is opt-in; so is this one.
	def := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowSystemdMode: true})
	if got := inspectLibpod(t, def, body); got != "" {
		t.Fatalf("unmask denied without deny_unconfined_system_paths: %q", got)
	}
	if got := inspectLibpod(t, deny, loadLibpodFixture(t, "basic_create.json")); got != "" {
		t.Fatalf("no-unmask body denied: %q", got)
	}
}

func TestLibpodContainerCreateHostDeviceListAndResourceDevices(t *testing.T) {
	base := func(extra string) []byte {
		return []byte(`{"image":"alpine","pod":"p","devices":[],` + extra + `}`)
	}
	tests := []struct {
		name string
		opts LibpodContainerCreateOptions
		body string
		want string
	}{
		{"host_device_list denied by default", LibpodContainerCreateOptions{},
			`"host_device_list":[{"path":"/dev/sda"}]`,
			`libpod container create denied: host_device_list entry "/dev/sda" is not allowlisted`},
		{"host_device_list non-allowlisted path denied", LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/fuse"}},
			`"host_device_list":[{"path":"/dev/fuse"},{"path":"/dev/sda"}]`,
			`libpod container create denied: host_device_list entry "/dev/sda" is not allowlisted`},
		{"host_device_list allowlisted path allowed", LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/fuse"}},
			`"host_device_list":[{"path":"/dev/fuse"}]`, ""},
		{"host_device_list allowed with allow_all_devices", LibpodContainerCreateOptions{AllowAllDevices: true},
			`"host_device_list":[{"path":"/dev/sda"}]`, ""},
		{"host_device_list empty path denied", LibpodContainerCreateOptions{AllowedDevices: []string{"/dev/fuse"}},
			`"host_device_list":[{}]`,
			`libpod container create denied: host_device_list entry "" is not allowlisted`},
		{"devices_from denied", LibpodContainerCreateOptions{AllowAllDevices: true},
			`"devices_from":["other"]`,
			"libpod container create denied: devices_from is not allowed"},
		{"devices_from empty allowed", LibpodContainerCreateOptions{},
			`"devices_from":[]`, ""},
		{"resource_limits.devices wildcard denied by default", LibpodContainerCreateOptions{},
			`"resource_limits":{"devices":[{"allow":true,"access":"rwm"}]}`,
			"libpod resource_limits.devices: container create denied: device cgroup rules are not allowed"},
		{"resource_limits.devices allow:false only passes", LibpodContainerCreateOptions{},
			`"resource_limits":{"devices":[{"allow":false,"access":"rwm"}]}`, ""},
		{"resource_limits.devices allowlisted rule passes", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			`"resource_limits":{"devices":[{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"}]}`, ""},
		{"resource_limits.devices wildcard denied against narrow allowlist", LibpodContainerCreateOptions{AllowedDeviceCgroupRules: []string{"c 1:3 rwm"}},
			`"resource_limits":{"devices":[{"allow":true,"type":"a","access":"rwm"}]}`,
			`libpod resource_limits.devices: container create denied: device cgroup rule "a *:* rwm" is not in the allowed list`},
		{"resource_limits.devices allowed with allow_device_cgroup_rules", LibpodContainerCreateOptions{AllowDeviceCgroupRules: true},
			`"resource_limits":{"devices":[{"allow":true,"access":"rwm"}]}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.AllowSystemdMode = true
			policy := newLibpodContainerCreatePolicy(tt.opts)
			if got := inspectLibpod(t, policy, base(tt.body)); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}
