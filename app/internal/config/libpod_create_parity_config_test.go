package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The libpod create block carries the same-named opt-ins as container_create
// for oci_runtime, device_cgroup_rule, gpus and unmask. They must default off
// and reach the libpod filter options, not the compat ones.
func TestLibpodCreateParityOptionsLoadAndMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := `request_body:
  libpod_container_create:
    allowed_runtimes: [runsc]
    allow_device_cgroup_rules: true
    allowed_device_cgroup_rules: ["c 1:3 rwm"]
    allow_device_requests: true
    deny_unconfined_system_paths: true
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	opts := cfg.RequestBody.ToFilterOptions()
	lib := opts.LibpodContainerCreate
	if !reflect.DeepEqual(lib.AllowedRuntimes, []string{"runsc"}) ||
		!lib.AllowDeviceCgroupRules ||
		!reflect.DeepEqual(lib.AllowedDeviceCgroupRules, []string{"c 1:3 rwm"}) ||
		!lib.AllowDeviceRequests ||
		!lib.DenyUnconfinedSystemPaths {
		t.Errorf("libpod options = %+v", lib)
	}
	c := opts.ContainerCreate
	if c.AllowedRuntimes != nil || c.AllowDeviceCgroupRules || c.AllowDeviceRequests || c.DenyUnconfinedSystemPaths {
		t.Errorf("libpod keys leaked into container_create options: %+v", c)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate() error = %v", err)
	}

	def, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d := def.RequestBody.ToFilterOptions().LibpodContainerCreate
	if d.AllowedRuntimes != nil || d.AllowDeviceCgroupRules || d.AllowedDeviceCgroupRules != nil || d.AllowDeviceRequests || d.DenyUnconfinedSystemPaths {
		t.Errorf("defaults not off: %+v", d)
	}
}

func TestLibpodCreateParityOptionsFromEnv(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOWED_RUNTIMES", "runsc,kata")
	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_DEVICE_REQUESTS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_DENY_UNCONFINED_SYSTEM_PATHS", "true")
	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lib := cfg.RequestBody.ToFilterOptions().LibpodContainerCreate
	if !reflect.DeepEqual(lib.AllowedRuntimes, []string{"runsc", "kata"}) || !lib.AllowDeviceRequests || !lib.DenyUnconfinedSystemPaths {
		t.Errorf("env not applied: %+v", lib)
	}
}
