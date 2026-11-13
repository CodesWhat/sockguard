package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowHostCgroupNSOnCgroupV1(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 {
		t.Fatal("default is on, want off")
	}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	if err := os.WriteFile(path, []byte("request_body:\n  container_create:\n    allow_host_cgroupns_on_cgroup_v1: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromYAML, err := Load(path)
	if err != nil {
		t.Fatalf("Load(yaml) error = %v", err)
	}
	cc := fromYAML.RequestBody.ContainerCreate
	if !cc.AllowHostCgroupNSOnCgroupV1 || cc.AllowHostCgroupNS {
		t.Fatalf("yaml: OnCgroupV1 = %v, AllowHostCgroupNS = %v, want true/false", cc.AllowHostCgroupNSOnCgroupV1, cc.AllowHostCgroupNS)
	}
	if !fromYAML.RequestBody.ContainerCreate.ToFilterOptions().AllowHostCgroupNSOnCgroupV1 {
		t.Fatal("yaml value did not reach the filter options")
	}

	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_HOST_CGROUPNS_ON_CGROUP_V1", "true")
	fromEnv, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load(env) error = %v", err)
	}
	if !fromEnv.RequestBody.ContainerCreate.AllowHostCgroupNSOnCgroupV1 {
		t.Fatal("env var did not set the option")
	}
}
