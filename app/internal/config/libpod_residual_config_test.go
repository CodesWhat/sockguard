package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLibpodResidualGatesDefaultOffAndMap pins allow_unified_cgroup_settings
// and allow_env_host: off by default, and each reaches its own filter option
// from YAML and from its environment variable.
func TestLibpodResidualGatesDefaultOffAndMap(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	opts := loaded.RequestBody.ToFilterOptions().LibpodContainerCreate
	if opts.AllowUnifiedCgroupSettings || opts.AllowEnvHost {
		t.Fatalf("defaults on: unified=%v env_host=%v", opts.AllowUnifiedCgroupSettings, opts.AllowEnvHost)
	}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := "request_body:\n  libpod_container_create:\n    allow_unified_cgroup_settings: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	opts = cfg.RequestBody.ToFilterOptions().LibpodContainerCreate
	if !opts.AllowUnifiedCgroupSettings || opts.AllowEnvHost {
		t.Fatalf("yaml: unified=%v env_host=%v", opts.AllowUnifiedCgroupSettings, opts.AllowEnvHost)
	}

	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_ENV_HOST", "true")
	cfg, err = Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts = cfg.RequestBody.ToFilterOptions().LibpodContainerCreate
	if opts.AllowUnifiedCgroupSettings || !opts.AllowEnvHost {
		t.Fatalf("env: unified=%v env_host=%v", opts.AllowUnifiedCgroupSettings, opts.AllowEnvHost)
	}
}

// TestLibpodStorageOptsAndRuntimeAnnotationsDefaultOffAndMap pins
// allow_storage_opts and allow_runtime_annotations: off by default, and each
// reaches its own filter option from YAML and from its environment variable.
func TestLibpodStorageOptsAndRuntimeAnnotationsDefaultOffAndMap(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	opts := loaded.RequestBody.ToFilterOptions().LibpodContainerCreate
	if opts.AllowStorageOpts || opts.AllowRuntimeAnnotations {
		t.Fatalf("defaults on: storage_opts=%v runtime_annotations=%v", opts.AllowStorageOpts, opts.AllowRuntimeAnnotations)
	}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := "request_body:\n  libpod_container_create:\n    allow_storage_opts: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	opts = cfg.RequestBody.ToFilterOptions().LibpodContainerCreate
	if !opts.AllowStorageOpts || opts.AllowRuntimeAnnotations {
		t.Fatalf("yaml: storage_opts=%v runtime_annotations=%v", opts.AllowStorageOpts, opts.AllowRuntimeAnnotations)
	}

	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_RUNTIME_ANNOTATIONS", "true")
	cfg, err = Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts = cfg.RequestBody.ToFilterOptions().LibpodContainerCreate
	if opts.AllowStorageOpts || !opts.AllowRuntimeAnnotations {
		t.Fatalf("env: storage_opts=%v runtime_annotations=%v", opts.AllowStorageOpts, opts.AllowRuntimeAnnotations)
	}
}
