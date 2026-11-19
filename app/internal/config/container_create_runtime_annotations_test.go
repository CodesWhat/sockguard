package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContainerCreateAllowRuntimeAnnotationsDefaultOffAndMaps pins
// request_body.container_create.allow_runtime_annotations: off by default, and
// it reaches the filter's ContainerCreate option from YAML and from its
// environment variable.
func TestContainerCreateAllowRuntimeAnnotationsDefaultOffAndMaps(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.RequestBody.ToFilterOptions().ContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("allow_runtime_annotations is on by default, want off")
	}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := "request_body:\n  container_create:\n    allow_runtime_annotations: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequestBody.ContainerCreate.AllowRuntimeAnnotations || !cfg.RequestBody.ToFilterOptions().ContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("yaml: allow_runtime_annotations did not reach the filter option")
	}
	if cfg.RequestBody.ToFilterOptions().LibpodContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("yaml: the compat flag leaked into libpod_container_create")
	}

	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_RUNTIME_ANNOTATIONS", "true")
	cfg, err = Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequestBody.ToFilterOptions().ContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("env: SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_RUNTIME_ANNOTATIONS did not reach the filter option")
	}
}

// TestLibpodContainerCreateAllowRuntimeAnnotationsDefaultOffAndMaps pins
// request_body.libpod_container_create.allow_runtime_annotations: off by
// default, reaching the native option from YAML and its environment variable,
// and not opening the Docker-compat gate.
func TestLibpodContainerCreateAllowRuntimeAnnotationsDefaultOffAndMaps(t *testing.T) {
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.RequestBody.ToFilterOptions().LibpodContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("libpod allow_runtime_annotations is on by default, want off")
	}

	path := filepath.Join(t.TempDir(), "sockguard.yaml")
	yaml := "request_body:\n  libpod_container_create:\n    allow_runtime_annotations: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := cfg.RequestBody.ToFilterOptions()
	if !opts.LibpodContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("yaml: libpod allow_runtime_annotations did not reach the filter option")
	}
	if opts.ContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("yaml: the libpod flag leaked into container_create")
	}

	t.Setenv("SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_RUNTIME_ANNOTATIONS", "true")
	cfg, err = Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequestBody.ToFilterOptions().LibpodContainerCreate.AllowRuntimeAnnotations {
		t.Fatal("env: SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_RUNTIME_ANNOTATIONS did not reach the filter option")
	}
}
