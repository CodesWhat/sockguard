package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

// libpodHostNamespaceGates is every host namespace gate on Podman's native
// create routes: its YAML key, its environment variable, and how to read it
// off a loaded config and off the filter options built from one.
var libpodHostNamespaceGates = []struct {
	key    string
	envVar string
	config func(*RequestBodyConfig) *bool
	filter func(*filter.PolicyConfig) *bool
}{
	{
		"libpod_container_create.allow_host_network", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_NETWORK",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostNetwork },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostNetwork },
	},
	{
		"libpod_container_create.allow_host_pid", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_PID",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostPID },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostPID },
	},
	{
		"libpod_container_create.allow_host_ipc", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_IPC",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostIPC },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostIPC },
	},
	{
		"libpod_container_create.allow_host_userns", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_USERNS",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostUserNS },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostUserNS },
	},
	{
		"libpod_container_create.allow_host_uts", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_UTS",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostUTS },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostUTS },
	},
	{
		"libpod_container_create.allow_host_cgroupns", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_HOST_CGROUPNS",
		func(c *RequestBodyConfig) *bool { return &c.LibpodContainerCreate.AllowHostCgroupNS },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodContainerCreate.AllowHostCgroupNS },
	},
	{
		"libpod_pod_create.allow_host_network", "SOCKGUARD_REQUEST_BODY_LIBPOD_POD_CREATE_ALLOW_HOST_NETWORK",
		func(c *RequestBodyConfig) *bool { return &c.LibpodPodCreate.AllowHostNetwork },
		func(p *filter.PolicyConfig) *bool { return &p.LibpodPodCreate.AllowHostNetwork },
	},
}

// TestLibpodHostNamespaceGatesDefaultOff pins that every host namespace gate
// on the native routes refuses until it's set.
func TestLibpodHostNamespaceGatesDefaultOff(t *testing.T) {
	defaults := Defaults()
	loaded, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for _, gate := range libpodHostNamespaceGates {
		if *gate.config(&defaults.RequestBody) {
			t.Errorf("Defaults() has request_body.%s on, want off", gate.key)
		}
		if *gate.config(&loaded.RequestBody) {
			t.Errorf("Load() with no file has request_body.%s on, want off", gate.key)
		}
	}
}

// TestLibpodHostNamespaceGatesMapOneToOne turns each gate on alone, from
// YAML and from its environment variable, and checks that it reaches its own
// filter option and no other. A gate wired to its neighbor's field would
// open a namespace the operator never asked to open.
func TestLibpodHostNamespaceGatesMapOneToOne(t *testing.T) {
	for _, gate := range libpodHostNamespaceGates {
		block, option, found := strings.Cut(gate.key, ".")
		if !found {
			t.Fatalf("gate key %q has no block", gate.key)
		}
		sources := map[string]func(t *testing.T) *Config{
			"yaml": func(t *testing.T) *Config {
				path := filepath.Join(t.TempDir(), "sockguard.yaml")
				yaml := "request_body:\n  " + block + ":\n    " + option + ": true\n"
				if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
				cfg, err := Load(path)
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				return cfg
			},
			"env": func(t *testing.T) *Config {
				t.Setenv(gate.envVar, "true")
				cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				return cfg
			},
		}
		for source, load := range sources {
			t.Run(gate.key+"/"+source, func(t *testing.T) {
				cfg := load(t)
				options := cfg.RequestBody.ToFilterOptions()
				for _, other := range libpodHostNamespaceGates {
					want := other.key == gate.key
					if got := *other.config(&cfg.RequestBody); got != want {
						t.Errorf("config request_body.%s = %t, want %t", other.key, got, want)
					}
					if got := *other.filter(&options); got != want {
						t.Errorf("filter option for request_body.%s = %t, want %t", other.key, got, want)
					}
				}
			})
		}
	}
}
