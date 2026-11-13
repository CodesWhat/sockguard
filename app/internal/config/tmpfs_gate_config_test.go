package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// TestTmpfsPrivilegedGateReachesItsRoutes turns allow_tmpfs_privileged_options
// on for one create route at a time, from YAML and from the environment, and
// checks which filter options it reaches. container_create also opens the
// service and compat volume routes, libpod_container_create the native volume
// route, and neither opens the other family.
func TestTmpfsPrivilegedGateReachesItsRoutes(t *testing.T) {
	type reach struct {
		container, service, volume, libpod, libpodVolume bool
	}
	read := func(p filter.PolicyConfig) reach {
		return reach{
			container:    p.ContainerCreate.AllowTmpfsPrivilegedOptions,
			service:      p.Service.AllowTmpfsPrivilegedOptions,
			volume:       p.Volume.AllowTmpfsPrivilegedOptions,
			libpod:       p.LibpodContainerCreate.AllowTmpfsPrivilegedOptions,
			libpodVolume: p.LibpodVolume.AllowTmpfsPrivilegedOptions,
		}
	}
	tests := []struct {
		block, envVar string
		want          reach
	}{
		{"container_create", "SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_ALLOW_TMPFS_PRIVILEGED_OPTIONS", reach{container: true, service: true, volume: true}},
		{"libpod_container_create", "SOCKGUARD_REQUEST_BODY_LIBPOD_CONTAINER_CREATE_ALLOW_TMPFS_PRIVILEGED_OPTIONS", reach{libpod: true, libpodVolume: true}},
	}

	cfg, err := Load("/nonexistent-so-defaults-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := read(cfg.RequestBody.ToFilterOptions()); got != (reach{}) {
		t.Errorf("defaults reach %+v, want none", got)
	}

	for _, tt := range tests {
		t.Run(tt.block+"/yaml", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sockguard.yaml")
			yaml := "request_body:\n  " + tt.block + ":\n    allow_tmpfs_privileged_options: true\n"
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := read(cfg.RequestBody.ToFilterOptions()); got != tt.want {
				t.Errorf("reach = %+v, want %+v", got, tt.want)
			}
		})
		t.Run(tt.block+"/env", func(t *testing.T) {
			t.Setenv(tt.envVar, "true")
			cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := read(cfg.RequestBody.ToFilterOptions()); got != tt.want {
				t.Errorf("reach = %+v, want %+v", got, tt.want)
			}
		})
	}
}
