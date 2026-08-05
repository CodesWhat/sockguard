package config

import (
	"reflect"
	"testing"
)

func TestResourceLimitConfigDefaultsAreDisabled(t *testing.T) {
	cfg := Defaults()
	cu := cfg.RequestBody.ContainerUpdate
	svc := cfg.RequestBody.Service

	if cu.RequireMemoryLimit || cu.RequireCPULimit || cu.RequireCPULimitHard || cu.RequirePidsLimit || svc.RequireCPULimit || svc.RequireCPULimitHard {
		t.Fatalf("resource-limit defaults are not all disabled: container_update=%+v service=%+v", cu, svc)
	}
}

func TestResourceLimitConfigEnvironmentOverridesAllSixFlags(t *testing.T) {
	for _, name := range []string{
		"SOCKGUARD_REQUEST_BODY_CONTAINER_UPDATE_REQUIRE_MEMORY_LIMIT",
		"SOCKGUARD_REQUEST_BODY_CONTAINER_UPDATE_REQUIRE_CPU_LIMIT",
		"SOCKGUARD_REQUEST_BODY_CONTAINER_UPDATE_REQUIRE_CPU_LIMIT_HARD",
		"SOCKGUARD_REQUEST_BODY_CONTAINER_UPDATE_REQUIRE_PIDS_LIMIT",
		"SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_CPU_LIMIT",
		"SOCKGUARD_REQUEST_BODY_SERVICE_REQUIRE_CPU_LIMIT_HARD",
	} {
		t.Setenv(name, "true")
	}

	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cu := cfg.RequestBody.ContainerUpdate
	svc := cfg.RequestBody.Service
	if !cu.RequireMemoryLimit || !cu.RequireCPULimit || !cu.RequireCPULimitHard || !cu.RequirePidsLimit || !svc.RequireCPULimit || !svc.RequireCPULimitHard {
		t.Fatalf("resource-limit env overrides were not all applied: container_update=%+v service=%+v", cu, svc)
	}
}

func TestResourceLimitConfigLoadsGlobalAndProfileMappings(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
request_body:
  container_update:
    allow_resource_updates: true
    require_memory_limit: true
    require_cpu_limit: true
    require_cpu_limit_hard: true
    require_pids_limit: true
  service:
    require_cpu_limit: true
    require_cpu_limit_hard: true
clients:
  profiles:
    - name: strict
      rules:
        - match: { method: POST, path: "/**" }
          action: allow
      request_body:
        container_update:
          allow_resource_updates: true
          require_memory_limit: true
          require_cpu_limit: true
          require_cpu_limit_hard: true
          require_pids_limit: true
        service:
          require_cpu_limit: true
          require_cpu_limit_hard: true
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	assertAllResourceLimitFlagsEnabled(t, cfg.RequestBody)
	if len(cfg.Clients.Profiles) != 1 || cfg.Clients.Profiles[0].Name != "strict" {
		t.Fatalf("profiles = %#v, want strict profile", cfg.Clients.Profiles)
	}
	assertAllResourceLimitFlagsEnabled(t, cfg.Clients.Profiles[0].RequestBody)
}

func TestResourceLimitConfigMapsAllSixFlagsToFilterOptions(t *testing.T) {
	requestBody := RequestBodyConfig{
		ContainerUpdate: ContainerUpdateRequestBodyConfig{
			AllowResourceUpdates: true,
			RequireMemoryLimit:   true,
			RequireCPULimit:      true,
			RequireCPULimitHard:  true,
			RequirePidsLimit:     true,
		},
		Service: ServiceRequestBodyConfig{
			RequireCPULimit:     true,
			RequireCPULimitHard: true,
		},
	}

	got := requestBody.ToFilterOptions()
	cu := got.ContainerUpdate
	svc := got.Service
	if !cu.AllowResourceUpdates || !cu.RequireMemoryLimit || !cu.RequireCPULimit || !cu.RequireCPULimitHard || !cu.RequirePidsLimit || !svc.RequireCPULimit || !svc.RequireCPULimitHard {
		t.Fatalf("filter mapping incomplete: container_update=%+v service=%+v", cu, svc)
	}
}

func TestResourceLimitConfigSchemaCompleteness(t *testing.T) {
	tests := []struct {
		typ  reflect.Type
		want []string
	}{
		{
			typ:  reflect.TypeOf(ContainerUpdateRequestBodyConfig{}),
			want: []string{"require_memory_limit", "require_cpu_limit", "require_cpu_limit_hard", "require_pids_limit"},
		},
		{
			typ:  reflect.TypeOf(ServiceRequestBodyConfig{}),
			want: []string{"require_cpu_limit", "require_cpu_limit_hard"},
		},
	}

	for _, tt := range tests {
		for _, tag := range tt.want {
			found := false
			for i := 0; i < tt.typ.NumField(); i++ {
				if tt.typ.Field(i).Tag.Get("mapstructure") == tag {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s missing mapstructure field %q", tt.typ, tag)
			}
		}
	}
}

func assertAllResourceLimitFlagsEnabled(t *testing.T, requestBody RequestBodyConfig) {
	t.Helper()
	cu := requestBody.ContainerUpdate
	svc := requestBody.Service
	if !cu.AllowResourceUpdates || !cu.RequireMemoryLimit || !cu.RequireCPULimit || !cu.RequireCPULimitHard || !cu.RequirePidsLimit || !svc.RequireCPULimit || !svc.RequireCPULimitHard {
		t.Fatalf("resource-limit flags incomplete: container_update=%+v service=%+v", cu, svc)
	}
}
