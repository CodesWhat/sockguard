package config

import (
	"strings"
	"testing"
)

func TestValidateImagePushConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ImagePushRequestBodyConfig
		wantErr string // empty means valid
	}{
		{name: "empty is inactive and valid", cfg: ImagePushRequestBodyConfig{}},
		{name: "allowlist only", cfg: ImagePushRequestBodyConfig{AllowedRegistries: []string{"ghcr.io", "registry.internal:5000", "[::1]:5000", "localhost:5000"}}},
		{name: "valid alias", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"registry.internal:5000"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "mirror.corp.example", To: "registry.internal:5000"}},
		}},
		{name: "alias to docker.io", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"docker.io"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "hub.corp.example", To: "docker.io"}},
		}},
		{name: "allowlist entry with scheme", cfg: ImagePushRequestBodyConfig{AllowedRegistries: []string{"https://ghcr.io"}}, wantErr: "image_push.allowed_registries"},
		{name: "allowlist entry with path", cfg: ImagePushRequestBodyConfig{AllowedRegistries: []string{"ghcr.io/acme"}}, wantErr: "image_push.allowed_registries"},
		{name: "allowlist entry empty", cfg: ImagePushRequestBodyConfig{AllowedRegistries: []string{" "}}, wantErr: "image_push.allowed_registries"},
		{name: "aliases without allowlist", cfg: ImagePushRequestBodyConfig{
			RegistryAliases: []ImagePushRegistryAlias{{From: "a.example", To: "b.example"}},
		}, wantErr: "requires image_push.allowed_registries"},
		{name: "alias key with scheme", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"b.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "https://a.example", To: "b.example"}},
		}, wantErr: ".from must be a bare registry host"},
		{name: "alias value with path", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"b.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "a.example", To: "b.example/x"}},
		}, wantErr: ".to must be a bare registry host"},
		{name: "alias to itself", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"a.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "a.example", To: "A.EXAMPLE"}},
		}, wantErr: "must differ from its target"},
		{name: "alias chain", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"c.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "a.example", To: "b.example"}, {From: "b.example", To: "c.example"}},
		}, wantErr: "chains are not followed"},
		{name: "alias cycle", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"a.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "a.example", To: "b.example"}, {From: "b.example", To: "a.example"}},
		}, wantErr: "chains are not followed"},
		{name: "duplicate keys after normalization", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"c.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "A.example", To: "c.example"}, {From: "a.example", To: "c.example"}},
		}, wantErr: "is a duplicate"},
		{name: "built-in alias key", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"c.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "registry-1.docker.io", To: "c.example"}},
		}, wantErr: "built-in Docker Hub alias"},
		{name: "docker.io key", cfg: ImagePushRequestBodyConfig{
			AllowedRegistries: []string{"c.example"},
			RegistryAliases:   []ImagePushRegistryAlias{{From: "docker.io", To: "c.example"}},
		}, wantErr: "built-in Docker Hub alias"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateImagePushConfig("request_body", tt.cfg)
			if tt.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("errors = %v, want none", errs)
				}
				return
			}
			if !strings.Contains(strings.Join(errs, "\n"), tt.wantErr) {
				t.Fatalf("errors = %v, want one containing %q", errs, tt.wantErr)
			}
		})
	}
}

func TestValidateReachesImagePushInTopLevelAndProfile(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ImagePush.RegistryAliases = []ImagePushRegistryAlias{{From: "a.example", To: "b.example"}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "request_body.image_push.registry_aliases") {
		t.Fatalf("Validate() = %v, want a request_body.image_push.registry_aliases error", err)
	}
}

func TestLoadBytesImagePushAliases(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
request_body:
  image_push:
    allowed_registries: [ghcr.io, registry.internal:5000]
    registry_aliases:
      - from: mirror.corp.example
        to: registry.internal:5000
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	opts := cfg.RequestBody.ToFilterOptions().ImagePush
	if len(opts.AllowedRegistries) != 2 || opts.RegistryAliases["mirror.corp.example"] != "registry.internal:5000" {
		t.Fatalf("ImagePush options = %#v", opts)
	}
}

func TestLoadImagePushAllowedRegistriesFromEnv(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_IMAGE_PUSH_ALLOWED_REGISTRIES", "ghcr.io,registry.internal:5000")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := strings.Join(cfg.RequestBody.ImagePush.AllowedRegistries, "|"); got != "ghcr.io|registry.internal:5000" {
		t.Fatalf("allowed_registries = %q", got)
	}
}
