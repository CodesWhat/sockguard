package config

import (
	"strings"
	"testing"
)

// dummyECDSAPEM is a well-formed PEM-encoded public key used by
// validateImageTrustConfig tests that need a non-empty PEM value.
// The validator only checks for emptiness (not PEM validity), so any
// syntactically valid block is fine here.
const dummyECDSAPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Q2VTG/T3z8QoKFxmVCfSWo6Lb
W1kQy8bNQeXwT4OJAGtKk5Z9j1vUn9G3z1eUgF6Gz0lJ9TQ1mHX5MAbS3g==
-----END PUBLIC KEY-----
`

// TestValidateImageTrustConfig_WarnWithNoKeys checks that mode=warn with no
// allowed_signing_keys and no allowed_keyless produces a validation error.
func TestValidateImageTrustConfig_WarnWithNoKeys(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "warn",
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for warn mode with no signing keys or keyless entries, got nil")
	}
	if !strings.Contains(err.Error(), "image_trust") {
		t.Fatalf("error should mention image_trust, got: %v", err)
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("error should mention 'at least one', got: %v", err)
	}
}

// TestValidateImageTrustConfig_EnforceWithSigningKey checks that mode=enforce
// with a non-empty PEM entry passes validation without error.
func TestValidateImageTrustConfig_EnforceWithSigningKey(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "enforce",
		AllowedSigningKeys: []SigningKeyConfig{
			{PEM: dummyECDSAPEM},
		},
		AllowedRegistries: []string{"ghcr.io"},
	}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected no error for enforce mode with a signing key, got: %v", err)
	}
}

// TestValidateImageTrustConfig_RegistryScope checks that warn/enforce need a
// registry scope (or an exact allowed_images list) so signature discovery
// cannot be pointed at an arbitrary client-named host.
func TestValidateImageTrustConfig_RegistryScope(t *testing.T) {
	trust := func(mutate func(*ImageTrustConfig)) ImageTrustConfig {
		cfg := ImageTrustConfig{Mode: "enforce", AllowedSigningKeys: []SigningKeyConfig{{PEM: dummyECDSAPEM}}}
		mutate(&cfg)
		return cfg
	}
	const wantMsg = "allow_all_registries, allow_official, or allowed_registries is required"
	tests := []struct {
		name    string
		trust   ImageTrustConfig
		images  []string
		wantErr string
	}{
		{name: "no scope", trust: trust(func(*ImageTrustConfig) {}), wantErr: wantMsg},
		{name: "allowed_images scopes", trust: trust(func(*ImageTrustConfig) {}), images: []string{"ghcr.io/org/app:1.0"}},
		{name: "allowed_registries", trust: trust(func(c *ImageTrustConfig) { c.AllowedRegistries = []string{"ghcr.io"} })},
		{name: "allow_all_registries", trust: trust(func(c *ImageTrustConfig) { c.AllowAllRegistries = true })},
		{name: "allow_official", trust: trust(func(c *ImageTrustConfig) { c.AllowOfficial = true })},
		{name: "bad registry host", trust: trust(func(c *ImageTrustConfig) { c.AllowedRegistries = []string{"https://ghcr.io"} }), wantErr: "allowed_registries entries must be bare registry hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, section := range []string{"container_create", "libpod_container_create"} {
				cfg := Defaults()
				switch section {
				case "container_create":
					cfg.RequestBody.ContainerCreate.ImageTrust = tt.trust
					cfg.RequestBody.ContainerCreate.AllowedImages = tt.images
				default:
					cfg.RequestBody.LibpodContainerCreate.ImageTrust = tt.trust
					cfg.RequestBody.LibpodContainerCreate.AllowedImages = tt.images
				}
				err := Validate(&cfg)
				switch {
				case tt.wantErr == "" && err != nil:
					t.Fatalf("%s: unexpected error: %v", section, err)
				case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
					t.Fatalf("%s: error = %v, want substring %q", section, err, tt.wantErr)
				}
			}
		})
	}
}

// TestValidateImageTrustConfig_InvalidMode checks that an unrecognized mode
// string returns an error identifying the field.
func TestValidateImageTrustConfig_InvalidMode(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "strict",
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid mode 'strict', got nil")
	}
	if !strings.Contains(err.Error(), "image_trust") {
		t.Fatalf("error should mention image_trust, got: %v", err)
	}
	if !strings.Contains(err.Error(), "strict") {
		t.Fatalf("error should mention the invalid value 'strict', got: %v", err)
	}
}

// TestValidateImageTrustConfig_EmptyPEM checks that an AllowedSigningKeys entry
// with an empty PEM is rejected.
func TestValidateImageTrustConfig_EmptyPEM(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "enforce",
		AllowedSigningKeys: []SigningKeyConfig{
			{PEM: ""},
		},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty PEM entry, got nil")
	}
	if !strings.Contains(err.Error(), "allowed_signing_keys[0].pem") {
		t.Fatalf("error should mention allowed_signing_keys[0].pem, got: %v", err)
	}
}

// TestValidateImageTrustConfig_InvalidSubjectPattern checks that a
// syntactically invalid SubjectPattern regex in an allowed_keyless entry is
// caught at validation time and not silently deferred to BuildConfig / New.
func TestValidateImageTrustConfig_InvalidSubjectPattern(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "enforce",
		AllowedKeyless: []KeylessConfig{
			{
				Issuer:         "https://accounts.google.com",
				SubjectPattern: "(*invalid",
			},
		},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid subject_pattern regex, got nil")
	}
	if !strings.Contains(err.Error(), "subject_pattern") {
		t.Fatalf("error should mention subject_pattern, got: %v", err)
	}
}
