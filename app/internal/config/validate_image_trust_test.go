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
	}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected no error for enforce mode with a signing key, got: %v", err)
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

// TestValidateImageTrustConfig_InvalidSubjectPattern documents that the current
// validateImageTrustConfig implementation does NOT compile the SubjectPattern
// regex — it only checks for emptiness. An invalid pattern like "[unclosed"
// therefore passes validation. This test pins the current behavior; the gap
// (no compile-time regex check) is a known coverage finding.
func TestValidateImageTrustConfig_InvalidSubjectPattern(t *testing.T) {
	cfg := Defaults()
	cfg.RequestBody.ContainerCreate.ImageTrust = ImageTrustConfig{
		Mode: "enforce",
		AllowedKeyless: []KeylessConfig{
			{
				Issuer:         "https://accounts.google.com",
				SubjectPattern: "[unclosed",
			},
		},
	}

	// validateImageTrustConfig only checks for an empty subject_pattern; it does
	// NOT compile the regex. A syntactically invalid pattern passes validation and
	// would only fail later at BuildConfig / New time.
	err := Validate(&cfg)
	if err != nil {
		t.Fatalf("current validator does not check regex syntax: unexpected error: %v", err)
	}
}
