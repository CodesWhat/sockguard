package config

import (
	"strings"
	"testing"
)

func TestValidatePolicyBundleDisabledIsNoop(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = false
	cfg.PolicyBundle.AllowedSigningKeys = []PolicyBundleSigningKey{{PEM: ""}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(disabled bundle) = %v, want nil", err)
	}
}

func TestValidatePolicyBundleRequiresSignaturePath(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.AllowedSigningKeys = []PolicyBundleSigningKey{{PEM: "PEM-PLACEHOLDER"}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "policy_bundle.signature_path") {
		t.Fatalf("expected signature_path error, got %v", err)
	}
}

func TestValidatePolicyBundleRequiresAtLeastOneTrustEntry(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "allowed_signing_keys or allowed_keyless") {
		t.Fatalf("expected trust-entry error, got %v", err)
	}
}

func TestValidatePolicyBundleRejectsEmptyKeyPEM(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	cfg.PolicyBundle.AllowedSigningKeys = []PolicyBundleSigningKey{{PEM: "  "}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "allowed_signing_keys[0].pem") {
		t.Fatalf("expected empty-PEM error, got %v", err)
	}
}

func TestValidatePolicyBundleRejectsKeylessWithoutIssuer(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	cfg.PolicyBundle.AllowedKeyless = []PolicyBundleKeyless{{SubjectPattern: ".*"}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "allowed_keyless[0].issuer") {
		t.Fatalf("expected missing-issuer error, got %v", err)
	}
}

func TestValidatePolicyBundleRejectsBadSubjectRegex(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	cfg.PolicyBundle.AllowedKeyless = []PolicyBundleKeyless{
		{Issuer: "https://example.com", SubjectPattern: "[unclosed"},
	}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "allowed_keyless[0].subject_pattern") {
		t.Fatalf("expected bad-regex error, got %v", err)
	}
}

func TestValidatePolicyBundleRejectsZeroTimeout(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	cfg.PolicyBundle.AllowedSigningKeys = []PolicyBundleSigningKey{{PEM: "PEM"}}
	cfg.PolicyBundle.VerifyTimeout = "0s"
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "verify_timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestValidatePolicyBundleAcceptsCompleteConfig(t *testing.T) {
	cfg := Defaults()
	cfg.PolicyBundle.Enabled = true
	cfg.PolicyBundle.SignaturePath = "/etc/sockguard/cfg.bundle.json"
	cfg.PolicyBundle.AllowedSigningKeys = []PolicyBundleSigningKey{{PEM: "PEM-PLACEHOLDER"}}
	cfg.PolicyBundle.VerifyTimeout = "15s"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate(complete bundle) = %v, want nil", err)
	}
}
