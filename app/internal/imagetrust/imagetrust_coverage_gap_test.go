package imagetrust

import (
	"context"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// TestVerify_NoVerifiersConfiguredReturnsError mirrors the policybundle
// "no verifiers configured" branch test for image trust: enforce mode with
// empty key/keyless lists is rejected by BuildConfig, so we construct the
// verifier struct directly to land in the final error branch.
func TestVerify_NoVerifiersConfiguredReturnsError(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	digest := "1111111111111111111111111111111111111111111111111111111111111111"
	entity, err := vs.Sign("ops@example.com", "https://github.com/login/oauth", []byte("x"))
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	v := &sigstoreVerifier{cfg: Config{Mode: ModeEnforce}}
	err = v.Verify(context.Background(), "registry.example.com/app:tag", "sha256:"+digest, entity)
	if err == nil {
		t.Fatal("Verify with empty key/keyless lists returned nil error")
	}
	if !strings.Contains(err.Error(), "no verifiers configured") {
		t.Errorf("err = %q, want \"no verifiers configured\"", err.Error())
	}
}

// TestVerify_InvalidDigestHexReturnsError covers the digest-decode branch
// in sigstoreVerifier.Verify.
func TestVerify_InvalidDigestHexReturnsError(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, err := vs.Sign("ops@example.com", "https://github.com/login/oauth", []byte("x"))
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	v := &sigstoreVerifier{cfg: Config{Mode: ModeEnforce}}
	err = v.Verify(context.Background(), "registry.example.com/app:tag", "sha256:not-hex", entity)
	if err == nil {
		t.Fatal("Verify with invalid digest hex returned nil")
	}
	if !strings.Contains(err.Error(), "invalid digest") {
		t.Errorf("err = %q, want \"invalid digest\"", err.Error())
	}
}

// TestVerifyKeyless_RequiresTrustedMaterial directly exercises the
// "TrustedMaterial is nil" guard inside verifyKeyless. The for-loop in
// Verify only reaches verifyKeyless when there are AllowedKeyless entries,
// so we configure one and leave TrustedMaterial nil to hit the early return.
func TestVerifyKeyless_RequiresTrustedMaterial(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	digest := "1111111111111111111111111111111111111111111111111111111111111111"
	entity, err := vs.Sign("ops@example.com", "https://github.com/login/oauth", []byte("x"))
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg, err := BuildConfig(RawConfig{
		Mode: ModeEnforce,
		AllowedKeyless: []KeylessConfig{
			{Issuer: "https://example.com", SubjectPattern: `^ops@example\.com$`},
		},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	// TrustedMaterial intentionally left nil to hit the guard.
	cfg.TrustedMaterial = nil

	v := &sigstoreVerifier{cfg: cfg}
	err = v.Verify(context.Background(), "registry.example.com/app:tag", "sha256:"+digest, entity)
	if err == nil {
		t.Fatal("Verify with nil TrustedMaterial returned nil")
	}
	if !strings.Contains(err.Error(), "TrustedMaterial") {
		t.Errorf("err = %q, want a TrustedMaterial complaint", err.Error())
	}
}
