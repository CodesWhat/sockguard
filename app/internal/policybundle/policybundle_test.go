package policybundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"regexp"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// generatePEM mints a fresh ECDSA P-256 keypair and returns the PEM-encoded
// public key.
func generatePEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := cryptoutils.MarshalPublicKeyToDER(priv.Public())
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// --- BuildConfig validation ---

func TestBuildConfig_DisabledReturnsNoopConfig(t *testing.T) {
	cfg, err := BuildConfig(RawConfig{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("Enabled must be false when raw.Enabled=false")
	}
	if cfg.AllowedSigningKeys != nil || cfg.AllowedKeyless != nil {
		t.Fatal("disabled config must carry no compiled material")
	}
}

func TestBuildConfig_EnabledRequiresAtLeastOneTrustEntry(t *testing.T) {
	_, err := BuildConfig(RawConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected error when Enabled=true and no trust entries are configured")
	}
}

func TestBuildConfig_RejectsMalformedPEM(t *testing.T) {
	_, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: "not-a-pem"}},
	})
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestBuildConfig_RejectsEmptyPEM(t *testing.T) {
	_, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: "   "}},
	})
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}
}

func TestBuildConfig_RejectsKeylessWithoutIssuer(t *testing.T) {
	_, err := BuildConfig(RawConfig{
		Enabled:        true,
		AllowedKeyless: []KeylessConfig{{SubjectPattern: ".*"}},
	})
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestBuildConfig_RejectsKeylessWithoutSubjectPattern(t *testing.T) {
	_, err := BuildConfig(RawConfig{
		Enabled:        true,
		AllowedKeyless: []KeylessConfig{{Issuer: "https://example.com"}},
	})
	if err == nil {
		t.Fatal("expected error for missing subject pattern")
	}
}

func TestBuildConfig_RejectsBadSubjectRegex(t *testing.T) {
	_, err := BuildConfig(RawConfig{
		Enabled: true,
		AllowedKeyless: []KeylessConfig{
			{Issuer: "https://example.com", SubjectPattern: "[unclosed"},
		},
	})
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
}

func TestBuildConfig_CompilesKeyedFingerprint(t *testing.T) {
	pemStr := generatePEM(t)
	cfg, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if len(cfg.AllowedSigningKeys) != 1 {
		t.Fatalf("signing keys count = %d, want 1", len(cfg.AllowedSigningKeys))
	}
	fp := cfg.AllowedSigningKeys[0].Fingerprint()
	if len(fp) != 64 {
		t.Fatalf("fingerprint = %q (len=%d), want 64-char hex", fp, len(fp))
	}
}

func TestBuildConfig_TimeoutParsing(t *testing.T) {
	pemStr := generatePEM(t)
	base := RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	}

	t.Run("valid 30s", func(t *testing.T) {
		raw := base
		raw.VerifyTimeoutStr = "30s"
		cfg, err := BuildConfig(raw)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if cfg.VerifyTimeout != 30*time.Second {
			t.Fatalf("timeout = %v, want 30s", cfg.VerifyTimeout)
		}
	})

	t.Run("zero rejected", func(t *testing.T) {
		raw := base
		raw.VerifyTimeoutStr = "0s"
		if _, err := BuildConfig(raw); err == nil {
			t.Fatal("expected error for zero timeout")
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		raw := base
		raw.VerifyTimeoutStr = "-1s"
		if _, err := BuildConfig(raw); err == nil {
			t.Fatal("expected error for negative timeout")
		}
	})

	t.Run("malformed rejected", func(t *testing.T) {
		raw := base
		raw.VerifyTimeoutStr = "notaduration"
		if _, err := BuildConfig(raw); err == nil {
			t.Fatal("expected error for malformed duration")
		}
	})
}

// --- New() invariants ---

func TestNew_KeylessRequiresTrustedMaterial(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: "https://example.com", SubjectPattern: regexp.MustCompile(`.*`)},
		},
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error when keyless identities configured but TrustedMaterial is nil")
	}
}

func TestDisabledVerifier_RejectsCalls(t *testing.T) {
	v, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatalf("New disabled: %v", err)
	}
	if _, err := v.Verify(context.Background(), []byte("hi"), nil); err == nil {
		t.Fatal("disabled verifier must reject calls so a wiring bug fails closed")
	}
}

// --- DigestYAML ---

func TestDigestYAML_Deterministic(t *testing.T) {
	got := DigestYAML([]byte("hello world"))
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got != want {
		t.Fatalf("DigestYAML(hello world) = %q, want %q", got, want)
	}
}

// --- Verify happy + sad paths via VirtualSigstore (keyless) ---

func TestVerify_KeylessHappyPath(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const issuer = "https://github.com/login/oauth"
	const subject = "ops@example.com"
	yaml := []byte("rules: []\n")

	entity, err := vs.Sign(subject, issuer, yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Enabled:               true,
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		VerifyTimeout:         VerifyTimeout,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^ops@example\.com$`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := v.Verify(context.Background(), yaml, entity)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.DigestHex != DigestYAML(yaml) {
		t.Fatalf("DigestHex = %q, want %q", res.DigestHex, DigestYAML(yaml))
	}
	if res.Signer == "" {
		t.Fatal("Signer must be populated on success")
	}
}

func TestVerify_TamperedYAMLRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const issuer = "https://github.com/login/oauth"
	const subject = "ops@example.com"
	signed := []byte("rules: []\n")
	entity, err := vs.Sign(subject, issuer, signed)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Enabled:               true,
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^ops@example\.com$`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tampered := []byte("rules: [evil]\n")
	if _, err := v.Verify(context.Background(), tampered, entity); err == nil {
		t.Fatal("expected verification to fail for tampered YAML")
	}
}

func TestVerify_IssuerMismatchRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	yaml := []byte("rules: []\n")
	entity, err := vs.Sign("ops@example.com", "https://wrong.issuer.com", yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Enabled:               true,
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: "https://accounts.google.com", SubjectPattern: regexp.MustCompile(`.*`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := v.Verify(context.Background(), yaml, entity); err == nil {
		t.Fatal("expected issuer mismatch to fail")
	}
}

func TestVerify_SubjectMismatchRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const issuer = "https://github.com/login/oauth"
	yaml := []byte("rules: []\n")
	entity, err := vs.Sign("unknown@example.com", issuer, yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Enabled:               true,
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^allowed@example\.com$`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := v.Verify(context.Background(), yaml, entity); err == nil {
		t.Fatal("expected SAN mismatch to fail")
	}
}

func TestVerify_NilEntityRejected(t *testing.T) {
	pemStr := generatePEM(t)
	cfg, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), []byte("rules: []\n"), nil); err == nil {
		t.Fatal("nil entity must be rejected")
	}
}

func TestVerify_EmptyYAMLRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, err := vs.Sign("ops@example.com", "https://example.com", []byte("anything"))
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}
	cfg := Config{
		Enabled:         true,
		TrustedMaterial: vs,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: "https://example.com", SubjectPattern: regexp.MustCompile(`.*`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), nil, entity); err == nil {
		t.Fatal("empty YAML must be rejected before any crypto work")
	}
}

// --- LoadBundle ---

func TestLoadBundle_MissingPathReturnsError(t *testing.T) {
	if _, err := LoadBundle("/nonexistent/bundle.json"); err == nil {
		t.Fatal("expected error for missing bundle file")
	}
}
