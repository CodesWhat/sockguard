package policybundle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// generatePEM mints a fresh ECDSA P-256 keypair and returns the PEM-encoded
// public key.
func generatePEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// --- BuildConfig validation ---

func TestBuildConfig_DisabledReturnsNoopConfig(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	_, err := BuildConfig(RawConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected error when Enabled=true and no trust entries are configured")
	}
}

func TestBuildConfig_RejectsMalformedPEM(t *testing.T) {
	t.Parallel()
	_, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: "not-a-pem"}},
	})
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestBuildConfig_RejectsEmptyPEM(t *testing.T) {
	t.Parallel()
	_, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: "   "}},
	})
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}
}

func TestBuildConfig_RejectsKeylessWithoutIssuer(t *testing.T) {
	t.Parallel()
	_, err := BuildConfig(RawConfig{
		Enabled:        true,
		AllowedKeyless: []KeylessConfig{{SubjectPattern: ".*"}},
	})
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestBuildConfig_RejectsKeylessWithoutSubjectPattern(t *testing.T) {
	t.Parallel()
	_, err := BuildConfig(RawConfig{
		Enabled:        true,
		AllowedKeyless: []KeylessConfig{{Issuer: "https://example.com"}},
	})
	if err == nil {
		t.Fatal("expected error for missing subject pattern")
	}
}

func TestBuildConfig_RejectsBadSubjectRegex(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	v, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatalf("New disabled: %v", err)
	}
	if _, err := v.Verify(context.Background(), []byte("hi"), nil); err == nil {
		t.Fatal("disabled verifier must reject calls so a wiring bug fails closed")
	}
}

// --- Verify happy + sad paths via VirtualSigstore (keyless) ---

func TestVerify_KeylessHappyPath(t *testing.T) {
	t.Parallel()
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
	wantDigest := sha256.Sum256(yaml)
	wantDigestHex := hex.EncodeToString(wantDigest[:])
	if res.DigestHex != wantDigestHex {
		t.Fatalf("DigestHex = %q, want %q", res.DigestHex, wantDigestHex)
	}
	wantSigner := "keyless:" + issuer + ":" + subject
	if res.Signer != wantSigner {
		t.Fatalf("Signer = %q, want verified certificate identity %q", res.Signer, wantSigner)
	}
}

// TestVerify_KeylessOrdinaryFailureFallsThroughToSecond ensures that when a
// keyless identity fails verification for an ordinary (non-canceled) reason,
// the fallback loop continues on to the next configured identity rather than
// treating the failure as a context cancellation and aborting the chain.
func TestVerify_KeylessOrdinaryFailureFallsThroughToSecond(t *testing.T) {
	t.Parallel()
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
			// Wrong issuer — must fail without aborting the fallback.
			{IssuerExact: "https://accounts.google.com", SubjectPattern: regexp.MustCompile(`.*`)},
			// Correct identity — must still be reached.
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^ops@example\.com$`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := v.Verify(context.Background(), yaml, entity)
	if err != nil {
		t.Fatalf("expected fallback to the second keyless identity to succeed, got: %v", err)
	}
	wantSigner := "keyless:" + issuer + ":" + subject
	if res.Signer != wantSigner {
		t.Fatalf("Signer = %q, want %q", res.Signer, wantSigner)
	}
}

func TestVerify_RejectsCanceledContext(t *testing.T) {
	t.Parallel()
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
	v, err := New(Config{
		Enabled:         true,
		TrustedMaterial: vs,
		VerifyTimeout:   VerifyTimeout,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^ops@example\.com$`)},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(ctx, yaml, entity); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify error = %v, want context canceled", err)
	}
}

func TestVerify_TamperedYAMLRejected(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	if _, err := LoadBundle("/nonexistent/bundle.json"); err == nil {
		t.Fatal("expected error for missing bundle file")
	}
}

// --- RequireRekorInclusion=false paths ---

// TestVerify_RekorNotRequired_AcceptsBundle verifies that setting
// RequireRekorInclusion=false does not prevent an otherwise-valid bundle from
// passing. VirtualSigstore embeds a tlog entry in every entity it produces,
// so this test confirms we don't FAIL when the log-presence requirement is
// relaxed — i.e. the flag only disables a mandatory check, not the whole
// keyless path.
func TestVerify_RekorNotRequired_AcceptsBundle(t *testing.T) {
	t.Parallel()
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
		RequireRekorInclusion: false,
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
	if res.Signer == "" {
		t.Fatal("Signer must be populated on success")
	}
}

// TestVerify_RekorNotRequired_StillRejectsBadIdentity is the security-relevant
// assertion: relaxing RequireRekorInclusion must NOT relax identity binding.
// A certificate whose issuer or SAN does not match AllowedKeyless must still
// be rejected even when the transparency-log requirement is off.
func TestVerify_RekorNotRequired_StillRejectsBadIdentity(t *testing.T) {
	t.Parallel()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const issuer = "https://github.com/login/oauth"
	yaml := []byte("rules: []\n")

	// Sign with a subject that does NOT match the configured AllowedKeyless pattern.
	entity, err := vs.Sign("attacker@evil.com", issuer, yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Enabled:               true,
		TrustedMaterial:       vs,
		RequireRekorInclusion: false,
		VerifyTimeout:         VerifyTimeout,
		AllowedKeyless: []KeylessIdentity{
			{IssuerExact: issuer, SubjectPattern: regexp.MustCompile(`^ops@example\.com$`)},
		},
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := v.Verify(context.Background(), yaml, entity); err == nil {
		t.Fatal("expected SAN mismatch to fail even when RequireRekorInclusion=false")
	}
}

// TestVerify_KeyedBranchExecutes covers the keyed verification path. We can't
// produce a "keyed" SignedEntity via the testing/ca helpers (they emit
// Fulcio-cert-bound entities), so instead we point a keyed-only config at a
// keyless-signed entity and assert the failure mentions the keyed branch.
// That proves verifyKeyed actually ran and returned its error rather than
// being short-circuited before invocation.
func TestVerify_KeyedBranchExecutes(t *testing.T) {
	t.Parallel()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	yaml := []byte("rules: []\n")
	entity, err := vs.Sign("ops@example.com", "https://github.com/login/oauth", yaml)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	pemStr := generatePEM(t)
	cfg, err := BuildConfig(RawConfig{
		Enabled:            true,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg.AllowedSigningKeys[0].fingerprint = "wrongkey1"
	cfg.AllowedSigningKeys = append(cfg.AllowedSigningKeys, KeyedVerifier{
		verifier:    cfg.AllowedSigningKeys[0].verifier,
		fingerprint: "wrongkey2",
	})
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Verify(context.Background(), yaml, entity)
	if err == nil {
		t.Fatal("expected verification failure: keyless-signed entity against keyed-only config")
	}
	if !strings.Contains(err.Error(), "keyed:") {
		t.Fatalf("expected error to mention the keyed branch, got %v", err)
	}
	for _, fingerprint := range []string{"wrongkey1", "wrongkey2"} {
		if !strings.Contains(err.Error(), fingerprint) {
			t.Fatalf("error should identify attempted key %q, got: %v", fingerprint, err)
		}
	}
}

// newKeyedPEMPair mints an ECDSA P-256 keypair and returns the private key and
// the PEM-encoded public key.
func newKeyedPEMPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signKeyedBundle signs yaml with priv and returns a genuine raw-key sigstore
// bundle (message signature plus a public-key hint, no certificate).
func signKeyedBundle(t *testing.T, priv *ecdsa.PrivateKey, yaml []byte) *bundle.Bundle {
	t.Helper()
	signer, err := sigsig.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("LoadECDSASignerVerifier: %v", err)
	}
	sig, err := signer.SignMessage(bytes.NewReader(yaml))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	digest := sha256.Sum256(yaml)
	b, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test-key"},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sig,
			},
		},
	})
	if err != nil {
		t.Fatalf("bundle.NewBundle: %v", err)
	}
	return b
}

func newKeyedVerifier(t *testing.T, pems ...string) (Verifier, Config) {
	t.Helper()
	keys := make([]SigningKeyConfig, 0, len(pems))
	for _, p := range pems {
		keys = append(keys, SigningKeyConfig{PEM: p})
	}
	cfg, err := BuildConfig(RawConfig{Enabled: true, AllowedSigningKeys: keys})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v, cfg
}

// TestVerify_KeyedTrustedAndUntrustedKeys proves a bundle signed by key B is
// accepted only while B is trusted: trusting an independent key A must fail
// closed with an empty result.
func TestVerify_KeyedTrustedAndUntrustedKeys(t *testing.T) {
	t.Parallel()
	yaml := []byte("rules: []\n")
	privB, pemB := newKeyedPEMPair(t)
	_, pemA := newKeyedPEMPair(t)
	entity := signKeyedBundle(t, privB, yaml)

	trusted, _ := newKeyedVerifier(t, pemB)
	if _, err := trusted.Verify(context.Background(), yaml, entity); err != nil {
		t.Fatalf("Verify with the signing key trusted: %v", err)
	}

	untrusted, _ := newKeyedVerifier(t, pemA)
	res, err := untrusted.Verify(context.Background(), yaml, entity)
	if err == nil {
		t.Fatal("expected a bundle signed by an untrusted key to be rejected")
	}
	if !strings.Contains(err.Error(), "keyed:") {
		t.Fatalf("error should come from the keyed branch, got %v", err)
	}
	if res != (VerifyResult{}) {
		t.Fatalf("result = %+v, want empty on rejection", res)
	}
}

// TestVerify_KeyedHappyPath pins the keyed success return: signer fingerprint,
// exact YAML digest, and fallthrough past a wrong first key.
func TestVerify_KeyedHappyPath(t *testing.T) {
	t.Parallel()
	yaml := []byte("rules:\n  - match: {method: GET, path: /_ping}\n    action: allow\n")
	privB, pemB := newKeyedPEMPair(t)
	_, pemA := newKeyedPEMPair(t)
	entity := signKeyedBundle(t, privB, yaml)

	v, cfg := newKeyedVerifier(t, pemA, pemB)
	res, err := v.Verify(context.Background(), yaml, entity)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantSigner := "keyed:" + cfg.AllowedSigningKeys[1].Fingerprint()
	if res.Signer != wantSigner {
		t.Fatalf("Signer = %q, want %q (the second, matching key)", res.Signer, wantSigner)
	}
	sum := sha256.Sum256(yaml)
	if res.DigestHex != hex.EncodeToString(sum[:]) {
		t.Fatalf("DigestHex = %q, want %q", res.DigestHex, hex.EncodeToString(sum[:]))
	}

	// A different YAML payload must not verify against the same signature.
	if _, err := v.Verify(context.Background(), append(yaml, '#'), entity); err == nil {
		t.Fatal("expected a tampered YAML payload to be rejected")
	}
}

// TestLoadBundle_ValidKeyedBundleRoundTrip serializes a genuine keyed bundle to
// disk, loads it with the production LoadBundle, and verifies the result.
func TestLoadBundle_ValidKeyedBundleRoundTrip(t *testing.T) {
	t.Parallel()
	yaml := []byte("rules: []\n")
	priv, pemStr := newKeyedPEMPair(t)
	raw, err := signKeyedBundle(t, priv, yaml).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "policy.bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	entity, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if entity == nil {
		t.Fatal("LoadBundle returned a nil entity")
	}
	v, _ := newKeyedVerifier(t, pemStr)
	if _, err := v.Verify(context.Background(), yaml, entity); err != nil {
		t.Fatalf("Verify of the loaded bundle: %v", err)
	}
}
