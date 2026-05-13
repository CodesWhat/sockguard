package imagetrust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// artDigest returns the sha256 hex digest of artifact (no prefix).
func artDigest(artifact []byte) string {
	h := sha256.Sum256(artifact)
	return hex.EncodeToString(h[:])
}

// generateECDSAKey generates a fresh ECDSA P-256 keypair.
// Returns the PEM-encoded public key and the private key.
func generateECDSAKey(t *testing.T) (pemStr string, priv *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := cryptoutils.MarshalPublicKeyToDER(privKey.Public())
	if err != nil {
		t.Fatalf("marshal public key DER: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(block), privKey
}

// alwaysFailVerifier is a test stub Verifier that always returns an error.
type alwaysFailVerifier struct{}

func (a *alwaysFailVerifier) Verify(_ context.Context, imageRef, _ string, _ verify.SignedEntity) error {
	return errors.New("stubbed verification failure for " + imageRef)
}

var _ Verifier = (*alwaysFailVerifier)(nil)

// --- Config validation ---

func TestBuildConfigValidation(t *testing.T) {
	t.Run("mode off accepted with no keys", func(t *testing.T) {
		cfg, err := BuildConfig(RawConfig{Mode: ModeOff})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeOff {
			t.Fatalf("mode = %q, want off", cfg.Mode)
		}
	})

	t.Run("mode enforce with no verifiers rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{Mode: ModeEnforce})
		if err == nil {
			t.Fatal("expected error for enforce with no verifiers")
		}
	})

	t.Run("mode warn with no verifiers rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{Mode: ModeWarn})
		if err == nil {
			t.Fatal("expected error for warn with no verifiers")
		}
	})

	t.Run("invalid mode string rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{Mode: "strict"})
		if err == nil {
			t.Fatal("expected error for invalid mode string")
		}
	})

	t.Run("malformed PEM rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{
			Mode:               ModeEnforce,
			AllowedSigningKeys: []SigningKeyConfig{{PEM: "not-a-pem"}},
		})
		if err == nil {
			t.Fatal("expected error for malformed PEM")
		}
	})

	t.Run("malformed subject_pattern regex rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{
			Mode: ModeEnforce,
			AllowedKeyless: []KeylessConfig{
				{Issuer: "https://example.com", SubjectPattern: "[unclosed"},
			},
		})
		if err == nil {
			t.Fatal("expected error for bad regex")
		}
	})

	t.Run("valid keyed config compiles 64-char fingerprint", func(t *testing.T) {
		pemStr, _ := generateECDSAKey(t)
		cfg, err := BuildConfig(RawConfig{
			Mode:               ModeEnforce,
			AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.AllowedSigningKeys) != 1 {
			t.Fatalf("signing keys count = %d, want 1", len(cfg.AllowedSigningKeys))
		}
		fp := cfg.AllowedSigningKeys[0].Fingerprint()
		if len(fp) != 64 {
			t.Fatalf("fingerprint = %q (len=%d), want 64-char hex", fp, len(fp))
		}
	})

	t.Run("empty PEM entry rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{
			Mode:               ModeEnforce,
			AllowedSigningKeys: []SigningKeyConfig{{PEM: "  "}},
		})
		if err == nil {
			t.Fatal("expected error for empty PEM")
		}
	})

	t.Run("missing issuer in keyless entry rejected", func(t *testing.T) {
		_, err := BuildConfig(RawConfig{
			Mode: ModeEnforce,
			AllowedKeyless: []KeylessConfig{
				{SubjectPattern: ".*"},
			},
		})
		if err == nil {
			t.Fatal("expected error for missing issuer")
		}
	})
}

// --- mode=off ---

func TestModeOff_NoopVerifier(t *testing.T) {
	cfg := Config{Mode: ModeOff}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// nil entity must succeed in mode=off (no network calls should occur).
	if err := v.Verify(context.Background(), "example.com/img:latest", "deadbeef", nil); err != nil {
		t.Fatalf("mode=off verify: %v", err)
	}
}

func TestVerifyWithMode_Off_AlwaysAllows(t *testing.T) {
	cfg := Config{Mode: ModeOff}
	outcome := VerifyWithMode(context.Background(), &offVerifier{}, cfg, nil, "img:latest", "abc", nil)
	if !outcome.Allowed {
		t.Fatal("mode=off must always allow")
	}
	if outcome.Verifier != "off" {
		t.Fatalf("outcome.Verifier = %q, want off", outcome.Verifier)
	}
}

// --- mode=warn ---

// TestVerifyWithMode_Warn_AllowsOnFailure ensures that a verification failure
// in warn mode does NOT deny the request; instead it logs and returns Allowed=true.
func TestVerifyWithMode_Warn_AllowsOnFailure(t *testing.T) {
	pemStr, _ := generateECDSAKey(t)
	cfg, err := BuildConfig(RawConfig{
		Mode:               ModeWarn,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	outcome := VerifyWithMode(context.Background(), &alwaysFailVerifier{}, cfg, slog.Default(), "img:latest", "abc", nil)
	if !outcome.Allowed {
		t.Fatal("mode=warn must allow even when verification fails")
	}
	if outcome.Verifier != "warn-bypass" {
		t.Fatalf("outcome.Verifier = %q, want warn-bypass", outcome.Verifier)
	}
	if outcome.FailureMsg == "" {
		t.Fatal("FailureMsg must be populated on warn bypass")
	}
}

// --- mode=enforce ---

// TestVerifyWithMode_Enforce_DeniesOnFailure ensures that a verification
// failure in enforce mode returns Allowed=false.
func TestVerifyWithMode_Enforce_DeniesOnFailure(t *testing.T) {
	pemStr, _ := generateECDSAKey(t)
	cfg, err := BuildConfig(RawConfig{
		Mode:               ModeEnforce,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	outcome := VerifyWithMode(context.Background(), &alwaysFailVerifier{}, cfg, nil, "img:latest", "abc", nil)
	if outcome.Allowed {
		t.Fatal("mode=enforce must deny on verification failure")
	}
	if outcome.Verifier != "denied" {
		t.Fatalf("outcome.Verifier = %q, want denied", outcome.Verifier)
	}
}

// TestNilEntityDeniedWithDescription ensures that a nil entity returns a
// descriptive error so the log record is useful.
func TestNilEntityDeniedWithDescription(t *testing.T) {
	pemStr, _ := generateECDSAKey(t)
	cfg, err := BuildConfig(RawConfig{
		Mode:               ModeEnforce,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = v.Verify(context.Background(), "example.com/img:latest", "abc123", nil)
	if err == nil {
		t.Fatal("expected error for nil entity, got nil")
	}
}

// --- keyless verification using VirtualSigstore ---

// TestKeylessVerification_Success verifies that an image signed with the
// correct issuer and identity passes enforcement.
func TestKeylessVerification_Success(t *testing.T) {
	artifact := []byte("my image manifest content for keyless")
	digestHex := artDigest(artifact)

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	const issuer = "https://github.com/login/oauth"
	const subject = "test@example.com"

	entity, err := vs.Sign(subject, issuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Mode:            ModeEnforce,
		TrustedMaterial: vs,
		AllowedKeyless: []KeylessIdentity{
			{
				IssuerExact:    issuer,
				SubjectPattern: regexp.MustCompile(`^test@example\.com$`),
			},
		},
		RequireRekorInclusion: true,
		VerifyTimeout:         VerifyTimeout,
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := v.Verify(context.Background(), "example.com/img@sha256:"+digestHex, digestHex, entity); err != nil {
		t.Fatalf("keyless verify success: %v", err)
	}
}

// TestKeylessVerification_IssuerMismatch checks that a signature from the
// wrong OIDC issuer is rejected.
func TestKeylessVerification_IssuerMismatch(t *testing.T) {
	artifact := []byte("manifest data - issuer mismatch test")
	digestHex := artDigest(artifact)

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	// Signed with the WRONG issuer.
	entity, err := vs.Sign("test@example.com", "https://wrong.issuer.com", artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Mode:            ModeEnforce,
		TrustedMaterial: vs,
		AllowedKeyless: []KeylessIdentity{
			{
				IssuerExact:    "https://accounts.google.com",
				SubjectPattern: regexp.MustCompile(`.*`),
			},
		},
		RequireRekorInclusion: true,
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = v.Verify(context.Background(), "example.com/img@sha256:"+digestHex, digestHex, entity)
	if err == nil {
		t.Fatal("expected issuer mismatch to fail, got nil")
	}
}

// TestKeylessVerification_SubjectMismatch checks that a signature whose SAN
// does not match the configured pattern is rejected.
func TestKeylessVerification_SubjectMismatch(t *testing.T) {
	artifact := []byte("manifest data - subject mismatch test")
	digestHex := artDigest(artifact)

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	const issuer = "https://github.com/login/oauth"

	// Signed with an identity that does NOT match the policy's allowed pattern.
	entity, err := vs.Sign("unknown@example.com", issuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Mode:            ModeEnforce,
		TrustedMaterial: vs,
		AllowedKeyless: []KeylessIdentity{
			{
				IssuerExact:    issuer,
				SubjectPattern: regexp.MustCompile(`^allowed@example\.com$`),
			},
		},
		RequireRekorInclusion: true,
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = v.Verify(context.Background(), "example.com/img@sha256:"+digestHex, digestHex, entity)
	if err == nil {
		t.Fatal("expected subject mismatch to fail, got nil")
	}
}

// TestKeyedVerification_WrongKeyFails checks that a keyed verifier rejects
// a bundle signed with a different key.
func TestKeyedVerification_WrongKeyFails(t *testing.T) {
	artifact := []byte("some manifest bytes for keyed mismatch")
	digestHex := artDigest(artifact)

	// Generate key A — the one in the policy.
	privA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	verifierA, err := sigsig.LoadECDSAVerifier(&privA.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("LoadECDSAVerifier A: %v", err)
	}

	// VirtualSigstore uses its own keys (not key A) to sign.
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	entity, err := vs.Sign("user@example.com", "https://accounts.google.com", artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	// Policy: only trust key A, but entity is signed with VirtualSigstore's cert.
	cfg := Config{
		Mode: ModeEnforce,
		AllowedSigningKeys: []KeyedVerifier{
			{verifier: verifierA, fingerprint: "aabbccdd"},
		},
	}
	sv := &sigstoreVerifier{cfg: cfg}
	digestBytes, _ := hex.DecodeString(digestHex)

	err = sv.verifyKeyed(context.Background(), entity, digestBytes, cfg.AllowedSigningKeys[0])
	if err == nil {
		t.Fatal("expected keyed verify to fail with cert-backed bundle against raw-key verifier")
	}
}

// TestBuildConfigTimeout validates the verify_timeout field parsing.
func TestBuildConfigTimeout(t *testing.T) {
	pemStr, _ := generateECDSAKey(t)
	base := RawConfig{
		Mode:               ModeEnforce,
		AllowedSigningKeys: []SigningKeyConfig{{PEM: pemStr}},
	}

	t.Run("valid 30s", func(t *testing.T) {
		raw := base
		raw.VerifyTimeoutStr = "30s"
		cfg, err := BuildConfig(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
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

// --- multi-verifier fallback chain ---

// TestVerify_KeyedFallsBackToKeyless checks that when all keyed verifiers fail
// the sigstoreVerifier falls through to the keyless list and succeeds if a
// keyless identity matches.
func TestVerify_KeyedFallsBackToKeyless(t *testing.T) {
	artifact := []byte("fallback-chain artifact payload")
	digestHex := artDigest(artifact)

	// Generate a random ECDSA key for the keyed policy entry. The keyless
	// entity signed by VirtualSigstore won't match this key, so keyed
	// verification must fail and the verifier must fall through.
	_, privA := generateECDSAKey(t)
	verifierA, err := sigsig.LoadECDSAVerifier(&privA.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("LoadECDSAVerifier: %v", err)
	}

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	const issuer = "https://github.com/login/oauth"
	const subject = "ci-bot@example.com"

	entity, err := vs.Sign(subject, issuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Mode: ModeEnforce,
		// Wrong key — keyed verification will fail.
		AllowedSigningKeys: []KeyedVerifier{
			{verifier: verifierA, fingerprint: "wrongkey"},
		},
		// Correct keyless identity — keyless verification must succeed.
		AllowedKeyless: []KeylessIdentity{
			{
				IssuerExact:    issuer,
				SubjectPattern: regexp.MustCompile(`^ci-bot@example\.com$`),
			},
		},
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		VerifyTimeout:         VerifyTimeout,
	}

	sv := &sigstoreVerifier{cfg: cfg}
	if err := sv.Verify(context.Background(), "example.com/img@sha256:"+digestHex, digestHex, entity); err != nil {
		t.Fatalf("expected keyed→keyless fallback to succeed, got: %v", err)
	}
}

// TestVerify_AllVerifiersFail_CompositeError checks that when both keyed and
// keyless verification fail the returned error contains both "keyed:" and
// "keyless:" substrings so operators can diagnose which leg(s) failed.
func TestVerify_AllVerifiersFail_CompositeError(t *testing.T) {
	artifact := []byte("composite error artifact payload")
	digestHex := artDigest(artifact)

	_, privA := generateECDSAKey(t)
	verifierA, err := sigsig.LoadECDSAVerifier(&privA.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("LoadECDSAVerifier: %v", err)
	}

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	// Sign with one issuer, but policy only trusts a different issuer.
	entity, err := vs.Sign("ci-bot@example.com", "https://github.com/login/oauth", artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	cfg := Config{
		Mode: ModeEnforce,
		// Wrong key — keyed verification fails.
		AllowedSigningKeys: []KeyedVerifier{
			{verifier: verifierA, fingerprint: "wrongkey2"},
		},
		// Wrong issuer — keyless verification also fails.
		AllowedKeyless: []KeylessIdentity{
			{
				IssuerExact:    "https://accounts.google.com",
				SubjectPattern: regexp.MustCompile(`.*`),
			},
		},
		TrustedMaterial:       vs,
		RequireRekorInclusion: true,
		VerifyTimeout:         VerifyTimeout,
	}

	sv := &sigstoreVerifier{cfg: cfg}
	verifyErr := sv.Verify(context.Background(), "example.com/img@sha256:"+digestHex, digestHex, entity)
	if verifyErr == nil {
		t.Fatal("expected both verifiers to fail, got nil error")
	}
	if !strings.Contains(verifyErr.Error(), "keyed:") {
		t.Fatalf("error should contain 'keyed:' substring, got: %v", verifyErr)
	}
	if !strings.Contains(verifyErr.Error(), "keyless:") {
		t.Fatalf("error should contain 'keyless:' substring, got: %v", verifyErr)
	}
}
