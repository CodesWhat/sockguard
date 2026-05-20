package sigverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TestCompileKey covers the PEM parsing surface: trimmed empty input,
// malformed PEM, a PEM that isn't a public key, and a happy path that
// also confirms CompileKey emits the SPKI sha256 fingerprint callers
// rely on for audit logs.
func TestCompileKey(t *testing.T) {
	t.Run("empty pem after trim is rejected", func(t *testing.T) {
		_, _, err := CompileKey("   \n\t  ")
		if err == nil || !strings.Contains(err.Error(), "pem is empty") {
			t.Fatalf("CompileKey(blank) error = %v, want pem-is-empty", err)
		}
	})

	t.Run("non-PEM input is rejected", func(t *testing.T) {
		_, _, err := CompileKey("not pem at all")
		if err == nil || !strings.Contains(err.Error(), "pem:") {
			t.Fatalf("CompileKey(non-pem) error = %v, want pem-decode error", err)
		}
	})

	t.Run("PEM block that is not a public key is rejected", func(t *testing.T) {
		// A valid PEM block, but the body isn't a SubjectPublicKeyInfo —
		// cryptoutils.UnmarshalPEMToPublicKey rejects it.
		bogus := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-a-spki")})
		_, _, err := CompileKey(string(bogus))
		if err == nil || !strings.Contains(err.Error(), "pem:") {
			t.Fatalf("CompileKey(bogus-spki) error = %v, want pem-decode error", err)
		}
	})

	t.Run("valid public key compiles and fingerprint matches DER SHA-256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
		if err != nil {
			t.Fatalf("MarshalPublicKeyToPEM: %v", err)
		}
		der, err := cryptoutils.MarshalPublicKeyToDER(priv.Public())
		if err != nil {
			t.Fatalf("MarshalPublicKeyToDER: %v", err)
		}
		want := sha256.Sum256(der)
		wantHex := hex.EncodeToString(want[:])

		verifier, gotHex, err := CompileKey(string(pubPEM))
		if err != nil {
			t.Fatalf("CompileKey(valid) error = %v", err)
		}
		if verifier == nil {
			t.Fatal("CompileKey(valid) returned nil verifier")
		}
		if gotHex != wantHex {
			t.Fatalf("fingerprint = %s, want %s", gotHex, wantHex)
		}
	})
}

// TestCompileKeyless covers the keyless-identity config surface: each
// of the two required fields rejected when empty (or whitespace-only),
// the regex compile error path, and a happy path that confirms the
// returned issuer is whitespace-trimmed and the compiled pattern
// round-trips.
func TestCompileKeyless(t *testing.T) {
	t.Run("empty issuer is rejected", func(t *testing.T) {
		_, _, err := CompileKeyless("  \n", "^.+$")
		if err == nil || !strings.Contains(err.Error(), "issuer is required") {
			t.Fatalf("CompileKeyless(empty issuer) error = %v, want issuer-required", err)
		}
	})

	t.Run("empty subject_pattern is rejected", func(t *testing.T) {
		_, _, err := CompileKeyless("https://example.com", "\t")
		if err == nil || !strings.Contains(err.Error(), "subject_pattern is required") {
			t.Fatalf("CompileKeyless(empty pattern) error = %v, want subject-pattern-required", err)
		}
	})

	t.Run("invalid regex is rejected", func(t *testing.T) {
		_, _, err := CompileKeyless("https://example.com", "([")
		if err == nil || !strings.Contains(err.Error(), "subject_pattern:") {
			t.Fatalf("CompileKeyless(bad regex) error = %v, want subject-pattern compile error", err)
		}
	})

	t.Run("valid issuer + pattern compile", func(t *testing.T) {
		issuer, re, err := CompileKeyless("  https://accounts.google.com  ", `^ops@example\.com$`)
		if err != nil {
			t.Fatalf("CompileKeyless(valid): %v", err)
		}
		if issuer != "https://accounts.google.com" {
			t.Fatalf("issuer = %q, want trimmed form", issuer)
		}
		if re == nil || !re.MatchString("ops@example.com") {
			t.Fatalf("compiled pattern does not match expected SAN")
		}
		if re.MatchString("attacker@elsewhere.io") {
			t.Fatal("compiled pattern matches a SAN it should reject")
		}
	})
}

// TestVerifyKeylessRequiresTrustedMaterial pins the explicit nil-guard
// at the top of VerifyKeyless. The higher-level imagetrust /
// policybundle paths construct verifiers that won't reach this branch
// with a nil material, but VerifyKeyless is exported and a future
// caller that forgets to inject TUF roots must fail closed.
func TestVerifyKeylessRequiresTrustedMaterial(t *testing.T) {
	err := VerifyKeyless(nil, nil, nil, "https://accounts.google.com", regexp.MustCompile(`^ops@example\.com$`), false)
	if err == nil || !strings.Contains(err.Error(), "TrustedMaterial") {
		t.Fatalf("VerifyKeyless(nil material) error = %v, want TrustedMaterial complaint", err)
	}
}

// TestVerifyKeylessIssuerMismatch confirms VerifyKeyless rejects a
// bundle whose Fulcio certificate's issuer does not match the
// configured issuerExact. The defensive belt-and-suspenders check at
// the bottom of VerifyKeyless layers on top of sigstore-go's matcher;
// asserting the rejection happens at all is the TQ-17b coverage gap.
func TestVerifyKeylessIssuerMismatch(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const signSubject = "ops@example.com"
	const signIssuer = "https://github.com/login/oauth"

	artifact := []byte("manifest contents for issuer-mismatch test")
	digest := sha256.Sum256(artifact)

	entity, err := vs.Sign(signSubject, signIssuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	// Verify with a *different* issuer; sigstore-go's matcher rejects
	// before our belt-and-suspenders fires, so any non-nil error proves
	// the issuer constraint reached the policy.
	err = VerifyKeyless(
		entity,
		digest[:],
		vs,
		"https://accounts.google.com",
		regexp.MustCompile(`.*`),
		false,
	)
	if err == nil {
		t.Fatal("VerifyKeyless with mismatched issuer returned nil; want error")
	}
	if errors.Is(err, nil) {
		t.Fatalf("VerifyKeyless mismatch error = %v, want non-nil", err)
	}
}

// TestVerifyKeylessSANMismatch is the SAN-side twin of
// TestVerifyKeylessIssuerMismatch: signed SAN does not match the
// configured subjectPattern, the policy rejects.
func TestVerifyKeylessSANMismatch(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const signSubject = "ops@example.com"
	const signIssuer = "https://github.com/login/oauth"

	artifact := []byte("manifest contents for SAN-mismatch test")
	digest := sha256.Sum256(artifact)

	entity, err := vs.Sign(signSubject, signIssuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	err = VerifyKeyless(
		entity,
		digest[:],
		vs,
		signIssuer,
		regexp.MustCompile(`^someone-else@example\.com$`),
		false,
	)
	if err == nil {
		t.Fatal("VerifyKeyless with mismatched SAN returned nil; want error")
	}
}

// TestVerifyKeylessSuccess proves the matcher allows what it should:
// a signed entity whose Fulcio cert carries the same issuer and a SAN
// matching the configured pattern. Provides the happy-path baseline
// the mismatch tests are measured against and prevents an accidental
// "always rejects" regression from satisfying the mismatch assertions.
func TestVerifyKeylessSuccess(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	const signSubject = "ops@example.com"
	const signIssuer = "https://github.com/login/oauth"

	artifact := []byte("manifest contents for success-path test")
	digest := sha256.Sum256(artifact)

	entity, err := vs.Sign(signSubject, signIssuer, artifact)
	if err != nil {
		t.Fatalf("vs.Sign: %v", err)
	}

	if err := VerifyKeyless(
		entity,
		digest[:],
		vs,
		signIssuer,
		regexp.MustCompile(`^ops@example\.com$`),
		false,
	); err != nil {
		t.Fatalf("VerifyKeyless(matching identity) error = %v, want nil", err)
	}
}
