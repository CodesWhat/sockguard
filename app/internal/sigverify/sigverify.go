// Package sigverify holds the sigstore-go primitives shared by
// internal/imagetrust (signed-image verification) and internal/policybundle
// (signed-config-bundle verification). Both packages historically carried
// byte-identical copies of the keyed / keyless verify routines; centralizing
// them here prevents the two security-critical paths from drifting.
package sigverify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// CompileKey parses a PEM-encoded public key into a signature verifier and
// returns the hex sha256 SPKI fingerprint that callers use in audit logs.
// The pem argument is trimmed of leading/trailing whitespace before parsing.
func CompileKey(pem string) (sigsig.Verifier, string, error) {
	pem = strings.TrimSpace(pem)
	if pem == "" {
		return nil, "", errors.New("pem is empty")
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
	if err != nil {
		return nil, "", fmt.Errorf("pem: %w", err)
	}
	verifier, err := sigsig.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, "", err
	}
	der, err := cryptoutils.MarshalPublicKeyToDER(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("fingerprint: %w", err)
	}
	h := sha256.Sum256(der)
	return verifier, hex.EncodeToString(h[:]), nil
}

// CompileKeyless validates a keyless identity (issuer + subject_pattern)
// config entry and returns the trimmed issuer and the compiled subject
// pattern regex. Both imagetrust and policybundle compile the same shape;
// callers wrap any returned error with their own config-path prefix.
func CompileKeyless(issuer, subjectPattern string) (string, *regexp.Regexp, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "", nil, errors.New("issuer is required")
	}
	pattern := strings.TrimSpace(subjectPattern)
	if pattern == "" {
		return "", nil, errors.New("subject_pattern is required")
	}
	// Anchor the pattern so the SAN must match in full. Without anchoring, an
	// unanchored pattern such as "ci@acme.com" would
	// match any SAN that merely *contains* it (e.g. "ci@acme.com.attacker.test"),
	// letting a Fulcio cert for a different identity pass — both here and in
	// sigstore-go's SANMatcher, which also matches on a substring basis.
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return "", nil, fmt.Errorf("subject_pattern: %w", err)
	}
	return issuer, re, nil
}

// VerifyKeyed runs sigstore-go's bundle verification against the given raw
// public-key verifier. Returns nil on success; otherwise an error describing
// why the bundle did not match.
func VerifyKeyed(ctx context.Context, entity verify.SignedEntity, digestBytes []byte, signer sigsig.Verifier) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyed verification canceled: %w", err)
	}
	tm := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(signer, time.Time{}, time.Time{}), nil
	})
	v, err := verify.NewVerifier(tm, verify.WithNoObserverTimestamps())
	if err != nil {
		return fmt.Errorf("build keyed verifier: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithKey(),
	)
	_, err = v.Verify(entity, policy)
	if contextErr := ctx.Err(); contextErr != nil {
		return fmt.Errorf("keyed verification canceled: %w", contextErr)
	}
	return err
}

// VerifyKeyless verifies a keyless entity against an exact issuer and subject
// pattern. Call VerifyKeylessIdentity when the verified SAN is needed for
// audit attribution.
func VerifyKeyless(
	ctx context.Context,
	entity verify.SignedEntity,
	digestBytes []byte,
	trustedMaterial root.TrustedMaterial,
	issuerExact string,
	subjectPattern *regexp.Regexp,
	requireRekorInclusion bool,
) error {
	_, err := VerifyKeylessIdentity(
		ctx,
		entity,
		digestBytes,
		trustedMaterial,
		issuerExact,
		subjectPattern,
		requireRekorInclusion,
	)
	return err
}

// VerifyKeylessIdentity runs keyless verification and returns the verified
// certificate SAN for audit attribution. The trusted material is required;
// callers must inject TUF roots in production or a VirtualSigstore in tests.
func VerifyKeylessIdentity(
	ctx context.Context,
	entity verify.SignedEntity,
	digestBytes []byte,
	trustedMaterial root.TrustedMaterial,
	issuerExact string,
	subjectPattern *regexp.Regexp,
	requireRekorInclusion bool,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("keyless verification canceled: %w", err)
	}
	if trustedMaterial == nil {
		return "", errors.New("keyless verification requires TrustedMaterial")
	}
	if issuerExact == "" || subjectPattern == nil {
		return "", errors.New("keyless verification requires both an exact issuer and a compiled subject pattern")
	}
	opts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if requireRekorInclusion {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	v, err := verify.NewVerifier(trustedMaterial, opts...)
	if err != nil {
		return "", fmt.Errorf("build keyless verifier: %w", err)
	}

	pattern := ""
	if subjectPattern != nil {
		pattern = subjectPattern.String()
	}
	sanMatcher, err := verify.NewSANMatcher("", pattern)
	if err != nil {
		return "", fmt.Errorf("compile SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(issuerExact, "")
	if err != nil {
		return "", fmt.Errorf("compile issuer matcher: %w", err)
	}
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})
	if err != nil {
		return "", fmt.Errorf("build cert identity: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	)
	result, err := v.Verify(entity, policy)
	if contextErr := ctx.Err(); contextErr != nil {
		return "", fmt.Errorf("keyless verification canceled: %w", contextErr)
	}
	if err != nil {
		return "", err
	}

	// Belt-and-suspenders issuer/SAN re-check. sigstore-go's policy gate above
	// already enforces both via NewCertificateIdentity, but a future sigstore-go
	// change to its result shape (or a verification path that returns nil cert
	// despite a successful Verify) must not silently skip the check on our side.
	// Treat an absent certificate as a verification failure: if the caller
	// configured an issuer / SAN expectation, we cannot honor it without a cert
	// to inspect.
	if issuerExact != "" || subjectPattern != nil {
		if result.Signature == nil || result.Signature.Certificate == nil {
			return "", fmt.Errorf("keyless: certificate identity required (issuer or SAN pattern configured) but verification result has no certificate")
		}
		cert := result.Signature.Certificate
		if issuerExact != "" && cert.Issuer != issuerExact {
			return "", fmt.Errorf("keyless: issuer mismatch: got %q, want %q", cert.Issuer, issuerExact)
		}
		if subjectPattern != nil && !subjectPattern.MatchString(cert.SubjectAlternativeName) {
			return "", fmt.Errorf("keyless: SAN %q does not match pattern %q", cert.SubjectAlternativeName, subjectPattern.String())
		}
		return cert.SubjectAlternativeName, nil
	}
	return "", errors.New("keyless: verified result did not include a configured identity")
}
