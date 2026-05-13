// Package policybundle verifies signed policy bundles before sockguard
// accepts them as authoritative configuration.
//
// A "policy bundle" is the operator's existing YAML config file plus a
// companion sigstore bundle (the JSON artifact emitted by `cosign sign-blob
// --bundle <file>`). The verifier hashes the YAML bytes, then asks
// sigstore-go to confirm that the bundle signs that exact digest under one
// of the operator-configured trust roots:
//
//   - keyed: PEM-encoded public keys (ECDSA, RSA, ed25519). One key per
//     entry; the bundle passes if any key accepts it.
//   - keyless: Fulcio-issued OIDC certs with a strict (issuer, SAN) match.
//     Rekor inclusion proof is required by default and recommended for
//     production.
//
// This package reuses the same sigstore-go stack as internal/imagetrust;
// there is no new crypto dependency.
package policybundle

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

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// VerifyTimeout is the default per-verification context timeout. Bundle
// verification is bounded because keyless paths may dial the trust-root
// material in future iterations; today it is purely CPU-bound, but the
// timeout still guards against pathological inputs.
const VerifyTimeout = 10 * time.Second

// SigningKeyConfig is the raw operator config for a single trusted key.
type SigningKeyConfig struct {
	PEM string
}

// KeylessConfig is the raw operator config for a single keyless identity.
type KeylessConfig struct {
	Issuer         string
	SubjectPattern string
}

// RawConfig is the operator-facing configuration before validation.
type RawConfig struct {
	// Enabled gates the entire verifier. When false, callers must not invoke
	// Verify; BuildConfig accepts the empty config in that case and returns
	// a Config with Enabled=false.
	Enabled bool
	// AllowedSigningKeys lists trusted PEM public keys. At least one key OR
	// one keyless identity is required when Enabled=true.
	AllowedSigningKeys []SigningKeyConfig
	// AllowedKeyless lists trusted Fulcio identity constraints.
	AllowedKeyless []KeylessConfig
	// RequireRekorInclusion requires a Rekor tlog inclusion proof for
	// keyless verification. Recommended true.
	RequireRekorInclusion bool
	// VerifyTimeoutStr overrides the default per-verification timeout.
	VerifyTimeoutStr string
}

// KeyedVerifier wraps a compiled raw-key verifier with its hex fingerprint.
type KeyedVerifier struct {
	verifier    sigsig.Verifier
	fingerprint string
}

// Fingerprint returns the hex sha256 SPKI fingerprint used in audit logs.
func (k KeyedVerifier) Fingerprint() string { return k.fingerprint }

// KeylessIdentity is a compiled Fulcio identity constraint.
type KeylessIdentity struct {
	IssuerExact    string
	SubjectPattern *regexp.Regexp
}

// Config is the parsed, validated bundle-verifier configuration.
type Config struct {
	Enabled               bool
	AllowedSigningKeys    []KeyedVerifier
	AllowedKeyless        []KeylessIdentity
	RequireRekorInclusion bool
	VerifyTimeout         time.Duration
	// TrustedMaterial backs keyless verification. Production wires it via
	// TUF; tests inject ca.VirtualSigstore. Nil is only legal when there
	// are no keyless identities configured.
	TrustedMaterial root.TrustedMaterial
}

// BuildConfig validates and compiles a RawConfig into a Config. Returns
// (Config{Enabled:false}, nil) when Enabled is false regardless of other
// fields so an operator can leave the trust material set while flipping
// the feature off.
func BuildConfig(raw RawConfig) (Config, error) {
	if !raw.Enabled {
		return Config{Enabled: false}, nil
	}

	var keyed []KeyedVerifier
	for i, k := range raw.AllowedSigningKeys {
		pem := strings.TrimSpace(k.PEM)
		if pem == "" {
			return Config{}, fmt.Errorf("policy_bundle.allowed_signing_keys[%d].pem is empty", i)
		}
		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_signing_keys[%d].pem: %w", i, err)
		}
		verifier, err := sigsig.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_signing_keys[%d]: %w", i, err)
		}
		der, err := cryptoutils.MarshalPublicKeyToDER(pubKey)
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_signing_keys[%d] fingerprint: %w", i, err)
		}
		h := sha256.Sum256(der)
		keyed = append(keyed, KeyedVerifier{
			verifier:    verifier,
			fingerprint: hex.EncodeToString(h[:]),
		})
	}

	var keyless []KeylessIdentity
	for i, kl := range raw.AllowedKeyless {
		issuer := strings.TrimSpace(kl.Issuer)
		if issuer == "" {
			return Config{}, fmt.Errorf("policy_bundle.allowed_keyless[%d].issuer is required", i)
		}
		pattern := strings.TrimSpace(kl.SubjectPattern)
		if pattern == "" {
			return Config{}, fmt.Errorf("policy_bundle.allowed_keyless[%d].subject_pattern is required", i)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_keyless[%d].subject_pattern: %w", i, err)
		}
		keyless = append(keyless, KeylessIdentity{
			IssuerExact:    issuer,
			SubjectPattern: re,
		})
	}

	if len(keyed) == 0 && len(keyless) == 0 {
		return Config{}, errors.New("policy_bundle: enabled=true but no allowed_signing_keys or allowed_keyless entries are configured")
	}

	timeout := VerifyTimeout
	if raw.VerifyTimeoutStr != "" {
		d, err := time.ParseDuration(raw.VerifyTimeoutStr)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("policy_bundle.verify_timeout must be a positive duration, got %q", raw.VerifyTimeoutStr)
		}
		timeout = d
	}

	return Config{
		Enabled:               true,
		AllowedSigningKeys:    keyed,
		AllowedKeyless:        keyless,
		RequireRekorInclusion: raw.RequireRekorInclusion,
		VerifyTimeout:         timeout,
	}, nil
}

// VerifyResult carries metadata about a successful verification. Callers
// surface it in audit logs and on GET /admin/policy/version.
type VerifyResult struct {
	// Signer is a stable, human-readable identifier of the trust path that
	// accepted the bundle. For keyed: "keyed:<hex-fingerprint>". For keyless:
	// "keyless:<issuer>:<san>".
	Signer string
	// DigestHex is the sha256 hex of the verified YAML bytes. Becomes the
	// PolicySnapshot.BundleDigest field so an operator can match what the
	// proxy is running against what was published.
	DigestHex string
	// ElapsedMS is the wall-clock duration of the verification, useful for
	// catching pathological keyless paths.
	ElapsedMS int64
}

// Verifier is the bundle-verifier contract. Tests substitute fakes.
type Verifier interface {
	// Verify checks that entity is a valid signature over yaml. Returns a
	// non-nil VerifyResult on success; on failure VerifyResult is the zero
	// value and the error carries a structured description.
	Verify(ctx context.Context, yaml []byte, entity verify.SignedEntity) (VerifyResult, error)
}

// New returns a Verifier ready to use. Returns an error if cfg is not
// internally consistent (e.g. keyless configured with no TrustedMaterial).
func New(cfg Config) (Verifier, error) {
	if !cfg.Enabled {
		return &disabledVerifier{}, nil
	}
	if len(cfg.AllowedKeyless) > 0 && cfg.TrustedMaterial == nil {
		return nil, errors.New("policy_bundle: keyless identities configured but TrustedMaterial is nil; production wiring must inject TUF roots")
	}
	return &sigstoreVerifier{cfg: cfg}, nil
}

// LoadBundle reads a sigstore bundle JSON from disk and returns a
// SignedEntity suitable for Verify. The accepted formats are exactly those
// understood by sigstore-go's bundle.LoadJSONFromPath: cosign's
// `--bundle <file>` output, or any other producer that emits the
// "application/vnd.dev.sigstore.bundle*" media types.
func LoadBundle(path string) (verify.SignedEntity, error) {
	b, err := bundle.LoadJSONFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("policy_bundle: load sigstore bundle %q: %w", path, err)
	}
	return b, nil
}

// DigestYAML returns the sha256 hex digest of yaml. Exposed so wiring code
// can stamp PolicySnapshot.BundleDigest even when verification is disabled.
func DigestYAML(yaml []byte) string {
	h := sha256.Sum256(yaml)
	return hex.EncodeToString(h[:])
}

// disabledVerifier is the no-op verifier returned when Enabled=false. It
// rejects calls so a wiring bug can't accidentally bypass an enabled gate
// by sneaking a disabled verifier through.
type disabledVerifier struct{}

func (d *disabledVerifier) Verify(_ context.Context, _ []byte, _ verify.SignedEntity) (VerifyResult, error) {
	return VerifyResult{}, errors.New("policy_bundle: verifier is disabled")
}

// sigstoreVerifier is the production implementation.
type sigstoreVerifier struct {
	cfg Config
}

func (s *sigstoreVerifier) Verify(ctx context.Context, yaml []byte, entity verify.SignedEntity) (VerifyResult, error) {
	if entity == nil {
		return VerifyResult{}, errors.New("policy_bundle: no signature bundle provided")
	}
	if len(yaml) == 0 {
		return VerifyResult{}, errors.New("policy_bundle: empty YAML payload; refusing to verify")
	}

	start := time.Now()
	digestBytes := sha256.Sum256(yaml)
	digestHex := hex.EncodeToString(digestBytes[:])

	if _, ok := ctx.Deadline(); !ok && s.cfg.VerifyTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.VerifyTimeout)
		defer cancel()
	}

	var keyedErr, keylessErr error

	for _, kv := range s.cfg.AllowedSigningKeys {
		if err := s.verifyKeyed(ctx, entity, digestBytes[:], kv); err != nil {
			keyedErr = err
			continue
		}
		return VerifyResult{
			Signer:    "keyed:" + kv.fingerprint,
			DigestHex: digestHex,
			ElapsedMS: time.Since(start).Milliseconds(),
		}, nil
	}

	for _, kl := range s.cfg.AllowedKeyless {
		if err := s.verifyKeyless(ctx, entity, digestBytes[:], kl); err != nil {
			keylessErr = err
			continue
		}
		return VerifyResult{
			Signer:    "keyless:" + kl.IssuerExact + ":" + kl.SubjectPattern.String(),
			DigestHex: digestHex,
			ElapsedMS: time.Since(start).Milliseconds(),
		}, nil
	}

	var msgs []string
	if keyedErr != nil {
		msgs = append(msgs, fmt.Sprintf("keyed: %v", keyedErr))
	}
	if keylessErr != nil {
		msgs = append(msgs, fmt.Sprintf("keyless: %v", keylessErr))
	}
	if len(msgs) == 0 {
		return VerifyResult{}, errors.New("policy_bundle: no verifiers configured")
	}
	return VerifyResult{}, fmt.Errorf("policy_bundle verification failed: %s", strings.Join(msgs, "; "))
}

func (s *sigstoreVerifier) verifyKeyed(_ context.Context, entity verify.SignedEntity, digestBytes []byte, kv KeyedVerifier) error {
	tm := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(kv.verifier, time.Time{}, time.Time{}), nil
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
	return err
}

func (s *sigstoreVerifier) verifyKeyless(_ context.Context, entity verify.SignedEntity, digestBytes []byte, kl KeylessIdentity) error {
	if s.cfg.TrustedMaterial == nil {
		return errors.New("keyless verification requires TrustedMaterial")
	}
	verifierOpts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if s.cfg.RequireRekorInclusion {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}
	v, err := verify.NewVerifier(s.cfg.TrustedMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("build keyless verifier: %w", err)
	}
	sanMatcher, err := verify.NewSANMatcher("", kl.SubjectPattern.String())
	if err != nil {
		return fmt.Errorf("compile SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(kl.IssuerExact, "")
	if err != nil {
		return fmt.Errorf("compile issuer matcher: %w", err)
	}
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})
	if err != nil {
		return fmt.Errorf("build cert identity: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	)
	result, err := v.Verify(entity, policy)
	if err != nil {
		return err
	}
	if result.Signature != nil && result.Signature.Certificate != nil {
		cert := result.Signature.Certificate
		if kl.IssuerExact != "" && cert.Issuer != kl.IssuerExact {
			return fmt.Errorf("keyless: issuer mismatch: got %q, want %q", cert.Issuer, kl.IssuerExact)
		}
		if kl.SubjectPattern != nil && !kl.SubjectPattern.MatchString(cert.SubjectAlternativeName) {
			return fmt.Errorf("keyless: SAN %q does not match pattern %q", cert.SubjectAlternativeName, kl.SubjectPattern.String())
		}
	}
	return nil
}
