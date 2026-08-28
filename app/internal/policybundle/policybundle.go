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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	sigsig "github.com/sigstore/sigstore/pkg/signature"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
	"github.com/codeswhat/sockguard/app/internal/sigverify"
)

// MaxBundleFileBytes caps a signature bundle before JSON decoding.
const MaxBundleFileBytes int64 = 4 << 20

// VerifyTimeout is the default cooperative verification deadline. Sigstore-go
// verification is synchronous and local, so cancellation is checked before
// work begins and after each verification attempt.
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
	// VerifyTimeoutStr overrides the default cooperative verification deadline.
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
		verifier, fingerprint, err := sigverify.CompileKey(k.PEM)
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_signing_keys[%d]: %w", i, err)
		}
		keyed = append(keyed, KeyedVerifier{
			verifier:    verifier,
			fingerprint: fingerprint,
		})
	}

	var keyless []KeylessIdentity
	for i, kl := range raw.AllowedKeyless {
		issuer, re, err := sigverify.CompileKeyless(kl.Issuer, kl.SubjectPattern)
		if err != nil {
			return Config{}, fmt.Errorf("policy_bundle.allowed_keyless[%d].%w", i, err)
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
	data, err := boundedio.ReadFile(path, MaxBundleFileBytes)
	if err != nil {
		return nil, fmt.Errorf("policy_bundle: load sigstore bundle %q: %w", path, err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("policy_bundle: load sigstore bundle %q: %w", path, err)
	}
	return &b, nil
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
	if _, ok := ctx.Deadline(); !ok && s.cfg.VerifyTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.VerifyTimeout)
		defer cancel()
	}
	return s.verify(ctx, yaml, entity, start)
}

func (s *sigstoreVerifier) verify(ctx context.Context, yaml []byte, entity verify.SignedEntity, start time.Time) (VerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("policy bundle verification canceled: %w", err)
	}
	digestBytes := sha256.Sum256(yaml)
	digestHex := hex.EncodeToString(digestBytes[:])
	var keyedErrs, keylessErrs []string

	for _, kv := range s.cfg.AllowedSigningKeys {
		if err := s.verifyKeyed(ctx, entity, digestBytes[:], kv); err != nil {
			if ctx.Err() != nil {
				return VerifyResult{}, err
			}
			keyedErrs = append(keyedErrs, fmt.Sprintf("%s: %v", kv.fingerprint, err))
			continue
		}
		return VerifyResult{
			Signer:    "keyed:" + kv.fingerprint,
			DigestHex: digestHex,
			ElapsedMS: time.Since(start).Milliseconds(),
		}, nil
	}

	for _, kl := range s.cfg.AllowedKeyless {
		san, err := s.verifyKeyless(ctx, entity, digestBytes[:], kl)
		if err != nil {
			if ctx.Err() != nil {
				return VerifyResult{}, err
			}
			keylessErrs = append(keylessErrs, fmt.Sprintf("%s: %v", kl.IssuerExact, err))
			continue
		}
		return VerifyResult{
			Signer:    "keyless:" + kl.IssuerExact + ":" + san,
			DigestHex: digestHex,
			ElapsedMS: time.Since(start).Milliseconds(),
		}, nil
	}

	var msgs []string
	if len(keyedErrs) > 0 {
		msgs = append(msgs, "keyed: "+strings.Join(keyedErrs, " | "))
	}
	if len(keylessErrs) > 0 {
		msgs = append(msgs, "keyless: "+strings.Join(keylessErrs, " | "))
	}
	if len(msgs) == 0 {
		return VerifyResult{}, errors.New("policy_bundle: no verifiers configured")
	}
	return VerifyResult{}, fmt.Errorf("policy_bundle verification failed: %s", strings.Join(msgs, "; "))
}

func (s *sigstoreVerifier) verifyKeyed(ctx context.Context, entity verify.SignedEntity, digestBytes []byte, kv KeyedVerifier) error {
	return sigverify.VerifyKeyed(ctx, entity, digestBytes, kv.verifier)
}

func (s *sigstoreVerifier) verifyKeyless(ctx context.Context, entity verify.SignedEntity, digestBytes []byte, kl KeylessIdentity) (string, error) {
	return sigverify.VerifyKeylessIdentity(ctx, entity, digestBytes, s.cfg.TrustedMaterial, kl.IssuerExact, kl.SubjectPattern, s.cfg.RequireRekorInclusion)
}
