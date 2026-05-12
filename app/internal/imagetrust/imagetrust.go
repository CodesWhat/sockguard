// Package imagetrust implements cosign-backed signature verification for
// container images referenced in POST /containers/create requests.
//
// Supported modes:
//   - off: no-op, all images are allowed without verification
//   - warn: verify; log a structured audit record and allow on failure
//   - enforce: verify; return an error on failure so the caller can deny
//
// Supported verifier types:
//   - Keyed: operator pastes one or more PEM-encoded public keys. sigstore-go
//     verifies the signature bundle against each key in turn; the image passes
//     if any key accepts it.
//   - Keyless: Fulcio-issued cert chain with issuer + SAN matching.
//     sigstore-go verifies the Fulcio chain and transparency log inclusion.
//
// The caller (filter/container_create.go) is responsible for resolving
// the image reference to a digest and building a Sigstore bundle before
// calling Verify. In production that bundle comes from the OCI registry's
// cosign-artifact layer; in tests it is synthesized using VirtualSigstore.
package imagetrust

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// Mode controls whether verification failures block container creation.
type Mode string

const (
	// ModeOff skips all verification. Default.
	ModeOff Mode = "off"
	// ModeWarn verifies and emits an audit log record on failure, but always
	// allows the request through.
	ModeWarn Mode = "warn"
	// ModeEnforce verifies and returns an error on failure. The caller must
	// deny the request.
	ModeEnforce Mode = "enforce"
)

// VerifyTimeout is the default context timeout for a single verification call.
const VerifyTimeout = 10 * time.Second

// Config is the parsed, validated configuration for image trust verification.
// Construct it via BuildConfig; do not construct it directly.
type Config struct {
	// Mode controls whether failures block or warn.
	Mode Mode
	// AllowedSigningKeys is the set of parsed keyed verifiers.
	AllowedSigningKeys []KeyedVerifier
	// AllowedKeyless is the set of keyless (Fulcio) identity matchers.
	AllowedKeyless []KeylessIdentity
	// RequireRekorInclusion requires a Rekor tlog entry for keyless verification.
	RequireRekorInclusion bool
	// TrustedMaterial is the root trusted material for keyless Fulcio/Rekor
	// verification. Must be set (non-nil) when keyless identities are configured.
	// Tests inject VirtualSigstore here; production builds fetch via TUF.
	TrustedMaterial root.TrustedMaterial
	// VerifyTimeout overrides the default per-verification timeout.
	VerifyTimeout time.Duration
}

// KeyedVerifier holds a parsed, ready-to-use public key verifier and its hex
// fingerprint (sha256 of DER-encoded SPKI) for logging.
type KeyedVerifier struct {
	verifier    sigsig.Verifier
	fingerprint string // hex sha256 of DER SPKI
}

// Fingerprint returns the hex sha256 SPKI fingerprint used in audit logs.
func (k KeyedVerifier) Fingerprint() string { return k.fingerprint }

// KeylessIdentity is a compiled Fulcio identity constraint. At least one must
// match the leaf cert's issuer OID extension and SAN for the image to pass.
type KeylessIdentity struct {
	IssuerExact    string         // exact OIDC issuer URL
	SubjectPattern *regexp.Regexp // compiled regex matched against the cert SAN
}

// SigningKeyConfig is the raw operator config entry for a single public key.
type SigningKeyConfig struct {
	PEM string
}

// KeylessConfig is the raw operator config entry for a single keyless identity.
type KeylessConfig struct {
	Issuer         string
	SubjectPattern string
}

// RawConfig is the operator-facing configuration before validation. Use
// BuildConfig to produce a Config.
type RawConfig struct {
	Mode                  Mode
	AllowedSigningKeys    []SigningKeyConfig
	AllowedKeyless        []KeylessConfig
	RequireRekorInclusion bool
	VerifyTimeoutStr      string
}

// BuildConfig validates and compiles a RawConfig into a ready-to-use Config.
// Returns an error if mode != off and the verifier would be misconfigured.
func BuildConfig(raw RawConfig) (Config, error) {
	if raw.Mode == "" {
		raw.Mode = ModeOff
	}
	switch raw.Mode {
	case ModeOff, ModeWarn, ModeEnforce:
	default:
		return Config{}, fmt.Errorf("image_trust.mode must be off, warn, or enforce; got %q", raw.Mode)
	}

	if raw.Mode == ModeOff {
		return Config{Mode: ModeOff}, nil
	}

	// Compile signing keys.
	var keyedVerifiers []KeyedVerifier
	for i, keyConf := range raw.AllowedSigningKeys {
		pem := strings.TrimSpace(keyConf.PEM)
		if pem == "" {
			return Config{}, fmt.Errorf("image_trust.allowed_signing_keys[%d].pem is empty", i)
		}
		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
		if err != nil {
			return Config{}, fmt.Errorf("image_trust.allowed_signing_keys[%d].pem: %w", i, err)
		}
		verifier, err := sigsig.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return Config{}, fmt.Errorf("image_trust.allowed_signing_keys[%d]: %w", i, err)
		}
		der, err := cryptoutils.MarshalPublicKeyToDER(pubKey)
		if err != nil {
			return Config{}, fmt.Errorf("image_trust.allowed_signing_keys[%d] fingerprint: %w", i, err)
		}
		h := sha256.Sum256(der)
		keyedVerifiers = append(keyedVerifiers, KeyedVerifier{
			verifier:    verifier,
			fingerprint: hex.EncodeToString(h[:]),
		})
	}

	// Compile keyless identities.
	var keylessIDs []KeylessIdentity
	for i, kl := range raw.AllowedKeyless {
		issuer := strings.TrimSpace(kl.Issuer)
		if issuer == "" {
			return Config{}, fmt.Errorf("image_trust.allowed_keyless[%d].issuer is required", i)
		}
		pattern := strings.TrimSpace(kl.SubjectPattern)
		if pattern == "" {
			return Config{}, fmt.Errorf("image_trust.allowed_keyless[%d].subject_pattern is required", i)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return Config{}, fmt.Errorf("image_trust.allowed_keyless[%d].subject_pattern: %w", i, err)
		}
		keylessIDs = append(keylessIDs, KeylessIdentity{
			IssuerExact:    issuer,
			SubjectPattern: re,
		})
	}

	if len(keyedVerifiers) == 0 && len(keylessIDs) == 0 {
		return Config{}, errors.New("image_trust: mode is not off but no allowed_signing_keys or allowed_keyless entries are configured")
	}

	timeout := VerifyTimeout
	if raw.VerifyTimeoutStr != "" {
		d, err := time.ParseDuration(raw.VerifyTimeoutStr)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("image_trust.verify_timeout must be a positive duration, got %q", raw.VerifyTimeoutStr)
		}
		timeout = d
	}

	return Config{
		Mode:                  raw.Mode,
		AllowedSigningKeys:    keyedVerifiers,
		AllowedKeyless:        keylessIDs,
		RequireRekorInclusion: raw.RequireRekorInclusion,
		VerifyTimeout:         timeout,
	}, nil
}

// Verifier is the interface implemented by the image trust verifier.
// Tests may substitute a stub.
type Verifier interface {
	// Verify checks whether the given sigstore bundle is a valid signature for
	// the artifact described by imageRef + digestHex (sha256 hex without
	// prefix).  Returns nil on success, a descriptive error on failure.
	Verify(ctx context.Context, imageRef, digestHex string, entity verify.SignedEntity) error
}

// VerifyOutcome carries the result of a verification attempt together with
// metadata for audit logging.
type VerifyOutcome struct {
	Allowed    bool
	Verifier   string // "keyed:<fingerprint>" | "keyless:<issuer>/<san>" | "off" | "warn-bypass" | "denied"
	FailureMsg string
	ElapsedMS  int64
}

// New builds and returns a Verifier from a Config. If cfg.Mode is ModeOff it
// returns a no-op verifier that always passes without any network calls.
func New(cfg Config) (Verifier, error) {
	if cfg.Mode == ModeOff {
		return &offVerifier{}, nil
	}
	return &sigstoreVerifier{cfg: cfg}, nil
}

// VerifyWithMode wraps Verify and applies mode semantics:
//   - ModeOff: returns Allowed=true without calling Verify
//   - ModeWarn: calls Verify; if it fails, logs the failure, returns Allowed=true
//   - ModeEnforce: calls Verify; if it fails, returns Allowed=false
func VerifyWithMode(ctx context.Context, v Verifier, cfg Config, logger *slog.Logger, imageRef, digestHex string, entity verify.SignedEntity) VerifyOutcome {
	start := time.Now()

	if cfg.Mode == ModeOff {
		return VerifyOutcome{Allowed: true, Verifier: "off", ElapsedMS: time.Since(start).Milliseconds()}
	}

	err := v.Verify(ctx, imageRef, digestHex, entity)
	elapsed := time.Since(start).Milliseconds()

	if err == nil {
		return VerifyOutcome{Allowed: true, Verifier: "verified", ElapsedMS: elapsed}
	}

	failMsg := err.Error()
	switch cfg.Mode {
	case ModeWarn:
		if logger != nil {
			logger.WarnContext(ctx, "image trust verification failed (warn mode — request allowed)",
				"image_ref", imageRef,
				"digest", digestHex,
				"error", failMsg,
				"elapsed_ms", elapsed,
			)
		}
		return VerifyOutcome{Allowed: true, Verifier: "warn-bypass", FailureMsg: failMsg, ElapsedMS: elapsed}
	default: // ModeEnforce
		return VerifyOutcome{Allowed: false, Verifier: "denied", FailureMsg: failMsg, ElapsedMS: elapsed}
	}
}

// offVerifier is the no-op Verifier returned when mode = off.
type offVerifier struct{}

func (o *offVerifier) Verify(_ context.Context, _, _ string, _ verify.SignedEntity) error {
	return nil
}

// sigstoreVerifier is the production verifier backed by sigstore-go.
type sigstoreVerifier struct {
	cfg Config
}

func (s *sigstoreVerifier) Verify(ctx context.Context, imageRef, digestHex string, entity verify.SignedEntity) error {
	if entity == nil {
		return fmt.Errorf("image trust: no signature bundle provided for %s", imageRef)
	}

	digestBytes, err := hex.DecodeString(strings.TrimPrefix(digestHex, "sha256:"))
	if err != nil {
		return fmt.Errorf("image trust: invalid digest %q: %w", digestHex, err)
	}

	var keyedErr, keylessErr error

	for _, kv := range s.cfg.AllowedSigningKeys {
		if err := s.verifyKeyed(ctx, entity, digestBytes, kv); err != nil {
			keyedErr = err
			continue
		}
		return nil
	}

	for _, kl := range s.cfg.AllowedKeyless {
		if err := s.verifyKeyless(ctx, entity, digestBytes, kl); err != nil {
			keylessErr = err
			continue
		}
		return nil
	}

	var msgs []string
	if keyedErr != nil {
		msgs = append(msgs, fmt.Sprintf("keyed: %v", keyedErr))
	}
	if keylessErr != nil {
		msgs = append(msgs, fmt.Sprintf("keyless: %v", keylessErr))
	}
	if len(msgs) == 0 {
		return fmt.Errorf("image trust: no verifiers configured for %s", imageRef)
	}
	return fmt.Errorf("image trust verification failed for %s: %s", imageRef, strings.Join(msgs, "; "))
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
		return errors.New("keyless verification requires TrustedMaterial (set TrustedMaterial in Config or use VirtualSigstore in tests)")
	}

	verifierOpts := []verify.VerifierOption{
		verify.WithObserverTimestamps(1),
	}
	if s.cfg.RequireRekorInclusion {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	v, err := verify.NewVerifier(s.cfg.TrustedMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("build keyless verifier: %w", err)
	}

	certID, err := buildCertID(kl)
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

	// Belt-and-suspenders check on the cert summary returned by sigstore-go.
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

func buildCertID(kl KeylessIdentity) (verify.CertificateIdentity, error) {
	sanMatcher, err := verify.NewSANMatcher("", kl.SubjectPattern.String())
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("compile SAN regexp: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(kl.IssuerExact, "")
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("compile issuer matcher: %w", err)
	}
	return verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})
}
