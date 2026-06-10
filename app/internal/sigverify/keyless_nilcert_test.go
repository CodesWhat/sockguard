package sigverify

// TestVerifyKeylessNilCertGuard covers the defensive belt-and-suspenders
// check inside VerifyKeyless (lines 158-160 in sigverify.go):
//
//	if issuerExact != "" || subjectPattern != nil {
//	    if result.Signature == nil || result.Signature.Certificate == nil {
//	        return fmt.Errorf("keyless: certificate identity required ...")
//	    }
//
// The guard is a future-proof backstop: as long as sigstore-go's Verify
// correctly enforces that a WithCertificateIdentity policy cannot succeed for
// an entity that carries only a public key (no Fulcio certificate), the guard
// is structurally unreachable through the public API.
//
// Concretely, sigstore-go's Verifier.Verify checks (signed_entity.go, ~line 779):
//
//	if policy.RequireIdentities() && !signedWithCertificate {
//	    return nil, errors.New("can't verify certificate identities: entity was not signed with a certificate")
//	}
//
// That error fires before Verify can return a successful result with a nil
// cert.  Therefore VerifyKeyless returns at the v.Verify() call, not at
// the belt-and-suspenders guard.
//
// # Test strategy
//
// We exercise the path as close to the guard as the API allows:
//
//  1. A keyed entity (bundle.PublicKey VerificationContent — no x509 cert) is
//     passed to VerifyKeyless with a non-empty issuer, so the guard *would*
//     fire if we ever reached it.  We assert the call fails.  The error
//     originates from sigstore-go's own identity check, not our guard — but
//     the test still proves the function rejects the input, which is the
//     observable behavior the guard is defending.
//
//  2. A keyed entity is passed with both issuerExact="" and subjectPattern=nil,
//     which means the guard is voluntarily skipped (no identity configured).
//     The call fails for a different reason (no timestamp), confirming the
//     guard's conditional is correctly scoped.
//
// If a future sigstore-go version changes Verify to succeed despite the absent
// certificate, the tests in this file will begin exercising the guard directly
// (and failing if the guard itself is accidentally removed), making them
// genuine regression tests.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// nilCertEntity is a SignedEntity whose VerificationContent() returns a
// bundle.PublicKey — that is, no Fulcio certificate.  This mirrors the
// keyedTestEntity pattern established in sigverify_test.go and exercises
// the "cert-absent" code path in VerifyKeyless.
type nilCertEntity struct {
	verify.BaseSignedEntity
	msgSig *bundle.MessageSignature
}

func (e *nilCertEntity) VerificationContent() (verify.VerificationContent, error) {
	return &bundle.PublicKey{}, nil
}

func (e *nilCertEntity) SignatureContent() (verify.SignatureContent, error) {
	return e.msgSig, nil
}

func (e *nilCertEntity) Timestamps() ([][]byte, error) { return nil, nil }

func (e *nilCertEntity) TlogEntries() ([]*tlog.Entry, error) { return nil, nil }

func (e *nilCertEntity) Version() (string, error) { return "v0.3", nil }

// newNilCertSignedEntity creates a nilCertEntity signed with a freshly
// generated ECDSA key and returns the entity together with a
// TrustedPublicKeyMaterial that recognizes it — exactly the material that
// VerifyKeyed uses internally.
func newNilCertSignedEntity(t *testing.T, artifact []byte) (verify.SignedEntity, root.TrustedMaterial) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sv, err := sigsig.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("LoadECDSASignerVerifier: %v", err)
	}

	sig, err := sv.SignMessage(strings.NewReader(string(artifact)))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	digest := sha256.Sum256(artifact)
	msgSig := bundle.NewMessageSignature(digest[:], "SHA2_256", sig)
	entity := &nilCertEntity{msgSig: msgSig}

	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPublicKeyToPEM: %v", err)
	}
	verifier, _, err := CompileKey(string(pubPEM))
	if err != nil {
		t.Fatalf("CompileKey: %v", err)
	}

	tm := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
	})

	return entity, tm
}

// TestVerifyKeylessNilCertWithIssuerConfigured passes a keyed (cert-less)
// entity to VerifyKeyless while an issuer constraint is configured.  The
// call must fail: sigstore-go rejects the entity at its own identity check
// ("can't verify certificate identities: entity was not signed with a
// certificate"), which fires before our defensive nil-cert guard.  The test
// asserts a non-nil error whose message references certificate identities,
// confirming that the two-layer rejection chain is intact.
//
// Reachability note: the belt-and-suspenders guard at lines 158-160 of
// sigverify.go (result.Signature == nil || result.Signature.Certificate == nil)
// is NOT reached in this test because sigstore-go's Verify returns an error
// first.  See the package-level comment for a full reachability analysis.
func TestVerifyKeylessNilCertWithIssuerConfigured(t *testing.T) {
	t.Parallel()

	artifact := []byte("payload for nil-cert guard test")
	digest := sha256.Sum256(artifact)

	entity, tm := newNilCertSignedEntity(t, artifact)

	err := VerifyKeyless(
		entity,
		digest[:],
		tm,
		"https://accounts.google.com", // non-empty issuerExact → guard condition is true
		nil,
		false,
	)
	if err == nil {
		t.Fatal("VerifyKeyless(keyed entity, issuer configured) returned nil; want error")
	}
	// The error must reference certificate identities — proof that
	// sigstore-go's own identity check fired on the cert-absent entity.
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate-related error, got: %v", err)
	}
}

// TestVerifyKeylessNilCertWithPatternConfigured is the subjectPattern twin of
// TestVerifyKeylessNilCertWithIssuerConfigured.  A non-nil subjectPattern also
// satisfies the guard's outer condition, so the same two-layer rejection
// applies.
func TestVerifyKeylessNilCertWithPatternConfigured(t *testing.T) {
	t.Parallel()

	artifact := []byte("payload for nil-cert SAN-guard test")
	digest := sha256.Sum256(artifact)

	entity, tm := newNilCertSignedEntity(t, artifact)

	err := VerifyKeyless(
		entity,
		digest[:],
		tm,
		"",
		regexp.MustCompile(`^ops@example\.com$`), // non-nil subjectPattern → guard condition is true
		false,
	)
	if err == nil {
		t.Fatal("VerifyKeyless(keyed entity, SAN pattern configured) returned nil; want error")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate-related error, got: %v", err)
	}
}

// TestVerifyKeylessNilCertNoIdentityConstraint confirms that when both
// issuerExact and subjectPattern are zero-valued the nil-cert guard is
// voluntarily bypassed (the outer condition is false).  With no identity
// constraints, VerifyKeyless must still fail — but for a different reason:
// a keyed entity cannot satisfy the observer-timestamps requirement that
// VerifyKeyless enforces.  This test pins the guard's conditional boundary
// and prevents an accidental widening of the guard to always-on.
func TestVerifyKeylessNilCertNoIdentityConstraint(t *testing.T) {
	t.Parallel()

	artifact := []byte("payload for nil-cert no-constraint test")
	digest := sha256.Sum256(artifact)

	entity, tm := newNilCertSignedEntity(t, artifact)

	err := VerifyKeyless(
		entity,
		digest[:],
		tm,
		"",  // issuerExact == "" — guard outer condition false
		nil, // subjectPattern == nil — guard outer condition false
		false,
	)
	// The call must fail, but NOT with the nil-cert guard message.  A keyed
	// entity has no observer timestamps, so sigstore-go rejects it on that
	// ground.
	if err == nil {
		t.Fatal("VerifyKeyless(keyed entity, no identity constraint) returned nil; want error")
	}
	if strings.Contains(err.Error(), "certificate identity required") {
		t.Fatalf("nil-cert guard fired even though no identity constraint was set; error: %v", err)
	}
}
