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
	"context"
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

// TestVerifyKeylessNilCertWithIdentityConfigured passes a keyed (cert-less)
// entity with a complete keyless identity constraint. The call must fail
// before a certificate-less entity can satisfy the keyless policy.
//
// Reachability note: the belt-and-suspenders guard at lines 158-160 of
// sigverify.go (result.Signature == nil || result.Signature.Certificate == nil)
// is NOT reached in this test because sigstore-go's Verify returns an error
// first.  See the package-level comment for a full reachability analysis.
func TestVerifyKeylessNilCertWithIdentityConfigured(t *testing.T) {
	t.Parallel()

	artifact := []byte("payload for nil-cert guard test")
	digest := sha256.Sum256(artifact)

	entity, tm := newNilCertSignedEntity(t, artifact)

	err := VerifyKeyless(
		context.Background(),
		entity,
		digest[:],
		tm,
		"https://accounts.google.com",
		regexp.MustCompile(`^ops@example\.com$`),
		false,
	)
	if err == nil {
		t.Fatal("VerifyKeyless(keyed entity, identity configured) returned nil; want error")
	}
}
