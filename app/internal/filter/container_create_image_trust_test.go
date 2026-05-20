package filter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/imagetrust"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// generateTestECDSAPEM produces a PEM-encoded ECDSA P-256 public key for use
// in image trust test fixtures.
func generateTestECDSAPEM(t *testing.T) string {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := cryptoutils.MarshalPublicKeyToDER(privKey.Public())
	if err != nil {
		t.Fatalf("marshal public key to DER: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestContainerCreateBuildImageTrustRawRoundTrip verifies that the
// buildImageTrustRaw → imagetrust.BuildConfig → imagetrust.New chain
// succeeds end-to-end and that the resulting policy has a non-nil image trust
// verifier. This covers the previously-zero-coverage buildImageTrustRaw helper
// and the new error-propagating code paths in newContainerCreatePolicy.
func TestContainerCreateBuildImageTrustRawRoundTrip(t *testing.T) {
	pemStr := generateTestECDSAPEM(t)

	opts := ContainerCreateOptions{
		ImageTrust: ImageTrustOptions{
			Mode: "enforce",
			AllowedSigningKeys: []SigningKeyOptions{
				{PEM: pemStr},
			},
		},
	}

	policy := newContainerCreatePolicy(opts)

	if policy.imageTrustInitErr != nil {
		t.Fatalf("newContainerCreatePolicy returned imageTrustInitErr = %v, want nil", policy.imageTrustInitErr)
	}
	if policy.imageTrustVerifier == nil {
		t.Fatal("newContainerCreatePolicy returned nil imageTrustVerifier, want non-nil")
	}
}

// TestContainerCreateImageTrustInitErrFailsClosed verifies that when image
// trust is configured with an invalid key, the policy stores an init error and
// inspect returns a denial reason (fail-closed) rather than silently allowing
// all requests through.
func TestContainerCreateImageTrustInitErrFailsClosed(t *testing.T) {
	opts := ContainerCreateOptions{
		ImageTrust: ImageTrustOptions{
			Mode: "enforce",
			AllowedSigningKeys: []SigningKeyOptions{
				{PEM: "not-a-valid-pem"},
			},
		},
	}

	policy := newContainerCreatePolicy(opts)

	if policy.imageTrustInitErr == nil {
		t.Fatal("expected imageTrustInitErr for invalid PEM, got nil")
	}
	if policy.imageTrustVerifier != nil {
		t.Fatal("expected nil imageTrustVerifier when init failed, got non-nil")
	}
}

// TestContainerCreateImageTrustTimeoutHonorsExplicitConfig pins the
// CONDITIONALS_NEGATION mutant at container_create.go:229 (`imageTrustTimeout
// == 0` → `!= 0`). The intent of the guard is "if the parsed Config came back
// with VerifyTimeout=0 (defensive against future Config callers), fall back
// to the package default." Under the mutant, the fall-back fires for every
// non-zero timeout instead — silently replacing operator-configured timeouts
// with the 10s package default.
//
// We configure verify_timeout="30s" and assert the policy stores 30s. The
// mutant would yield 10s.
func TestContainerCreateImageTrustTimeoutHonorsExplicitConfig(t *testing.T) {
	pemStr := generateTestECDSAPEM(t)

	opts := ContainerCreateOptions{
		ImageTrust: ImageTrustOptions{
			Mode: "enforce",
			AllowedSigningKeys: []SigningKeyOptions{
				{PEM: pemStr},
			},
			VerifyTimeout: "30s",
		},
	}

	policy := newContainerCreatePolicy(opts)

	if policy.imageTrustInitErr != nil {
		t.Fatalf("imageTrustInitErr = %v, want nil", policy.imageTrustInitErr)
	}
	want := 30 * time.Second
	if policy.imageTrustTimeout != want {
		t.Fatalf("imageTrustTimeout = %v, want %v — mutant `imageTrustTimeout != 0` would replace the configured 30s with imagetrust.VerifyTimeout (%v)", policy.imageTrustTimeout, want, imagetrust.VerifyTimeout)
	}
}
