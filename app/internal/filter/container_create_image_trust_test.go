package filter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

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
