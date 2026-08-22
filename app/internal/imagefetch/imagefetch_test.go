package imagefetch

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"

	"github.com/codeswhat/sockguard/app/internal/imagetrust"
)

const simpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

// testRegistry spins up go-containerregistry's in-memory registry over httptest
// and returns its host (which go-containerregistry treats as insecure/plain-HTTP
// because it is 127.0.0.1).
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse registry url: %v", err)
	}
	return u.Host
}

// signingKeyPair returns a fresh ECDSA P-256 key, a sigstore signer over it, and
// the PEM-encoded public key for configuring a keyed verifier.
func signingKeyPair(t *testing.T) (sigsig.Signer, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := sigsig.LoadSigner(priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	der, err := cryptoutils.MarshalPublicKeyToDER(priv.Public())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return signer, pubPEM
}

// simpleSigningPayloadFor builds a cosign simple-signing payload that vouches
// for the given manifest digest in dockerReference (the repository the signer
// claims, e.g. "example.com/app").
func simpleSigningPayloadFor(t *testing.T, dockerReference, manifestDigest string) []byte {
	t.Helper()
	doc := map[string]any{
		"critical": map[string]any{
			"identity": map[string]any{"docker-reference": dockerReference},
			"image":    map[string]any{"docker-manifest-digest": manifestDigest},
			"type":     cosignSimpleSigningType,
		},
		"optional": nil,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// pushSubjectImage pushes a random image and returns its parsed reference and
// resolved descriptor (digest).
func pushSubjectImage(t *testing.T, host, repo string) (name.Reference, *v1.Descriptor) {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:v1", host, repo))
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push subject image: %v", err)
	}
	desc, err := remote.Head(ref)
	if err != nil {
		t.Fatalf("head subject image: %v", err)
	}
	return ref, desc
}

// pushClassicSignature builds and pushes a cosign .sig image (one simple-signing
// layer carrying the given annotations) at the classic sha256-<hex>.sig tag.
func pushClassicSignature(t *testing.T, ref name.Reference, digest v1.Hash, payload []byte, annotations map[string]string) {
	t.Helper()
	layer := static.NewLayer(payload, types.MediaType(simpleSigningMediaType))
	sigImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: annotations,
	})
	if err != nil {
		t.Fatalf("build sig image: %v", err)
	}
	sigRef := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", digest.Algorithm, digest.Hex))
	if err := remote.Write(sigRef, sigImg); err != nil {
		t.Fatalf("push sig image: %v", err)
	}
}

// keyedVerifier builds an enforce-mode keyed verifier for the given public key.
func keyedVerifier(t *testing.T, pubPEM string) (imagetrust.Verifier, imagetrust.Config) {
	t.Helper()
	cfg, err := imagetrust.BuildConfig(imagetrust.RawConfig{
		Mode:               imagetrust.ModeEnforce,
		AllowedSigningKeys: []imagetrust.SigningKeyConfig{{PEM: pubPEM}},
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	v, err := imagetrust.New(cfg)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v, cfg
}

func TestFetchCandidates_ClassicKeyed_Success(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)
	ref, desc := pushSubjectImage(t, host, "app")

	signer, pubPEM := signingKeyPair(t)
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), desc.Digest.String())
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pushClassicSignature(t, ref, desc.Digest, payload, map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(sig),
	})

	candidates, err := NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if err != nil {
		t.Fatalf("FetchCandidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}

	// The reconstructed bundle must verify against the configured key end-to-end.
	v, cfg := keyedVerifier(t, pubPEM)
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, v, cfg, nil, ref.Name(), candidates, nil)
	if !outcome.Allowed {
		t.Fatalf("verification denied a valid signature: %s", outcome.FailureMsg)
	}
}

func TestFetchCandidates_ClassicKeyed_TamperedSignatureFails(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)
	ref, desc := pushSubjectImage(t, host, "app")

	signer, pubPEM := signingKeyPair(t)
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), desc.Digest.String())
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip the last byte of the signature.
	sig[len(sig)-1] ^= 0xFF
	pushClassicSignature(t, ref, desc.Digest, payload, map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(sig),
	})

	candidates, err := NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if err != nil {
		t.Fatalf("FetchCandidates: %v", err)
	}
	v, cfg := keyedVerifier(t, pubPEM)
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, v, cfg, nil, ref.Name(), candidates, nil)
	if outcome.Allowed {
		t.Fatal("verification ALLOWED a tampered signature — must deny")
	}
}

func TestFetchCandidates_DigestBindingMismatchRejected(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)
	ref, desc := pushSubjectImage(t, host, "app")

	signer, _ := signingKeyPair(t)
	// Sign a payload that vouches for a DIFFERENT image digest.
	wrong := sha256.Sum256([]byte("not-this-image"))
	wrongDigest := "sha256:" + hex.EncodeToString(wrong[:])
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), wrongDigest)
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pushClassicSignature(t, ref, desc.Digest, payload, map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(sig),
	})

	// A cryptographically valid signature that binds to another image must not
	// produce a candidate for this image.
	_, err = NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("got err %v, want ErrNoSignatures (transplanted signature must be rejected)", err)
	}
}

// TestFetchCandidates_RepositoryBindingMismatchRejected is a regression test
// for the cross-repository signature-transplant finding: a genuinely-signed
// manifest and its cosign signature are copied byte-for-byte from the
// repository they were signed for into a different, attacker-controlled
// repository (mirroring keeps the digest identical since content is
// addressed by hash). Before the fix, payloadBindsTo only checked the
// manifest digest, so the copied signature verified for the attacker's
// repository too; after the fix it must not, because the payload's
// docker-reference names the victim's repository, not the attacker's.
func TestFetchCandidates_RepositoryBindingMismatchRejected(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)

	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	victimRef, err := name.ParseReference(fmt.Sprintf("%s/victim/app:v1", host))
	if err != nil {
		t.Fatalf("parse victim ref: %v", err)
	}
	if err := remote.Write(victimRef, img); err != nil {
		t.Fatalf("push victim image: %v", err)
	}
	desc, err := remote.Head(victimRef)
	if err != nil {
		t.Fatalf("head victim image: %v", err)
	}

	// The attacker mirrors the identical, byte-for-byte image into their own
	// repository; content-addressing means it resolves to the same digest.
	attackerRef, err := name.ParseReference(fmt.Sprintf("%s/attacker/app:v1", host))
	if err != nil {
		t.Fatalf("parse attacker ref: %v", err)
	}
	if err := remote.Write(attackerRef, img); err != nil {
		t.Fatalf("push attacker image: %v", err)
	}

	// A genuine signature for the victim's repository.
	signer, pubPEM := signingKeyPair(t)
	payload := simpleSigningPayloadFor(t, victimRef.Context().Name(), desc.Digest.String())
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The attacker copies the identical signature manifest (public, non-secret
	// data) into their own repository at the classic .sig tag.
	pushClassicSignature(t, attackerRef, desc.Digest, payload, map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(sig),
	})

	// A client pulling from the attacker's repository must get no verified
	// candidates: the signature's docker-reference names victim/app, not
	// attacker/app, even though the digest matches exactly.
	_, err = NewFetcher().FetchCandidates(ctx, nil, attackerRef.Name())
	if !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("got err %v, want ErrNoSignatures (transplanted cross-repository signature must be rejected)", err)
	}

	// Sanity check: the identical signature+payload DOES verify against the
	// victim's own repository, proving the rejection above is about repository
	// identity and not a broken signature.
	pushClassicSignature(t, victimRef, desc.Digest, payload, map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(sig),
	})
	candidates, err := NewFetcher().FetchCandidates(ctx, nil, victimRef.Name())
	if err != nil {
		t.Fatalf("FetchCandidates(victim): %v", err)
	}
	v, cfg := keyedVerifier(t, pubPEM)
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, v, cfg, nil, victimRef.Name(), candidates, nil)
	if !outcome.Allowed {
		t.Fatalf("verification denied a valid same-repository signature: %s", outcome.FailureMsg)
	}
}

func TestFetchCandidates_UnsignedImageReturnsErrNoSignatures(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)
	ref, _ := pushSubjectImage(t, host, "app")

	_, err := NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("got err %v, want ErrNoSignatures for an unsigned image", err)
	}
}

func TestFetchCandidates_GoodAndBadLayers_GoodWins(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)
	ref, desc := pushSubjectImage(t, host, "app")

	signer, pubPEM := signingKeyPair(t)
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), desc.Digest.String())
	goodSig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Two signature layers on the same .sig manifest: one garbage, one valid.
	layerBad := static.NewLayer(payload, types.MediaType(simpleSigningMediaType))
	layerGood := static.NewLayer(payload, types.MediaType(simpleSigningMediaType))
	sigImg, err := mutate.Append(empty.Image,
		mutate.Addendum{Layer: layerBad, Annotations: map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("garbage")),
		}},
		mutate.Addendum{Layer: layerGood, Annotations: map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString(goodSig),
		}},
	)
	if err != nil {
		t.Fatalf("build sig image: %v", err)
	}
	sigRef := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", desc.Digest.Algorithm, desc.Digest.Hex))
	if err := remote.Write(sigRef, sigImg); err != nil {
		t.Fatalf("push sig image: %v", err)
	}

	candidates, err := NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if err != nil {
		t.Fatalf("FetchCandidates: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(candidates))
	}
	v, cfg := keyedVerifier(t, pubPEM)
	outcome := imagetrust.VerifyCandidatesWithMode(ctx, v, cfg, nil, ref.Name(), candidates, nil)
	if !outcome.Allowed {
		t.Fatalf("expected the valid layer to verify, got denial: %s", outcome.FailureMsg)
	}
}

func TestFetchCandidates_InvalidReference(t *testing.T) {
	_, err := NewFetcher().FetchCandidates(context.Background(), nil, "::::not a ref::::")
	if err == nil {
		t.Fatal("expected an error for an unparseable reference")
	}
	if errors.Is(err, ErrNoSignatures) {
		t.Fatal("a parse error should not be reported as ErrNoSignatures")
	}
}

func TestReadLayerPayloadLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "at limit", size: maxPayloadBytes},
		{name: "oversize", size: maxPayloadBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer := static.NewLayer(bytes.Repeat([]byte("x"), tt.size), types.MediaType(simpleSigningMediaType))
			_, err := readLayerPayload(layer)
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "exceeds")) {
				t.Fatalf("readLayerPayload() error = %v, want size-limit error", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("readLayerPayload() error = %v, want nil", err)
			}
		})
	}
}

// --- unit tests for the keyless reconstruction internals ---

func TestPayloadBindsTo(t *testing.T) {
	repo, err := name.NewRepository("example.com/app")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: "ab" + hexRepeat(62)}
	good := simpleSigningPayloadFor(t, "example.com/app", digest.String())
	if !payloadBindsTo(good, digest, repo) {
		t.Fatal("payloadBindsTo rejected a matching payload")
	}

	other := v1.Hash{Algorithm: "sha256", Hex: "cd" + hexRepeat(62)}
	if payloadBindsTo(good, other, repo) {
		t.Fatal("payloadBindsTo accepted a mismatched digest")
	}

	wrongType := []byte(`{"critical":{"type":"something else","identity":{"docker-reference":"example.com/app"},"image":{"docker-manifest-digest":"` + digest.String() + `"}}}`)
	if payloadBindsTo(wrongType, digest, repo) {
		t.Fatal("payloadBindsTo accepted a non-cosign payload type")
	}

	if payloadBindsTo([]byte("not json"), digest, repo) {
		t.Fatal("payloadBindsTo accepted invalid JSON")
	}

	// Regression for the cross-repository signature-transplant finding: a
	// genuinely-signed manifest+signature payload for one repository (both are
	// public, non-secret data) must not verify when the identical bytes are
	// copied into a different, attacker-controlled repository — the digest
	// alone matches, but the signer's claimed identity doesn't.
	attackerRepo, err := name.NewRepository("attacker.example/anything")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	if payloadBindsTo(good, digest, attackerRepo) {
		t.Fatal("payloadBindsTo accepted a payload signed for a different repository (signature-transplant)")
	}

	// A payload missing docker-reference entirely must fail closed rather than
	// silently skip the repository check.
	noIdentity := []byte(`{"critical":{"type":"` + cosignSimpleSigningType + `","image":{"docker-manifest-digest":"` + digest.String() + `"}}}`)
	if payloadBindsTo(noIdentity, digest, repo) {
		t.Fatal("payloadBindsTo accepted a payload with no docker-reference")
	}
}

func TestBuildBundle_KeyedHasPublicKeyMaterialNoTlog(t *testing.T) {
	payload := []byte("payload")
	pb, err := buildBundle(payload, []byte("sig"), "", "")
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if pb.GetMessageSignature() == nil {
		t.Fatal("expected a MessageSignature content")
	}
	if pb.VerificationMaterial.GetPublicKey() == nil {
		t.Fatal("keyed bundle must use public-key verification material")
	}
	if len(pb.VerificationMaterial.TlogEntries) != 0 {
		t.Fatal("keyed bundle must not carry tlog entries")
	}
	want := sha256.Sum256(payload)
	if !bytes.Equal(pb.GetMessageSignature().MessageDigest.Digest, want[:]) {
		t.Fatal("message digest is not sha256(payload)")
	}
}

func TestTlogEntryFromAnnotation(t *testing.T) {
	body := []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`)
	logKeyHex := "c0ffee" + hexRepeat(58)
	annotation := map[string]any{
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("set-bytes")),
		"Payload": map[string]any{
			"body":           base64.StdEncoding.EncodeToString(body),
			"integratedTime": 1700000000,
			"logIndex":       42,
			"logID":          logKeyHex,
		},
	}
	raw, err := json.Marshal(annotation)
	if err != nil {
		t.Fatalf("marshal annotation: %v", err)
	}

	entry, err := tlogEntryFromAnnotation(string(raw))
	if err != nil {
		t.Fatalf("tlogEntryFromAnnotation: %v", err)
	}
	if entry.LogIndex != 42 || entry.IntegratedTime != 1700000000 {
		t.Fatalf("logIndex/integratedTime mismatch: %+v", entry)
	}
	if entry.KindVersion.Kind != "hashedrekord" || entry.KindVersion.Version != "0.0.1" {
		t.Fatalf("kindVersion mismatch: %+v", entry.KindVersion)
	}
	wantKeyID, _ := hex.DecodeString(logKeyHex)
	if !bytes.Equal(entry.LogId.KeyId, wantKeyID) {
		t.Fatal("logID was not hex-decoded into LogId.KeyId")
	}
	if string(entry.InclusionPromise.SignedEntryTimestamp) != "set-bytes" {
		t.Fatal("SET bytes not carried through")
	}
	if !bytes.Equal(entry.CanonicalizedBody, body) {
		t.Fatal("canonicalized body must be the base64-decoded entry body")
	}
}

func TestTlogEntryFromAnnotation_Empty(t *testing.T) {
	if _, err := tlogEntryFromAnnotation(""); err == nil {
		t.Fatal("expected error for empty annotation")
	}
	if _, err := tlogEntryFromAnnotation(`{"Payload":{}}`); err == nil {
		t.Fatal("expected error when SET/body are missing")
	}
}

// hexRepeat returns a string of n hex '0' characters; helper to pad fake digests
// to the expected 64-hex length.
func hexRepeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}
