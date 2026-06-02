// Package imagefetch resolves a container image reference to its manifest
// digest, discovers the cosign signatures attached to it in the OCI registry,
// and reconstructs a sigstore-go verification bundle for each signature so the
// internal/imagetrust verifier can check it against the operator's configured
// keys or keyless identities.
//
// Two discovery methods are supported, covering essentially every image cosign
// can sign today:
//
//   - Classic tag: cosign stores the signature manifest under the tag
//     "sha256-<hex>.sig" alongside the image. This is the default cosign layout.
//   - OCI 1.1 referrers: cosign's referrers mode attaches the signature
//     manifest as a referrer of the image digest. The signature manifest
//     content is identical to the classic layout, so one parser handles both.
//
// Each signature manifest layer carries a "simple signing" payload (the layer
// blob) plus cosign annotations: the raw signature, and — for keyless
// signatures — the Fulcio certificate and the Rekor inclusion bundle. The
// signature is computed over sha256(payload), and the payload itself names the
// image digest it vouches for. imagefetch enforces that binding (rejecting any
// signature whose payload does not reference the exact resolved manifest
// digest) before handing the bundle to the verifier, which prevents a valid
// signature for one image from being transplanted onto another.
package imagefetch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/codeswhat/sockguard/internal/imagetrust"
)

const (
	// cosignSignatureAnnotation holds the base64-encoded raw signature over the
	// simple-signing payload (present on every cosign signature layer).
	cosignSignatureAnnotation = "dev.cosignproject.cosign/signature"
	// cosignCertAnnotation holds the PEM Fulcio certificate for keyless signatures.
	cosignCertAnnotation = "dev.sigstore.cosign/certificate"
	// cosignBundleAnnotation holds the Rekor inclusion bundle (SET + entry body).
	cosignBundleAnnotation = "dev.sigstore.cosign/bundle"

	// cosignSigArtifactType is the OCI 1.1 referrers artifactType cosign uses for
	// classic simple-signing signatures attached as referrers.
	cosignSigArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"

	// bundleMediaTypeV01 is the sigstore bundle media type for v0.1. Classic
	// cosign annotations carry a Rekor inclusion *promise* (SET) but not an
	// inclusion *proof*; sigstore-go only permits a promise-only tlog entry at
	// bundle version v0.1 (v0.2+ requires a full inclusion proof).
	bundleMediaTypeV01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"

	// cosignSimpleSigningType is the value of critical.type in a cosign
	// container-image simple-signing payload.
	cosignSimpleSigningType = "cosign container image signature"

	// maxPayloadBytes caps the simple-signing payload blob read. Real payloads
	// are a few hundred bytes; the cap defends against a hostile registry.
	maxPayloadBytes = 1 << 20
)

// ErrNoSignatures is returned when an image resolves successfully but carries no
// cosign signature that binds to its manifest digest. Callers in enforce mode
// must treat this as a verification failure (deny).
var ErrNoSignatures = errors.New("no cosign signatures found")

// Fetcher discovers and reconstructs image signatures. The zero value is not
// usable; construct one with NewFetcher.
type Fetcher struct {
	keychain   authn.Keychain
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

// NewFetcher returns a Fetcher that authenticates to registries using the
// ambient Docker keychain (mounted config.json), falling back to anonymous
// access for public images.
func NewFetcher() *Fetcher {
	return &Fetcher{keychain: authn.DefaultKeychain}
}

// Option configures a Fetcher. Used by tests to point at an in-memory registry.
type Option func(*Fetcher)

// WithRemoteOptions appends go-containerregistry remote options applied to every
// registry call (e.g. a custom transport for an httptest registry).
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(f *Fetcher) { f.remoteOpts = append(f.remoteOpts, opts...) }
}

// WithNameOptions appends name-parsing options (e.g. name.Insecure for plain-HTTP
// test registries).
func WithNameOptions(opts ...name.Option) Option {
	return func(f *Fetcher) { f.nameOpts = append(f.nameOpts, opts...) }
}

// NewFetcherWith builds a Fetcher with the given options.
func NewFetcherWith(opts ...Option) *Fetcher {
	f := NewFetcher()
	for _, o := range opts {
		o(f)
	}
	return f
}

func (f *Fetcher) opts(ctx context.Context) []remote.Option {
	out := make([]remote.Option, 0, len(f.remoteOpts)+2)
	out = append(out, remote.WithContext(ctx), remote.WithAuthFromKeychain(f.keychain))
	out = append(out, f.remoteOpts...)
	return out
}

// FetchCandidates resolves imageRef to its manifest digest, discovers cosign
// signatures, and reconstructs a verification bundle for each signature layer
// whose simple-signing payload binds to that digest. It returns ErrNoSignatures
// (wrapped) when the image is reachable but unsigned.
func (f *Fetcher) FetchCandidates(ctx context.Context, imageRef string) ([]imagetrust.Candidate, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef), f.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	desc, err := remote.Head(ref, f.opts(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest digest for %q: %w", imageRef, err)
	}
	imageDigest := desc.Digest

	sigImages, err := f.discoverSignatureImages(ctx, ref, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("discover signatures for %q: %w", imageRef, err)
	}

	var candidates []imagetrust.Candidate
	for _, sigImg := range sigImages {
		cs, err := candidatesFromSigImage(sigImg, imageDigest)
		if err != nil {
			// A malformed signature manifest must not mask a sibling valid one;
			// skip it and keep scanning.
			continue
		}
		candidates = append(candidates, cs...)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w for %q (resolved %s)", ErrNoSignatures, imageRef, imageDigest)
	}
	return candidates, nil
}

// PinnedReference rewrites imageRef (which may carry a mutable tag) to a
// digest-pinned reference of the form "registry/repo@sha256:<hex>", using the
// supplied digest ("sha256:<hex>"). Callers use this after a successful trust
// verification so the reference forwarded to dockerd resolves to exactly the
// digest that was verified, closing the verify→pull TOCTOU.
func PinnedReference(imageRef, digest string) (string, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef), name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}
	pinned, err := name.NewDigest(ref.Context().Name()+"@"+strings.TrimSpace(digest), name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("build digest reference for %q: %w", imageRef, err)
	}
	return pinned.Name(), nil
}

// discoverSignatureImages returns the distinct signature manifests attached to
// imageDigest via the classic .sig tag and via OCI 1.1 referrers. Discovery
// failures from either method are non-fatal: a registry without referrers
// support still yields the classic tag, and vice versa.
func (f *Fetcher) discoverSignatureImages(ctx context.Context, ref name.Reference, imageDigest v1.Hash) ([]v1.Image, error) {
	seen := make(map[string]struct{})
	var imgs []v1.Image

	add := func(img v1.Image) {
		dig, err := img.Digest()
		if err != nil {
			return
		}
		if _, dup := seen[dig.String()]; dup {
			return
		}
		seen[dig.String()] = struct{}{}
		imgs = append(imgs, img)
	}

	// Classic layout: repo:sha256-<hex>.sig
	sigTag := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", imageDigest.Algorithm, imageDigest.Hex))
	if img, err := remote.Image(sigTag, f.opts(ctx)...); err == nil {
		add(img)
	}

	// OCI 1.1 referrers layout.
	digestRef := ref.Context().Digest(imageDigest.String())
	if idx, err := remote.Referrers(digestRef, f.opts(ctx)...); err == nil {
		if im, err := idx.IndexManifest(); err == nil {
			for _, m := range im.Manifests {
				if m.ArtifactType != cosignSigArtifactType {
					continue
				}
				if rImg, err := remote.Image(ref.Context().Digest(m.Digest.String()), f.opts(ctx)...); err == nil {
					add(rImg)
				}
			}
		}
	}

	return imgs, nil
}

// candidatesFromSigImage extracts one verification candidate per signature layer
// whose simple-signing payload binds to imageDigest.
func candidatesFromSigImage(sigImg v1.Image, imageDigest v1.Hash) ([]imagetrust.Candidate, error) {
	mf, err := sigImg.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read signature manifest: %w", err)
	}

	var out []imagetrust.Candidate
	for _, layerDesc := range mf.Layers {
		sigB64 := strings.TrimSpace(layerDesc.Annotations[cosignSignatureAnnotation])
		if sigB64 == "" {
			continue
		}

		layer, err := sigImg.LayerByDigest(layerDesc.Digest)
		if err != nil {
			continue
		}
		payload, err := readLayerPayload(layer)
		if err != nil {
			continue
		}

		// Security-critical binding: the payload must vouch for exactly the image
		// we resolved. Without this, a valid signature for image B could be
		// replayed to authorize creating image A.
		if !payloadBindsTo(payload, imageDigest) {
			continue
		}

		rawSig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			continue
		}

		pb, err := buildBundle(payload, rawSig,
			layerDesc.Annotations[cosignCertAnnotation],
			layerDesc.Annotations[cosignBundleAnnotation],
		)
		if err != nil {
			continue
		}
		b, err := bundle.NewBundle(pb)
		if err != nil {
			continue
		}

		digest := sha256.Sum256(payload)
		out = append(out, imagetrust.Candidate{
			DigestHex:   hex.EncodeToString(digest[:]),
			Entity:      b,
			ImageDigest: imageDigest.String(),
		})
	}
	return out, nil
}

func readLayerPayload(layer v1.Layer) ([]byte, error) {
	// cosign simple-signing layers are stored uncompressed; Compressed() returns
	// the raw stored blob (the payload) without attempting gunzip.
	rc, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxPayloadBytes))
}

// simpleSigningPayload is the subset of the cosign simple-signing payload we
// inspect to bind a signature to an image digest.
type simpleSigningPayload struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func payloadBindsTo(payload []byte, imageDigest v1.Hash) bool {
	var ss simpleSigningPayload
	if err := json.Unmarshal(payload, &ss); err != nil {
		return false
	}
	if ss.Critical.Type != cosignSimpleSigningType {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(ss.Critical.Image.DockerManifestDigest), imageDigest.String())
}

// buildBundle assembles a sigstore protobuf bundle from a cosign signature
// layer's payload, raw signature, and (for keyless) certificate + Rekor bundle
// annotations. An empty certPEM produces a keyed bundle (public-key material, no
// tlog); a non-empty certPEM produces a keyless bundle (Fulcio cert chain plus a
// reconstructed Rekor inclusion-promise tlog entry).
func buildBundle(payload, rawSig []byte, certPEM, rekorBundleJSON string) (*protobundle.Bundle, error) {
	digest := sha256.Sum256(payload)
	content := &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    digest[:],
			},
			Signature: rawSig,
		},
	}

	certPEM = strings.TrimSpace(certPEM)
	if certPEM == "" {
		// Keyed signature: the verifier supplies the operator's public key from
		// its own trusted material; the bundle only needs public-key material to
		// pass validation and select the WithKey policy path.
		return &protobundle.Bundle{
			MediaType: bundleMediaTypeV01,
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_PublicKey{
					PublicKey: &protocommon.PublicKeyIdentifier{Hint: "cosign"},
				},
			},
			Content: content,
		}, nil
	}

	der, err := pemCertToDER(certPEM)
	if err != nil {
		return nil, fmt.Errorf("decode certificate: %w", err)
	}
	vm := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: der}},
			},
		},
	}
	if entry, err := tlogEntryFromAnnotation(rekorBundleJSON); err == nil && entry != nil {
		vm.TlogEntries = []*protorekor.TransparencyLogEntry{entry}
	}

	return &protobundle.Bundle{
		MediaType:            bundleMediaTypeV01,
		VerificationMaterial: vm,
		Content:              content,
	}, nil
}

// cosignRekorBundle mirrors the JSON shape cosign writes to the
// dev.sigstore.cosign/bundle annotation. encoding/json decodes the base64
// SignedEntryTimestamp string directly into the []byte field.
type cosignRekorBundle struct {
	SignedEntryTimestamp []byte `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// rekorEntryBody is the minimal envelope used to recover the entry kind/version
// from a canonicalized Rekor body so the reconstructed tlog entry's KindVersion
// matches what sigstore-go parses out of the body itself.
type rekorEntryBody struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func tlogEntryFromAnnotation(rekorBundleJSON string) (*protorekor.TransparencyLogEntry, error) {
	rekorBundleJSON = strings.TrimSpace(rekorBundleJSON)
	if rekorBundleJSON == "" {
		return nil, errors.New("no rekor bundle annotation")
	}
	var rb cosignRekorBundle
	if err := json.Unmarshal([]byte(rekorBundleJSON), &rb); err != nil {
		return nil, fmt.Errorf("parse rekor bundle: %w", err)
	}
	if len(rb.SignedEntryTimestamp) == 0 || rb.Payload.Body == "" {
		return nil, errors.New("rekor bundle missing SET or body")
	}

	body, err := base64.StdEncoding.DecodeString(rb.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("decode rekor body: %w", err)
	}
	logKeyID, err := hex.DecodeString(rb.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("decode rekor logID: %w", err)
	}

	var eb rekorEntryBody
	if err := json.Unmarshal(body, &eb); err != nil {
		return nil, fmt.Errorf("parse rekor entry body: %w", err)
	}

	return &protorekor.TransparencyLogEntry{
		LogIndex:       rb.Payload.LogIndex,
		LogId:          &protocommon.LogId{KeyId: logKeyID},
		KindVersion:    &protorekor.KindVersion{Kind: eb.Kind, Version: eb.APIVersion},
		IntegratedTime: rb.Payload.IntegratedTime,
		InclusionPromise: &protorekor.InclusionPromise{
			SignedEntryTimestamp: rb.SignedEntryTimestamp,
		},
		CanonicalizedBody: body,
	}, nil
}

// pemCertToDER decodes the leaf certificate from a PEM block (the Fulcio leaf
// cosign stores in the certificate annotation) and returns its DER bytes.
func pemCertToDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no PEM certificate block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	return block.Bytes, nil
}
