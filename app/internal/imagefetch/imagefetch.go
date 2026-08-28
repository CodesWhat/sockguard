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
// signature is computed over sha256(payload), and the payload itself names
// both the image digest and the source registry/repository (docker-reference)
// it vouches for. imagefetch enforces both bindings (rejecting any signature
// whose payload does not reference the exact resolved manifest digest, or
// whose docker-reference names a different registry/repository than the one
// being pulled from) before handing the bundle to the verifier. Digest binding
// alone stops a signature for image B being transplanted onto image A;
// docker-reference binding additionally stops a genuinely-signed
// manifest+signature pair — both public, non-secret data — from being copied
// byte-for-byte into an attacker-controlled repository and re-verifying there.
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
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/codeswhat/sockguard/app/internal/imagetrust"
	"github.com/codeswhat/sockguard/app/internal/logging"
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

	// Registry-controlled signature metadata is intentionally bounded well
	// above normal cosign output, where an image normally has one signature
	// image with one layer and a few kilobytes of annotations.
	maxReferrerDescriptors   = 32
	maxSignatureImages       = 16
	maxSignatureLayers       = 32
	maxCandidates            = 16
	maxAnnotationBytes       = 256 << 10
	maxAggregatePayloadBytes = 16 << 20
	maxMetadataResponseBytes = 4 << 20
)

// ErrNoSignatures is returned when an image resolves successfully but carries no
// cosign signature that binds to its manifest digest. Callers in enforce mode
// must treat this as a verification failure (deny).
var ErrNoSignatures = errors.New("no cosign signatures found")

var errRegistryInputLimit = errors.New("registry signature input limit exceeded")

// Fetcher discovers and reconstructs image signatures. The zero value is not
// usable; construct one with NewFetcher.
type Fetcher struct {
	keychain   authn.Keychain
	transport  http.RoundTripper
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

// NewFetcher returns a Fetcher that authenticates to registries using the
// ambient Docker keychain (mounted config.json), falling back to anonymous
// access for public images.
func NewFetcher() *Fetcher {
	return &Fetcher{
		keychain:  authn.DefaultKeychain,
		transport: remote.DefaultTransport,
	}
}

// Option configures a Fetcher. Used by tests to point at an in-memory registry.
type Option func(*Fetcher)

// WithRemoteOptions appends non-transport go-containerregistry options applied
// to every registry call. Use WithRegistryTransport for a custom transport so
// Sockguard can retain its metadata response-size boundary around it.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(f *Fetcher) { f.remoteOpts = append(f.remoteOpts, opts...) }
}

// WithRegistryTransport replaces the base registry transport. Sockguard wraps
// it with the same metadata response-size boundary used in production.
func WithRegistryTransport(transport http.RoundTripper) Option {
	return func(f *Fetcher) { f.transport = transport }
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
	baseTransport := f.transport
	if baseTransport == nil {
		baseTransport = remote.DefaultTransport
	}
	out := make([]remote.Option, 0, len(f.remoteOpts)+3)
	out = append(out,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(f.keychain),
	)
	out = append(out, f.remoteOpts...)
	// Install this last so an opaque remote.WithTransport option cannot replace
	// the input boundary. Custom transports belong in WithRegistryTransport and
	// become the wrapped base instead.
	out = append(out, remote.WithTransport(&metadataLimitTransport{base: baseTransport}))
	return out
}

func (f *Fetcher) signatureImage(ctx context.Context, ref name.Reference) (v1.Image, error) {
	desc, err := remote.Get(ref, f.opts(ctx)...)
	if err != nil {
		return nil, err
	}
	mediaType, _, err := mime.ParseMediaType(string(desc.MediaType))
	if err != nil {
		return nil, fmt.Errorf("signature reference %q has invalid media type %q: %w", ref.Name(), desc.MediaType, err)
	}
	desc.MediaType = types.MediaType(mediaType)
	if !desc.MediaType.IsImage() {
		return nil, fmt.Errorf("signature reference %q has media type %q; image manifest required", ref.Name(), desc.MediaType)
	}
	return desc.Image()
}

type metadataLimitTransport struct {
	base http.RoundTripper
}

func (t *metadataLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil || req.Method != http.MethodGet {
		return resp, err
	}
	// Apply the ceiling to every GET response, not just URLs whose current path
	// looks like a manifest or referrers endpoint. net/http follows redirects by
	// issuing a fresh request for the Location URL, which may be an opaque CDN
	// path; limiting every hop keeps a registry from redirecting around the
	// metadata boundary. Signature blobs retain the stricter 1 MiB payload cap.
	resp.Body = &metadataLimitReadCloser{
		body:      resp.Body,
		remaining: maxMetadataResponseBytes,
	}
	return resp, nil
}

type metadataLimitReadCloser struct {
	body      io.ReadCloser
	remaining int64
}

func (r *metadataLimitReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining > 0 {
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.body.Read(p)
		r.remaining -= int64(n)
		return n, err
	}

	var probe [1]byte
	if n, err := r.body.Read(probe[:]); n > 0 {
		return 0, inputLimitError("registry metadata response exceeds %d byte limit", maxMetadataResponseBytes)
	} else {
		return 0, err
	}
}

func (r *metadataLimitReadCloser) Close() error {
	return r.body.Close()
}

// FetchCandidates resolves imageRef to its manifest digest, discovers cosign
// signatures, and reconstructs a verification bundle for each signature layer
// whose simple-signing payload binds to that digest. It returns ErrNoSignatures
// (wrapped) when the image is reachable but unsigned.
func (f *Fetcher) FetchCandidates(ctx context.Context, logger *slog.Logger, imageRef string) ([]imagetrust.Candidate, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef), f.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	desc, err := remote.Head(ref, f.opts(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest digest for %q: %w", imageRef, err)
	}
	imageDigest := desc.Digest

	var candidates []imagetrust.Candidate
	var candidateErrs []error
	budget := &candidateBudget{}
	err = f.visitSignatureImages(ctx, ref, imageDigest, budget, func(sigImg v1.Image) error {
		cs, candidateErr := candidatesFromSigImageWithBudget(sigImg, imageDigest, ref.Context(), budget)
		if errors.Is(candidateErr, errRegistryInputLimit) {
			return candidateErr
		}
		candidates = append(candidates, cs...)
		if candidateErr != nil {
			// A malformed signature manifest must not mask a sibling valid one;
			// skip it and keep scanning. Leave a debug breadcrumb so an operator
			// can tell a verification miss apart from a silently-dropped manifest.
			if logger != nil {
				logger.DebugContext(ctx, "skipping malformed cosign signature manifest",
					"image_ref", logging.SafeString(imageRef), "resolved_digest", logging.SafeString(imageDigest.String()), "error", logging.SafeString(candidateErr.Error()))
			}
			candidateErrs = append(candidateErrs, candidateErr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover signatures for %q: %w", imageRef, err)
	}

	if len(candidates) == 0 {
		baseErr := fmt.Errorf("%w for %q (resolved %s)", ErrNoSignatures, imageRef, imageDigest)
		if len(candidateErrs) > 0 {
			return nil, fmt.Errorf("%w: signature parsing failures: %w", baseErr, errors.Join(candidateErrs...))
		}
		return nil, baseErr
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

// visitSignatureImages visits each distinct signature manifest attached to
// imageDigest via the classic .sig tag and OCI 1.1 referrers. Images are
// processed as they are discovered instead of being retained as an attacker-
// sized slice. Discovery failures from either method remain non-fatal so a
// registry without referrers support can still yield the classic tag, and vice
// versa. Explicit input-limit failures always stop discovery and fail closed.
func (f *Fetcher) visitSignatureImages(ctx context.Context, ref name.Reference, imageDigest v1.Hash, budget *candidateBudget, visit func(v1.Image) error) error {
	seen := make(map[string]struct{})
	signatureImages := 0

	add := func(img v1.Image) error {
		dig, err := img.Digest()
		if err != nil {
			return nil
		}
		if _, dup := seen[dig.String()]; dup {
			return nil
		}
		if signatureImages >= maxSignatureImages {
			return inputLimitError("cosign signature images exceed %d limit", maxSignatureImages)
		}
		seen[dig.String()] = struct{}{}
		signatureImages++
		return visit(img)
	}

	// Classic layout: repo:sha256-<hex>.sig
	sigTag := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", imageDigest.Algorithm, imageDigest.Hex))
	if img, err := f.signatureImage(ctx, sigTag); err == nil {
		if err := add(img); err != nil {
			return err
		}
	} else if errors.Is(err, errRegistryInputLimit) {
		return err
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	// OCI 1.1 referrers layout.
	digestRef := ref.Context().Digest(imageDigest.String())
	if idx, err := remote.Referrers(digestRef, f.opts(ctx)...); err == nil {
		if im, err := idx.IndexManifest(); err == nil {
			if err := budget.addIndexAnnotations(im); err != nil {
				return err
			}
			if len(im.Manifests) > maxReferrerDescriptors {
				return inputLimitError("registry returned %d referrers; limit is %d", len(im.Manifests), maxReferrerDescriptors)
			}
			for _, m := range im.Manifests {
				if m.ArtifactType != cosignSigArtifactType {
					continue
				}
				if rImg, err := f.signatureImage(ctx, ref.Context().Digest(m.Digest.String())); err == nil {
					if err := add(rImg); err != nil {
						return err
					}
				} else if errors.Is(err, errRegistryInputLimit) {
					return err
				} else if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
			}
		}
	} else if errors.Is(err, errRegistryInputLimit) {
		return err
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	return ctx.Err()
}

// candidatesFromSigImage extracts one verification candidate per signature layer
// whose simple-signing payload binds to imageDigest in wantRepo.
func candidatesFromSigImage(sigImg v1.Image, imageDigest v1.Hash, wantRepo name.Repository) ([]imagetrust.Candidate, error) {
	return candidatesFromSigImageWithBudget(sigImg, imageDigest, wantRepo, &candidateBudget{})
}

type candidateBudget struct {
	annotationBytes int
	payloadBytes    int64
	candidates      int
}

func inputLimitError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRegistryInputLimit, fmt.Sprintf(format, args...))
}

func (b *candidateBudget) addAnnotationMap(annotations map[string]string) error {
	for key, value := range annotations {
		materialBytes := len(key) + len(value)
		if materialBytes > maxAnnotationBytes-b.annotationBytes {
			return inputLimitError("cosign annotation material exceeds %d byte limit", maxAnnotationBytes)
		}
		b.annotationBytes += materialBytes
	}
	return nil
}

func (b *candidateBudget) addIndexAnnotations(im *v1.IndexManifest) error {
	if err := b.addAnnotationMap(im.Annotations); err != nil {
		return err
	}
	if im.Subject != nil {
		if err := b.addAnnotationMap(im.Subject.Annotations); err != nil {
			return err
		}
	}
	for _, manifest := range im.Manifests {
		if err := b.addAnnotationMap(manifest.Annotations); err != nil {
			return err
		}
	}
	return nil
}

func (b *candidateBudget) addManifestAnnotations(mf *v1.Manifest) error {
	if err := b.addAnnotationMap(mf.Annotations); err != nil {
		return err
	}
	if err := b.addAnnotationMap(mf.Config.Annotations); err != nil {
		return err
	}
	if mf.Subject != nil {
		if err := b.addAnnotationMap(mf.Subject.Annotations); err != nil {
			return err
		}
	}
	for _, layer := range mf.Layers {
		if err := b.addAnnotationMap(layer.Annotations); err != nil {
			return err
		}
	}
	return nil
}

func (b *candidateBudget) addCandidate() error {
	if b.candidates >= maxCandidates {
		return inputLimitError("cosign verification candidates exceed %d limit", maxCandidates)
	}
	b.candidates++
	return nil
}

func candidatesFromSigImageWithBudget(sigImg v1.Image, imageDigest v1.Hash, wantRepo name.Repository, budget *candidateBudget) ([]imagetrust.Candidate, error) {
	mf, err := sigImg.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read signature manifest: %w", err)
	}
	if len(mf.Layers) > maxSignatureLayers {
		return nil, inputLimitError("signature manifest has %d layers; limit is %d", len(mf.Layers), maxSignatureLayers)
	}
	if err := budget.addManifestAnnotations(mf); err != nil {
		return nil, err
	}

	var out []imagetrust.Candidate
	var layerErrs []error
	for _, layerDesc := range mf.Layers {
		sigB64 := strings.TrimSpace(layerDesc.Annotations[cosignSignatureAnnotation])
		if sigB64 == "" {
			continue
		}
		if len(layerDesc.URLs) != 0 {
			return out, inputLimitError("cosign signature payload layer uses alternate URLs")
		}

		layer, err := sigImg.LayerByDigest(layerDesc.Digest)
		if err != nil {
			layerErrs = append(layerErrs, fmt.Errorf("layer %s: resolve blob: %w", layerDesc.Digest, err))
			continue
		}
		payload, err := readLayerPayloadWithBudget(layer, budget)
		if err != nil {
			if errors.Is(err, errRegistryInputLimit) {
				return out, err
			}
			layerErrs = append(layerErrs, fmt.Errorf("layer %s: read payload: %w", layerDesc.Digest, err))
			continue
		}

		// Security-critical binding: the payload must vouch for exactly the image
		// digest we resolved, in exactly the repository being pulled from. Without
		// the digest check, a valid signature for image B could be replayed to
		// authorize creating image A. Without the repository check, a genuinely
		// signed manifest+signature for repoA@sha256:X could be copied verbatim
		// into an attacker-controlled repoB and still verify for repoB@sha256:X.
		if !payloadBindsTo(payload, imageDigest, wantRepo) {
			continue
		}

		rawSig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			layerErrs = append(layerErrs, fmt.Errorf("layer %s: decode signature: %w", layerDesc.Digest, err))
			continue
		}

		pb, err := buildBundle(payload, rawSig,
			layerDesc.Annotations[cosignCertAnnotation],
			layerDesc.Annotations[cosignBundleAnnotation],
		)
		if err != nil {
			layerErrs = append(layerErrs, fmt.Errorf("layer %s: build bundle: %w", layerDesc.Digest, err))
			continue
		}
		b, err := bundle.NewBundle(pb)
		if err != nil {
			layerErrs = append(layerErrs, fmt.Errorf("layer %s: parse bundle: %w", layerDesc.Digest, err))
			continue
		}

		digest := sha256.Sum256(payload)
		if err := budget.addCandidate(); err != nil {
			return out, err
		}
		out = append(out, imagetrust.Candidate{
			DigestHex:   hex.EncodeToString(digest[:]),
			Entity:      b,
			ImageDigest: imageDigest.String(),
		})
	}
	return out, errors.Join(layerErrs...)
}

func readLayerPayload(layer v1.Layer) ([]byte, error) {
	return readLayerPayloadWithBudget(layer, &candidateBudget{})
}

func readLayerPayloadWithBudget(layer v1.Layer, budget *candidateBudget) ([]byte, error) {
	// cosign simple-signing layers are stored uncompressed; Compressed() returns
	// the raw stored blob (the payload) without attempting gunzip.
	rc, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	remaining := int64(maxAggregatePayloadBytes) - budget.payloadBytes
	if remaining < 0 {
		return nil, inputLimitError("cosign signature payload material exceeds %d byte limit", maxAggregatePayloadBytes)
	}
	readLimit := int64(maxPayloadBytes)
	if remaining < readLimit {
		readLimit = remaining
	}
	payload, err := io.ReadAll(io.LimitReader(rc, readLimit+1))
	if len(payload) > maxPayloadBytes {
		return nil, inputLimitError("signature payload exceeds %d byte limit", maxPayloadBytes)
	}
	if int64(len(payload)) > remaining {
		return nil, inputLimitError("cosign signature payload material exceeds %d byte limit", maxAggregatePayloadBytes)
	}
	budget.payloadBytes += int64(len(payload))
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// simpleSigningPayload is the subset of the cosign simple-signing payload we
// inspect to bind a signature to an image digest and a source repository.
type simpleSigningPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// payloadBindsTo reports whether payload is a well-formed cosign simple-signing
// payload that vouches for imageDigest in wantRepo. Both the manifest digest and
// the docker-reference identity must match: the digest alone only proves content
// integrity, not that the signer intended this repository to serve it.
func payloadBindsTo(payload []byte, imageDigest v1.Hash, wantRepo name.Repository) bool {
	var ss simpleSigningPayload
	if err := json.Unmarshal(payload, &ss); err != nil {
		return false
	}
	if ss.Critical.Type != cosignSimpleSigningType {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(ss.Critical.Image.DockerManifestDigest), imageDigest.String()) {
		return false
	}
	return payloadRepositoryMatches(ss.Critical.Identity.DockerReference, wantRepo)
}

// payloadRepositoryMatches reports whether dockerReference — the
// critical.identity.docker-reference the signer embedded in the payload — names
// the same registry/repository as wantRepo. Cosign's own payload builder
// (sigstore/pkg/signature/payload.Cosign.SimpleContainerImage) always sets this
// field, defaulting to the signed image's own repository when the signer
// supplies no explicit claimed identity, so a missing or mismatched value means
// the signature was not issued for this repository and must not verify here.
func payloadRepositoryMatches(dockerReference string, wantRepo name.Repository) bool {
	dockerReference = strings.TrimSpace(dockerReference)
	if dockerReference == "" {
		return false
	}
	claimed, err := name.ParseReference(dockerReference, name.WeakValidation)
	if err != nil {
		return false
	}
	return claimed.Context().Name() == wantRepo.Name()
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
