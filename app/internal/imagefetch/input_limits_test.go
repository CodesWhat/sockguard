package imagefetch

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	testMaxReferrerDescriptors = 32
	testMaxSignatureImages     = 16
	testMaxSignatureLayers     = 32
	testMaxCandidates          = 16
	testMaxAnnotationBytes     = 256 << 10
	testMaxAggregatePayload    = 16 << 20
	testMaxMetadataResponse    = 4 << 20
)

type countingTransport struct {
	base  http.RoundTripper
	calls int
}

type terminalErrorReader struct {
	reader *bytes.Reader
	err    error
}

func (r *terminalErrorReader) Read(p []byte) (int, error) {
	if r.reader.Len() == 0 {
		return 0, r.err
	}
	return r.reader.Read(p)
}

type terminalErrorLayer struct {
	v1.Layer
	payload []byte
	err     error
}

type recordingLayerImage struct {
	v1.Image
	resolutions int
}

type manifestErrorImage struct {
	v1.Image
	err error
}

type layerResultImage struct {
	v1.Image
	layer v1.Layer
	err   error
}

type selectedLayerResultImage struct {
	v1.Image
	digest v1.Hash
	layer  v1.Layer
	err    error
}

type compressedErrorLayer struct {
	v1.Layer
	err error
}

func (i *recordingLayerImage) LayerByDigest(digest v1.Hash) (v1.Layer, error) {
	i.resolutions++
	return i.Image.LayerByDigest(digest)
}

func (i manifestErrorImage) Manifest() (*v1.Manifest, error) {
	return nil, i.err
}

func (i layerResultImage) LayerByDigest(v1.Hash) (v1.Layer, error) {
	return i.layer, i.err
}

func (i selectedLayerResultImage) LayerByDigest(digest v1.Hash) (v1.Layer, error) {
	if digest == i.digest {
		return i.layer, i.err
	}
	return i.Image.LayerByDigest(digest)
}

func (l compressedErrorLayer) Compressed() (io.ReadCloser, error) {
	return nil, l.err
}

func (l terminalErrorLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(&terminalErrorReader{reader: bytes.NewReader(l.payload), err: l.err}), nil
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	return t.base.RoundTrip(req)
}

func signatureImageWithLayers(t *testing.T, payload []byte, annotations map[string]string, count int) v1.Image {
	t.Helper()
	addendums := make([]mutate.Addendum, count)
	for i := range addendums {
		addendums[i] = mutate.Addendum{
			Layer:       static.NewLayer(payload, types.MediaType(simpleSigningMediaType)),
			Annotations: annotations,
		}
	}
	img, err := mutate.Append(empty.Image, addendums...)
	if err != nil {
		t.Fatalf("build %d-layer signature image: %v", count, err)
	}
	return img
}

func pushClassicSignatureImage(t *testing.T, ref name.Reference, subjectDigest v1.Hash, img v1.Image) {
	t.Helper()
	sigRef := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", subjectDigest.Algorithm, subjectDigest.Hex))
	if err := remote.Write(sigRef, img); err != nil {
		t.Fatalf("push classic signature image: %v", err)
	}
}

func pushReferrerImage(t *testing.T, ref name.Reference, subject v1.Descriptor, artifactType string, img v1.Image) v1.Hash {
	t.Helper()
	img = mutate.ConfigMediaType(img, types.MediaType(artifactType))
	img = mutate.Subject(img, subject).(v1.Image)
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest referrer image: %v", err)
	}
	if err := remote.Write(ref.Context().Digest(digest.String()), img); err != nil {
		t.Fatalf("push referrer image: %v", err)
	}
	return digest
}

func TestFetchCandidatesRejectsTooManyReferrers(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "referrer-cap")

	for i := 0; i < testMaxReferrerDescriptors+1; i++ {
		img := signatureImageWithLayers(t, []byte(fmt.Sprintf("unrelated-%d", i)), nil, 1)
		pushReferrerImage(t, ref, *subject, "application/vnd.example.unrelated", img)
	}

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("registry returned %d referrers; limit is %d", testMaxReferrerDescriptors+1, testMaxReferrerDescriptors)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsTooManySignatureImages(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "signature-image-cap")

	classic := signatureImageWithLayers(t, []byte("classic-invalid-payload"), map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}, 1)
	pushClassicSignatureImage(t, ref, subject.Digest, classic)
	for i := 0; i < testMaxSignatureImages; i++ {
		img := signatureImageWithLayers(t, []byte(fmt.Sprintf("referrer-invalid-payload-%d", i)), map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
		}, 1)
		pushReferrerImage(t, ref, *subject, cosignSigArtifactType, img)
	}

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("cosign signature images exceed %d limit", testMaxSignatureImages)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsSignatureIndexes(t *testing.T) {
	annotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}

	t.Run("classic tag", func(t *testing.T) {
		host := testRegistry(t)
		ref, subject := pushSubjectImage(t, host, "classic-index")
		payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
		idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
			Add: signatureImageWithLayers(t, payload, annotations, 1),
		})
		sigRef := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", subject.Digest.Algorithm, subject.Digest.Hex))
		if err := remote.WriteIndex(sigRef, idx); err != nil {
			t.Fatalf("push signature index: %v", err)
		}

		_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
		if !errors.Is(err, ErrNoSignatures) {
			t.Fatalf("FetchCandidates() error = %v, want ErrNoSignatures for signature index", err)
		}
	})

	t.Run("referrer", func(t *testing.T) {
		baseRegistry := registry.New(registry.WithReferrersSupport(true))
		var referrersResponse string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/") && referrersResponse != "" {
				w.Header().Set("Content-Type", string(types.OCIImageIndex))
				_, _ = io.WriteString(w, referrersResponse)
				return
			}
			baseRegistry.ServeHTTP(w, r)
		}))
		t.Cleanup(server.Close)
		hostURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatalf("parse registry URL: %v", err)
		}
		ref, subject := pushSubjectImage(t, hostURL.Host, "referrer-index")
		payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
		idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
			Add: signatureImageWithLayers(t, payload, annotations, 1),
		})
		indexDigest, err := idx.Digest()
		if err != nil {
			t.Fatalf("signature index digest: %v", err)
		}
		indexSize, err := idx.Size()
		if err != nil {
			t.Fatalf("signature index size: %v", err)
		}
		if err := remote.WriteIndex(ref.Context().Digest(indexDigest.String()), idx); err != nil {
			t.Fatalf("push signature index: %v", err)
		}
		referrersResponse = fmt.Sprintf(
			`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":%d,"artifactType":%q}]}`,
			types.OCIImageIndex, types.OCIImageIndex, indexDigest.String(), indexSize, cosignSigArtifactType,
		)

		_, err = NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
		if !errors.Is(err, ErrNoSignatures) {
			t.Fatalf("FetchCandidates() error = %v, want ErrNoSignatures for signature index", err)
		}
	})
}

func TestFetchCandidatesPreservesDiscoveryDeadline(t *testing.T) {
	baseRegistry := registry.New(registry.WithReferrersSupport(true))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, ".sig") {
			<-r.Context().Done()
			return
		}
		baseRegistry.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	hostURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	ref, _ := pushSubjectImage(t, hostURL.Host, "deadline")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = NewFetcher().FetchCandidates(ctx, nil, ref.Name())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchCandidates() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestCandidatesFromSigImageRejectsTooManyLayers(t *testing.T) {
	repo, err := name.NewRepository("example.com/app")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}

	for _, tt := range []struct {
		name    string
		layers  int
		wantErr bool
	}{
		{name: "at limit", layers: testMaxSignatureLayers},
		{name: "over limit", layers: testMaxSignatureLayers + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			img := signatureImageWithLayers(t, []byte("ignored"), nil, tt.layers)
			_, gotErr := candidatesFromSigImage(img, digest, repo)
			want := fmt.Sprintf("signature manifest has %d layers; limit is %d", tt.layers, testMaxSignatureLayers)
			if tt.wantErr && (gotErr == nil || !strings.Contains(gotErr.Error(), want)) {
				t.Fatalf("candidatesFromSigImage() error = %v, want %q", gotErr, want)
			}
			if !tt.wantErr && gotErr != nil {
				t.Fatalf("candidatesFromSigImage() error = %v, want nil", gotErr)
			}
		})
	}
}

func TestCandidatesFromSigImageRejectsAlternateLayerURLsBeforeResolution(t *testing.T) {
	repo, err := name.NewRepository("example.com/app")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	payload := simpleSigningPayloadFor(t, repo.Name(), digest.String())
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(payload, types.MediaType(simpleSigningMediaType)),
		URLs:  []string{"https://attacker.example/payload"},
		Annotations: map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
		},
	})
	if err != nil {
		t.Fatalf("build signature image: %v", err)
	}
	recording := &recordingLayerImage{Image: img}

	_, err = candidatesFromSigImage(recording, digest, repo)
	want := "cosign signature payload layer uses alternate URLs"
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("candidatesFromSigImage() error = %v, want %q", err, want)
	}
	if recording.resolutions != 0 {
		t.Fatalf("LayerByDigest() calls = %d, want 0", recording.resolutions)
	}
}

func TestFetchCandidatesRejectsAggregateCandidateCount(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "candidate-cap")
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
	annotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}

	pushClassicSignatureImage(t, ref, subject.Digest, signatureImageWithLayers(t, payload, annotations, 9))
	pushReferrerImage(t, ref, *subject, cosignSigArtifactType, signatureImageWithLayers(t, payload, annotations, 8))

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("cosign verification candidates exceed %d limit", testMaxCandidates)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsAggregateAnnotationMaterialBeforeDecode(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "annotation-cap")
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
	largeButIndividuallySafe := strings.Repeat("A", 140<<10)
	annotations := map[string]string{cosignSignatureAnnotation: largeButIndividuallySafe}

	pushClassicSignatureImage(t, ref, subject.Digest, signatureImageWithLayers(t, payload, annotations, 1))
	pushReferrerImage(t, ref, *subject, cosignSigArtifactType, signatureImageWithLayers(t, payload, annotations, 1))

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("cosign annotation material exceeds %d byte limit", testMaxAnnotationBytes)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestCandidateBudgetCountsEveryRegistryAnnotationMap(t *testing.T) {
	chunk := strings.Repeat("a", maxAnnotationBytes/6)
	annotations := func(suffix string) map[string]string {
		return map[string]string{"annotation-" + suffix: chunk}
	}
	budget := &candidateBudget{}
	index := &v1.IndexManifest{
		Annotations: annotations("index"),
		Subject:     &v1.Descriptor{Annotations: annotations("index-subject")},
		Manifests:   []v1.Descriptor{{Annotations: annotations("referrer")}},
	}
	if err := budget.addIndexAnnotations(index); err != nil {
		t.Fatalf("addIndexAnnotations() error = %v, want nil below aggregate limit", err)
	}

	manifest := &v1.Manifest{
		Annotations: annotations("manifest"),
		Config:      v1.Descriptor{Annotations: annotations("config")},
		Subject:     &v1.Descriptor{Annotations: annotations("manifest-subject")},
		Layers:      []v1.Descriptor{{Annotations: annotations("layer")}},
	}
	err := budget.addManifestAnnotations(manifest)
	want := fmt.Sprintf("cosign annotation material exceeds %d byte limit", maxAnnotationBytes)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("addManifestAnnotations() error = %v, want %q", err, want)
	}
}

func TestCandidateBudgetRejectsOverflowFromEachAnnotationMap(t *testing.T) {
	overflow := map[string]string{"annotation": strings.Repeat("x", maxAnnotationBytes)}
	tests := []struct {
		name  string
		apply func(*candidateBudget) error
	}{
		{
			name: "index",
			apply: func(b *candidateBudget) error {
				return b.addIndexAnnotations(&v1.IndexManifest{Annotations: overflow})
			},
		},
		{
			name: "index subject",
			apply: func(b *candidateBudget) error {
				return b.addIndexAnnotations(&v1.IndexManifest{Subject: &v1.Descriptor{Annotations: overflow}})
			},
		},
		{
			name: "referrer descriptor",
			apply: func(b *candidateBudget) error {
				return b.addIndexAnnotations(&v1.IndexManifest{Manifests: []v1.Descriptor{{Annotations: overflow}}})
			},
		},
		{
			name: "manifest",
			apply: func(b *candidateBudget) error {
				return b.addManifestAnnotations(&v1.Manifest{Annotations: overflow})
			},
		},
		{
			name: "manifest config",
			apply: func(b *candidateBudget) error {
				return b.addManifestAnnotations(&v1.Manifest{Config: v1.Descriptor{Annotations: overflow}})
			},
		},
		{
			name: "manifest subject",
			apply: func(b *candidateBudget) error {
				return b.addManifestAnnotations(&v1.Manifest{Subject: &v1.Descriptor{Annotations: overflow}})
			},
		},
		{
			name: "manifest layer",
			apply: func(b *candidateBudget) error {
				return b.addManifestAnnotations(&v1.Manifest{Layers: []v1.Descriptor{{Annotations: overflow}}})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			budget := &candidateBudget{annotationBytes: 1}
			err := tt.apply(budget)
			if !errors.Is(err, errRegistryInputLimit) {
				t.Fatalf("annotation overflow error = %v, want errRegistryInputLimit", err)
			}
		})
	}
}

func TestMetadataLimitReadCloserBoundaryReads(t *testing.T) {
	r := &metadataLimitReadCloser{
		body:      io.NopCloser(strings.NewReader("ab")),
		remaining: 2,
	}
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll(exact limit): %v", err)
	}
	if string(got) != "ab" {
		t.Fatalf("ReadAll(exact limit) = %q, want ab", got)
	}
}

func TestCandidatesFromSigImageReportsBoundaryFailures(t *testing.T) {
	repo, err := name.NewRepository("example.com/app")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	payload := simpleSigningPayloadFor(t, repo.Name(), digest.String())
	annotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}
	baseImage := signatureImageWithLayers(t, payload, annotations, 1)

	t.Run("manifest read", func(t *testing.T) {
		wantErr := errors.New("manifest unavailable")
		_, gotErr := candidatesFromSigImage(manifestErrorImage{Image: baseImage, err: wantErr}, digest, repo)
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("candidatesFromSigImage() error = %v, want %v", gotErr, wantErr)
		}
	})

	t.Run("layer resolution", func(t *testing.T) {
		wantErr := errors.New("blob unavailable")
		_, gotErr := candidatesFromSigImage(layerResultImage{Image: baseImage, err: wantErr}, digest, repo)
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("candidatesFromSigImage() error = %v, want %v", gotErr, wantErr)
		}
	})

	t.Run("layer read", func(t *testing.T) {
		wantErr := errors.New("blob read failed")
		img := layerResultImage{
			Image: baseImage,
			layer: compressedErrorLayer{
				err: wantErr,
			},
		}
		_, gotErr := candidatesFromSigImage(img, digest, repo)
		if !errors.Is(gotErr, wantErr) {
			t.Fatalf("candidatesFromSigImage() error = %v, want %v", gotErr, wantErr)
		}
	})

	t.Run("signature encoding", func(t *testing.T) {
		img := signatureImageWithLayers(t, payload, map[string]string{
			cosignSignatureAnnotation: "%%%",
		}, 1)
		_, gotErr := candidatesFromSigImage(img, digest, repo)
		if gotErr == nil || !strings.Contains(gotErr.Error(), "decode signature") {
			t.Fatalf("candidatesFromSigImage() error = %v, want signature decode error", gotErr)
		}
	})

	t.Run("certificate encoding", func(t *testing.T) {
		img := signatureImageWithLayers(t, payload, map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
			cosignCertAnnotation:      "not a certificate",
		}, 1)
		_, gotErr := candidatesFromSigImage(img, digest, repo)
		if gotErr == nil || !strings.Contains(gotErr.Error(), "build bundle") {
			t.Fatalf("candidatesFromSigImage() error = %v, want bundle construction error", gotErr)
		}
	})

}

func TestCandidatesFromSigImageSkipsMalformedLayerForValidSibling(t *testing.T) {
	repo, err := name.NewRepository("example.com/app")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}
	digest := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	payload := simpleSigningPayloadFor(t, repo.Name(), digest.String())
	siblingPayload := append(append([]byte(nil), payload...), '\n')
	validAnnotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}
	tests := []struct {
		name             string
		firstAnnotations map[string]string
		wrap             func(v1.Image, v1.Hash) v1.Image
		wantDiagnostic   string
	}{
		{
			name:             "layer resolution",
			firstAnnotations: validAnnotations,
			wrap: func(img v1.Image, firstDigest v1.Hash) v1.Image {
				return selectedLayerResultImage{Image: img, digest: firstDigest, err: errors.New("blob unavailable")}
			},
			wantDiagnostic: "resolve blob",
		},
		{
			name:             "layer read",
			firstAnnotations: validAnnotations,
			wrap: func(img v1.Image, firstDigest v1.Hash) v1.Image {
				return selectedLayerResultImage{
					Image:  img,
					digest: firstDigest,
					layer:  compressedErrorLayer{err: errors.New("blob read failed")},
				}
			},
			wantDiagnostic: "read payload",
		},
		{
			name: "signature encoding",
			firstAnnotations: map[string]string{
				cosignSignatureAnnotation: "%%%",
			},
			wantDiagnostic: "decode signature",
		},
		{
			name: "certificate encoding",
			firstAnnotations: map[string]string{
				cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
				cosignCertAnnotation:      "not a certificate",
			},
			wantDiagnostic: "build bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, buildErr := mutate.Append(empty.Image,
				mutate.Addendum{
					Layer:       static.NewLayer(payload, types.MediaType(simpleSigningMediaType)),
					Annotations: tt.firstAnnotations,
				},
				mutate.Addendum{
					Layer:       static.NewLayer(siblingPayload, types.MediaType(simpleSigningMediaType)),
					Annotations: validAnnotations,
				},
			)
			if buildErr != nil {
				t.Fatalf("build signature image: %v", buildErr)
			}
			if tt.wrap != nil {
				manifest, manifestErr := img.Manifest()
				if manifestErr != nil {
					t.Fatalf("read signature manifest: %v", manifestErr)
				}
				img = tt.wrap(img, manifest.Layers[0].Digest)
			}

			candidates, gotErr := candidatesFromSigImage(img, digest, repo)
			if len(candidates) != 1 {
				t.Fatalf("candidatesFromSigImage() candidates = %d, want valid sibling", len(candidates))
			}
			if gotErr == nil || !strings.Contains(gotErr.Error(), tt.wantDiagnostic) {
				t.Fatalf("candidatesFromSigImage() error = %v, want first-layer diagnostic %q", gotErr, tt.wantDiagnostic)
			}
		})
	}
}

func TestFetchCandidatesReportsMalformedSignatureDiagnostics(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "malformed-signature")
	payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
	pushClassicSignatureImage(t, ref, subject.Digest, signatureImageWithLayers(t, payload, map[string]string{
		cosignSignatureAnnotation: "%%%",
	}, 1))
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := NewFetcher().FetchCandidates(context.Background(), logger, ref.Name())
	if !errors.Is(err, ErrNoSignatures) || !strings.Contains(err.Error(), "signature parsing failures") {
		t.Fatalf("FetchCandidates() error = %v, want ErrNoSignatures with parsing diagnostics", err)
	}
	logOutput := logs.String()
	for _, want := range []string{
		"skipping malformed cosign signature manifest",
		"image_ref=" + ref.Name(),
		"resolved_digest=" + subject.Digest.String(),
		"decode signature",
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("debug log = %q, want %q", logOutput, want)
		}
	}
}

func TestFetchCandidatesRejectsAggregatePayloadMaterial(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "payload-cap")
	invalidPayload := []byte(strings.Repeat("x", maxPayloadBytes))
	annotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}

	pushClassicSignatureImage(t, ref, subject.Digest, signatureImageWithLayers(t, invalidPayload, annotations, 9))
	pushReferrerImage(t, ref, *subject, cosignSigArtifactType, signatureImageWithLayers(t, invalidPayload, annotations, 8))

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("cosign signature payload material exceeds %d byte limit", testMaxAggregatePayload)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestReadLayerPayloadChargesBytesReturnedWithReadError(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), maxPayloadBytes)
	baseLayer := static.NewLayer(payload, types.MediaType(simpleSigningMediaType))
	budget := &candidateBudget{}
	shortLayer := terminalErrorLayer{Layer: baseLayer, payload: payload, err: io.ErrUnexpectedEOF}

	for i := 0; i < maxAggregatePayloadBytes/maxPayloadBytes; i++ {
		if _, err := readLayerPayloadWithBudget(shortLayer, budget); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short payload read %d error = %v, want io.ErrUnexpectedEOF", i+1, err)
		}
	}

	_, err := readLayerPayloadWithBudget(static.NewLayer([]byte("valid"), types.MediaType(simpleSigningMediaType)), budget)
	want := fmt.Sprintf("cosign signature payload material exceeds %d byte limit", maxAggregatePayloadBytes)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("read after repeated short payloads error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsOversizedPayloadDespiteValidSibling(t *testing.T) {
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "oversized-payload-sibling")
	annotations := map[string]string{
		cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("signature")),
	}
	validPayload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
	img, err := mutate.Append(empty.Image,
		mutate.Addendum{
			Layer:       static.NewLayer(validPayload, types.MediaType(simpleSigningMediaType)),
			Annotations: annotations,
		},
		mutate.Addendum{
			Layer:       static.NewLayer([]byte(strings.Repeat("x", maxPayloadBytes+1)), types.MediaType(simpleSigningMediaType)),
			Annotations: annotations,
		},
	)
	if err != nil {
		t.Fatalf("build signature image: %v", err)
	}
	pushClassicSignatureImage(t, ref, subject.Digest, img)

	_, err = NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("signature payload exceeds %d byte limit", maxPayloadBytes)
	if !errors.Is(err, errRegistryInputLimit) || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsOversizedRegistryMetadataResponse(t *testing.T) {
	baseRegistry := registry.New(registry.WithReferrersSupport(true))
	prefix := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"padding":"`)
	suffix := []byte(`"}}`)
	responseBytes := testMaxMetadataResponse + 1
	oversizedIndex := make([]byte, 0, responseBytes)
	oversizedIndex = append(oversizedIndex, prefix...)
	oversizedIndex = append(oversizedIndex, strings.Repeat("x", responseBytes-len(prefix)-len(suffix))...)
	oversizedIndex = append(oversizedIndex, suffix...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/") {
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			w.Header().Set("Content-Length", fmt.Sprint(len(oversizedIndex)))
			_, _ = w.Write(oversizedIndex)
			return
		}
		baseRegistry.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	hostURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	ref, _ := pushSubjectImage(t, hostURL.Host, "metadata-response-cap")

	customTransport := &countingTransport{base: remote.DefaultTransport}
	fetcher := NewFetcherWith(WithRegistryTransport(customTransport))
	_, err = fetcher.FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("registry metadata response exceeds %d byte limit", testMaxMetadataResponse)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
	if customTransport.calls == 0 {
		t.Fatal("custom registry transport was not used")
	}
}

func TestFetchCandidatesRejectsOversizedRedirectedRegistryMetadataResponse(t *testing.T) {
	baseRegistry := registry.New(registry.WithReferrersSupport(true))
	prefix := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"padding":"`)
	suffix := []byte(`"}}`)
	responseBytes := testMaxMetadataResponse + 1
	oversizedIndex := make([]byte, 0, responseBytes)
	oversizedIndex = append(oversizedIndex, prefix...)
	oversizedIndex = append(oversizedIndex, strings.Repeat("x", responseBytes-len(prefix)-len(suffix))...)
	oversizedIndex = append(oversizedIndex, suffix...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/"):
			http.Redirect(w, r, "/oversized-index", http.StatusTemporaryRedirect)
		case r.Method == http.MethodGet && r.URL.Path == "/oversized-index":
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			w.Header().Set("Content-Length", fmt.Sprint(len(oversizedIndex)))
			_, _ = w.Write(oversizedIndex)
		default:
			baseRegistry.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(server.Close)
	hostURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	ref, _ := pushSubjectImage(t, hostURL.Host, "redirected-metadata-response-cap")

	_, err = NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("registry metadata response exceeds %d byte limit", testMaxMetadataResponse)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsOversizedClassicSignatureManifestResponse(t *testing.T) {
	baseRegistry := registry.New(registry.WithReferrersSupport(true))
	prefix := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[],"annotations":{"padding":"`)
	suffix := []byte(`"}}`)
	responseBytes := testMaxMetadataResponse + 1
	oversizedManifest := make([]byte, 0, responseBytes)
	oversizedManifest = append(oversizedManifest, prefix...)
	oversizedManifest = append(oversizedManifest, strings.Repeat("x", responseBytes-len(prefix)-len(suffix))...)
	oversizedManifest = append(oversizedManifest, suffix...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".sig") {
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Content-Length", fmt.Sprint(len(oversizedManifest)))
			_, _ = w.Write(oversizedManifest)
			return
		}
		baseRegistry.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	hostURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	ref, _ := pushSubjectImage(t, hostURL.Host, "classic-response-cap")

	_, err = NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("registry metadata response exceeds %d byte limit", testMaxMetadataResponse)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesRejectsOversizedRedirectedClassicSignatureManifestResponse(t *testing.T) {
	baseRegistry := registry.New(registry.WithReferrersSupport(true))
	prefix := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[],"annotations":{"padding":"`)
	suffix := []byte(`"}}`)
	responseBytes := testMaxMetadataResponse + 1
	oversizedManifest := make([]byte, 0, responseBytes)
	oversizedManifest = append(oversizedManifest, prefix...)
	oversizedManifest = append(oversizedManifest, strings.Repeat("x", responseBytes-len(prefix)-len(suffix))...)
	oversizedManifest = append(oversizedManifest, suffix...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".sig"):
			http.Redirect(w, r, "/oversized-manifest", http.StatusTemporaryRedirect)
		case r.Method == http.MethodGet && r.URL.Path == "/oversized-manifest":
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Content-Length", fmt.Sprint(len(oversizedManifest)))
			_, _ = w.Write(oversizedManifest)
		default:
			baseRegistry.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(server.Close)
	hostURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	ref, _ := pushSubjectImage(t, hostURL.Host, "redirected-classic-response-cap")

	_, err = NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	want := fmt.Sprintf("registry metadata response exceeds %d byte limit", testMaxMetadataResponse)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("FetchCandidates() error = %v, want %q", err, want)
	}
}

func TestFetchCandidatesAllowsExactlyReferrerDescriptorLimit(t *testing.T) {
	// Covers the "len(im.Manifests) > maxReferrerDescriptors" boundary at
	// imagefetch.go:355: exactly the limit's worth of referrer descriptors
	// must not trip the input-limit rejection (only exceeding it may).
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "referrer-cap-exact")

	for i := 0; i < testMaxReferrerDescriptors; i++ {
		img := signatureImageWithLayers(t, []byte(fmt.Sprintf("unrelated-%d", i)), nil, 1)
		pushReferrerImage(t, ref, *subject, "application/vnd.example.unrelated", img)
	}

	_, err := NewFetcher().FetchCandidates(context.Background(), nil, ref.Name())
	if errors.Is(err, errRegistryInputLimit) {
		t.Fatalf("FetchCandidates() error = %v, want no input-limit error at exactly %d referrers", err, testMaxReferrerDescriptors)
	}
	if !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("FetchCandidates() error = %v, want ErrNoSignatures (no cosign-typed referrers were pushed)", err)
	}
}

// toggleErrContext lets a test flip ctx.Err() to context.Canceled on demand
// without closing Done(), so an httptest registry call already committed to
// the wire after the flip still completes instead of racing real
// cancellation plumbing. That keeps the test deterministic: no sleeps, no
// real network beyond httptest, and the SUT's own ctx.Err() checks are
// exercised directly.
type toggleErrContext struct {
	context.Context
	canceled bool
}

func (c *toggleErrContext) Err() error {
	if c.canceled {
		return context.Canceled
	}
	return c.Context.Err()
}

// referrerCancelTransport intercepts GET requests for the referrer
// manifests named in digests. The first one it sees fails and triggers
// cancel; every subsequent distinct digest it sees is recorded (also as a
// failure) so the test can assert whether discovery kept scanning past the
// first failure.
type referrerCancelTransport struct {
	base    http.RoundTripper
	digests []string
	cancel  func()
	seen    map[string]bool
	order   []string
}

func (t *referrerCancelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, d := range t.digests {
		if !strings.Contains(req.URL.Path, d) {
			continue
		}
		if t.seen == nil {
			t.seen = map[string]bool{}
		}
		first := len(t.order) == 0
		if !t.seen[d] {
			t.seen[d] = true
			t.order = append(t.order, d)
		}
		if first {
			t.cancel()
		}
		return nil, errors.New("synthetic referrer fetch failure")
	}
	return t.base.RoundTrip(req)
}

func TestFetchCandidatesStopsReferrerScanOnContextCancellation(t *testing.T) {
	// Covers the "ctxErr != nil" guard inside the referrers loop at
	// imagefetch.go:368: once ctx.Err() reports non-nil after a referrer
	// signature-image fetch fails, discovery must stop scanning the
	// remaining referrer descriptors rather than continuing the loop.
	host := testRegistry(t)
	ref, subject := pushSubjectImage(t, host, "referrer-ctx-cancel")

	payload := simpleSigningPayloadFor(t, ref.Context().Name(), subject.Digest.String())
	// Distinct annotation values so the two referrer images are genuinely
	// distinct manifests (and digests) in the registry, not the same
	// content pushed twice.
	annotationsFor := func(seq string) map[string]string {
		return map[string]string{
			cosignSignatureAnnotation: base64.StdEncoding.EncodeToString([]byte("sig")),
			"seq":                     seq,
		}
	}
	digestA := pushReferrerImage(t, ref, *subject, cosignSigArtifactType, signatureImageWithLayers(t, payload, annotationsFor("a"), 1))
	digestB := pushReferrerImage(t, ref, *subject, cosignSigArtifactType, signatureImageWithLayers(t, payload, annotationsFor("b"), 1))
	if digestA == digestB {
		t.Fatal("test setup bug: referrer images must have distinct digests")
	}

	spy := &referrerCancelTransport{base: remote.DefaultTransport, digests: []string{digestA.Hex, digestB.Hex}}
	toggleCtx := &toggleErrContext{Context: context.Background()}
	spy.cancel = func() { toggleCtx.canceled = true }

	fetcher := NewFetcherWith(WithRegistryTransport(spy))
	_, err := fetcher.FetchCandidates(toggleCtx, nil, ref.Name())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchCandidates() error = %v, want context.Canceled", err)
	}
	if len(spy.order) != 1 {
		t.Fatalf("distinct referrer descriptors contacted = %v, want exactly 1: discovery must stop once ctx.Err() is non-nil", spy.order)
	}
}

func TestCandidateBudgetAddAnnotationMapAllowsExactlyAtLimit(t *testing.T) {
	// Covers the "materialBytes > maxAnnotationBytes-b.annotationBytes"
	// boundary at imagefetch.go:401: material that exactly fills the
	// remaining budget must be accepted, not rejected.
	const key = "k"
	budget := &candidateBudget{}
	exact := strings.Repeat("a", maxAnnotationBytes-len(key))
	if err := budget.addAnnotationMap(map[string]string{key: exact}); err != nil {
		t.Fatalf("addAnnotationMap() error = %v, want nil for material exactly at the limit", err)
	}
	if budget.annotationBytes != maxAnnotationBytes {
		t.Fatalf("annotationBytes = %d, want %d", budget.annotationBytes, maxAnnotationBytes)
	}

	over := &candidateBudget{}
	oneOver := strings.Repeat("a", maxAnnotationBytes-len(key)+1)
	if err := over.addAnnotationMap(map[string]string{key: oneOver}); !errors.Is(err, errRegistryInputLimit) {
		t.Fatalf("addAnnotationMap() error = %v, want errRegistryInputLimit for material one byte over the limit", err)
	}
}

func TestReadLayerPayloadWithBudgetAllowsEmptyPayloadAtExhaustedAggregateBudget(t *testing.T) {
	// Covers the "remaining < 0" boundary at imagefetch.go:547: remaining
	// == 0 (budget exactly exhausted, not negative) must still allow
	// reading an empty layer, since nothing has actually gone over budget.
	budget := &candidateBudget{payloadBytes: int64(maxAggregatePayloadBytes)}
	layer := static.NewLayer(nil, types.MediaType(simpleSigningMediaType))

	payload, err := readLayerPayloadWithBudget(layer, budget)
	if err != nil {
		t.Fatalf("readLayerPayloadWithBudget() error = %v, want nil for an empty layer at exactly the exhausted aggregate budget", err)
	}
	if len(payload) != 0 {
		t.Fatalf("payload = %q, want empty", payload)
	}
}

func TestReadLayerPayloadWithBudgetClampsReadLimitToRemainingAggregateBudget(t *testing.T) {
	// Covers the "remaining < readLimit" guard at imagefetch.go:551: when
	// the aggregate budget remaining is smaller than the per-layer cap
	// (maxPayloadBytes), the per-layer read must be clamped to the smaller
	// remaining amount. An unclamped read of oversized content trips the
	// per-layer maxPayloadBytes message instead of the aggregate-budget
	// message, so the two are distinguishable by error text.
	const remaining = 500 * 1024 // well below maxPayloadBytes (1 MiB)
	budget := &candidateBudget{payloadBytes: int64(maxAggregatePayloadBytes - remaining)}

	oversizedContent := bytes.Repeat([]byte("x"), maxPayloadBytes+1024)
	layer := static.NewLayer(oversizedContent, types.MediaType(simpleSigningMediaType))

	_, err := readLayerPayloadWithBudget(layer, budget)
	if !errors.Is(err, errRegistryInputLimit) {
		t.Fatalf("readLayerPayloadWithBudget() error = %v, want errRegistryInputLimit", err)
	}
	want := fmt.Sprintf("cosign signature payload material exceeds %d byte limit", maxAggregatePayloadBytes)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("readLayerPayloadWithBudget() error = %v, want the clamped aggregate-budget message %q", err, want)
	}
	if strings.Contains(err.Error(), "signature payload exceeds") {
		t.Fatalf("readLayerPayloadWithBudget() error = %v, want the aggregate message, not the unclamped per-layer message", err)
	}
}
