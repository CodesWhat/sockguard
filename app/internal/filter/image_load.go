package filter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
)

const maxImageLoadBodyBytes = 512 << 20       // 512 MiB
const maxImageLoadManifestBytes = 1 << 20     // 1 MiB
const maxImageLoadDecompressedBytes = 2 << 30 // 2 GiB (gzip-bomb guard)
const maxImageLoadOCITrackedBlobs = 4096
const maxImageLoadOCIMetadataBytes = 16 << 20 // 16 MiB

// errImageLoadDecompressedTooLarge is the loud sentinel returned when a
// gzip-compressed image archive expands past maxImageLoadDecompressedBytes.
var errImageLoadDecompressedTooLarge = errors.New("decompressed image archive exceeds byte limit")

// ImageLoadOptions configures request-body inspection for POST /images/load
// and its libpod counterpart POST /libpod/images/load.
type ImageLoadOptions struct {
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
	AllowUntagged      bool
	// AllowBlindWrites wires the top-level insecure_allow_body_blind_writes
	// acknowledgment, which is the only thing that admits
	// POST /libpod/local/images/load — the archive-by-daemon-host-path
	// variant this policy cannot read. It is not part of a request_body
	// block; internal/cmd/serve.go's attachRuntimeInspectors sets it, the
	// same way it does for BuildOptions and ExecOptions.
	AllowBlindWrites bool
}

type imageLoadPolicy struct {
	allowUntagged    bool
	allowBlindWrites bool
	imagePolicy      imagePullPolicy
	io               ioDeps
}

func newImageLoadPolicy(opts ImageLoadOptions) imageLoadPolicy {
	return imageLoadPolicy{
		allowUntagged:    opts.AllowUntagged,
		allowBlindWrites: opts.AllowBlindWrites,
		imagePolicy: newImagePullPolicy(ImagePullOptions{
			AllowAllRegistries: opts.AllowAllRegistries,
			AllowOfficial:      opts.AllowOfficial,
			AllowedRegistries:  opts.AllowedRegistries,
		}),
		io: defaultIODeps(),
	}
}

func (p imageLoadPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesImageLoadInspection(normalizedPath) {
		return "", nil
	}
	// POST /libpod/local/images/load carries no archive: it names one by
	// absolute path on the daemon host and Podman opens it server-side, so
	// the RepoTags check below has nothing to read and the registry
	// allowlist cannot be applied at all. Deny it under the blind-write
	// acknowledgment rather than letting the empty body fall through to
	// this function's size==0 allow.
	if isLibpodLocalImageLoadPath(normalizedPath) {
		if !p.allowBlindWrites {
			return "image load denied: Podman local image load reads a daemon-host path and requires insecure_allow_body_blind_writes", nil
		}
		return "", nil
	}
	if !p.allowsAnyImageLoad() {
		return "image load denied: loading image archives is not allowed", nil
	}
	if r.Body == nil {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	spool, size, err := p.io.spoolRequestBodyForInspection(r, "sockguard-image-load-", maxImageLoadBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("image load denied: request body exceeds %d byte limit", maxImageLoadBodyBytes))
		}
		return "", err
	}
	if spool == nil || size == 0 {
		// closeAndRemove is nil-safe; this avoids a per-path nil check and
		// eliminates an equivalent mutation point in the inspect hot path.
		spool.closeAndRemove()
		return "", nil
	}

	archive, err := p.io.extractImageLoadArchive(spool.file, isLibpodImageLoadPath(normalizedPath))
	if err != nil {
		spool.closeAndRemove()
		if errors.Is(err, errImageLoadDecompressedTooLarge) {
			return fmt.Sprintf("image load denied: decompressed image archive exceeds %d byte limit", maxImageLoadDecompressedBytes), nil
		}
		return "", fmt.Errorf("inspect image load manifest: %w", err)
	}
	if archive.format == imageLoadArchiveUnknown {
		if !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: image manifest is not inspectable", nil
		}
	} else {
		if archive.hasUntagged && !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: untagged images are not allowed", nil
		}
		for _, tag := range archive.references {
			if isLibpodImageLoadPath(normalizedPath) {
				tag = normalizeLibpodImageLoadReference(tag)
			}
			if denyReason := p.denyReasonForTag(tag); denyReason != "" {
				spool.closeAndRemove()
				return denyReason, nil
			}
		}
	}

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind image load body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func (p imageLoadPolicy) allowsAnyImageLoad() bool {
	return p.allowUntagged || p.imagePolicy.allowAllRegistries || p.imagePolicy.allowOfficial || len(p.imagePolicy.allowedRegistries) > 0
}

func (p imageLoadPolicy) denyReasonForTag(tag string) string {
	trimmed := strings.TrimSpace(tag)
	if trimmed == "" || trimmed == "<none>:<none>" {
		if p.allowUntagged {
			return ""
		}
		return "image load denied: untagged images are not allowed"
	}
	if _, ok := parseImageReference(trimmed); !ok {
		return fmt.Sprintf("image load denied: image reference %q could not be inspected", trimmed)
	}
	return p.imagePolicy.denyReasonForReference(trimmed, "image load")
}

type imageLoadManifestEntry struct {
	RepoTags []string `json:"RepoTags"`
}

type imageLoadArchiveFormat uint8

const (
	imageLoadArchiveUnknown imageLoadArchiveFormat = iota
	imageLoadArchiveDocker
	imageLoadArchiveOCI
)

const ociImageRefNameAnnotation = "org.opencontainers.image.ref.name"
const containerdImageNameAnnotation = "io.containerd.image.name"

type imageLoadArchiveInspection struct {
	format      imageLoadArchiveFormat
	references  []string
	hasUntagged bool
}

type imageLoadOCIIndex struct {
	SchemaVersion int                           `json:"schemaVersion"`
	Manifests     []imageLoadOCIIndexDescriptor `json:"manifests"`
}

type imageLoadOCIIndexDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

type imageLoadOCIManifest struct {
	SchemaVersion int                           `json:"schemaVersion"`
	Config        imageLoadOCIIndexDescriptor   `json:"config"`
	Layers        []imageLoadOCIIndexDescriptor `json:"layers"`
}

type imageLoadOCILayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type imageLoadArchiveControlFiles struct {
	dockerManifest []byte
	ociIndex       []byte
	ociLayout      []byte
	seenDocker     bool
	seenOCIIndex   bool
	seenOCILayout  bool
	ociBlobs       map[string]imageLoadOCIBlob
	ociMetadata    int64
	ociBlobErr     error
}

type imageLoadOCIBlob struct {
	size        int64
	digestMatch bool
	body        []byte
}

// extractImageLoadArchive classifies and reads policy-relevant references
// from Docker and OCI archives. Docker's /images/load accepts both a raw tar
// and a gzip-compressed tar, so probe gzip first and fall back to a plain tar
// walk only when the body is not gzip-compressed.
func (io_ ioDeps) extractImageLoadArchive(file *os.File, preferOCI bool) (imageLoadArchiveInspection, error) {
	if archive, compressed, err := io_.extractImageLoadArchiveFromGzip(file, preferOCI); compressed || err != nil {
		return archive, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("rewind image load body: %w", err)
	}
	return io_.extractImageLoadArchiveFromTar(tar.NewReader(file), preferOCI)
}

// extractImageLoadArchiveFromGzip decompresses a gzip-wrapped tar through a
// loud, decompressed-byte-bounded reader (gzip-bomb guard) and walks its
// format control files. A non-gzip header returns compressed=false so the
// caller rewinds and reads the body as a plain tar.
func (io_ ioDeps) extractImageLoadArchiveFromGzip(file *os.File, preferOCI bool) (imageLoadArchiveInspection, bool, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return imageLoadArchiveInspection{}, false, nil
		}
		return imageLoadArchiveInspection{}, false, fmt.Errorf("create gzip reader: %w", err)
	}

	limited := &limitedReader{r: gzr, remaining: maxImageLoadDecompressedBytes, tooLarge: errImageLoadDecompressedTooLarge}
	archive, err := io_.extractImageLoadArchiveFromTar(tar.NewReader(limited), preferOCI)
	if err == nil {
		if drainErr := io_.DrainReader(limited); drainErr != nil {
			err = fmt.Errorf("drain gzip stream: %w", drainErr)
		}
	}
	if closeErr := io_.CloseReadCloser(gzr); err == nil && closeErr != nil {
		err = fmt.Errorf("close gzip reader: %w", closeErr)
	}
	if errors.Is(err, errImageLoadDecompressedTooLarge) {
		// Surface the sentinel unwrapped so inspect maps it to a clean 403 deny
		// rather than a 500.
		return imageLoadArchiveInspection{}, true, errImageLoadDecompressedTooLarge
	}
	return archive, true, err
}

func (io_ ioDeps) extractImageLoadArchiveFromTar(tr *tar.Reader, preferOCI bool) (imageLoadArchiveInspection, error) {
	var controls imageLoadArchiveControlFiles

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return parseImageLoadArchiveControlFiles(controls, preferOCI)
		}
		if err != nil {
			return imageLoadArchiveInspection{}, fmt.Errorf("read tar entry: %w", err)
		}

		name := normalizeImageLoadArchivePath(header.Name)
		if strings.HasPrefix(name, "blobs/sha256/") {
			if controls.ociBlobErr == nil {
				controls.ociBlobErr = io_.recordImageLoadOCIBlob(&controls, name, header, tr)
			}
			continue
		}
		if name != "manifest.json" && name != "index.json" && name != "oci-layout" {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return imageLoadArchiveInspection{}, fmt.Errorf("image archive control file %s is not a regular file", name)
		}

		body, err := io_.ReadAllLimited(tr, maxImageLoadManifestBytes+1)
		if err != nil {
			return imageLoadArchiveInspection{}, fmt.Errorf("read %s: %w", name, err)
		}
		if len(body) > maxImageLoadManifestBytes {
			return imageLoadArchiveInspection{}, fmt.Errorf("%s exceeds %d byte limit", name, maxImageLoadManifestBytes)
		}

		switch name {
		case "manifest.json":
			if controls.seenDocker {
				return imageLoadArchiveInspection{}, errors.New("image archive contains duplicate manifest.json control files")
			}
			controls.seenDocker = true
			controls.dockerManifest = body
		case "index.json":
			if controls.seenOCIIndex {
				return imageLoadArchiveInspection{}, errors.New("image archive contains duplicate index.json control files")
			}
			controls.seenOCIIndex = true
			controls.ociIndex = body
		case "oci-layout":
			if controls.seenOCILayout {
				return imageLoadArchiveInspection{}, errors.New("image archive contains duplicate oci-layout control files")
			}
			controls.seenOCILayout = true
			controls.ociLayout = body
		}
	}
}

func (io_ ioDeps) recordImageLoadOCIBlob(controls *imageLoadArchiveControlFiles, name string, header *tar.Header, reader io.Reader) error {
	if header.Typeflag != tar.TypeReg {
		return fmt.Errorf("OCI image archive blob %s is not a regular file", name)
	}
	if controls.ociBlobs == nil {
		controls.ociBlobs = make(map[string]imageLoadOCIBlob)
	}
	if _, exists := controls.ociBlobs[name]; exists {
		return fmt.Errorf("OCI image archive contains duplicate blob path %s", name)
	}
	if len(controls.ociBlobs) >= maxImageLoadOCITrackedBlobs {
		return fmt.Errorf("OCI image archive exceeds %d tracked blob limit", maxImageLoadOCITrackedBlobs)
	}

	hasher := sha256.New()
	var body bytes.Buffer
	writer := io.Writer(hasher)
	retainBody := header.Size >= 0 && header.Size <= maxImageLoadManifestBytes && controls.ociMetadata+header.Size <= maxImageLoadOCIMetadataBytes
	if retainBody {
		writer = io.MultiWriter(hasher, &body)
	}
	size, err := io.Copy(writer, reader)
	if err != nil {
		return fmt.Errorf("read OCI image archive blob %s: %w", name, err)
	}
	digestHex := strings.TrimPrefix(name, "blobs/sha256/")
	blob := imageLoadOCIBlob{
		size:        size,
		digestMatch: len(digestHex) == sha256.Size*2 && fmt.Sprintf("%x", hasher.Sum(nil)) == digestHex,
	}
	if retainBody {
		blob.body = body.Bytes()
		controls.ociMetadata += int64(len(blob.body))
	}
	controls.ociBlobs[name] = blob
	return nil
}

func parseImageLoadArchiveControlFiles(controls imageLoadArchiveControlFiles, preferOCI bool) (imageLoadArchiveInspection, error) {
	hasOCIControl := controls.seenOCIIndex || controls.seenOCILayout
	if !hasOCIControl {
		if controls.seenDocker {
			return parseDockerImageLoadManifest(controls.dockerManifest)
		}
		return imageLoadArchiveInspection{format: imageLoadArchiveUnknown}, nil
	}

	// Podman's native load tries OCI archive before Docker archive. Docker's
	// compatibility endpoint retains Docker-manifest precedence. A mixed
	// archive is therefore not inherently ambiguous: inspect the format the
	// selected daemon route will actually load, and use the other format only
	// when the preferred control metadata is invalid.
	if preferOCI {
		archive, ociErr := parseOCIImageLoadManifest(controls)
		if ociErr == nil {
			return archive, nil
		}
		if controls.seenDocker {
			if dockerArchive, dockerErr := parseDockerImageLoadManifest(controls.dockerManifest); dockerErr == nil {
				return dockerArchive, nil
			} else {
				return imageLoadArchiveInspection{}, fmt.Errorf("OCI archive invalid (%w) and Docker archive invalid: %w", ociErr, dockerErr)
			}
		}
		return imageLoadArchiveInspection{}, ociErr
	}
	if controls.seenDocker {
		return parseDockerImageLoadManifest(controls.dockerManifest)
	}
	return parseOCIImageLoadManifest(controls)
}

func parseDockerImageLoadManifest(body []byte) (imageLoadArchiveInspection, error) {
	var manifest []imageLoadManifestEntry
	if err := json.Unmarshal(body, &manifest); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode manifest.json: %w", err)
	}

	archive := imageLoadArchiveInspection{format: imageLoadArchiveDocker}
	for _, entry := range manifest {
		if len(entry.RepoTags) == 0 {
			archive.hasUntagged = true
		}
		archive.references = append(archive.references, entry.RepoTags...)
	}
	if len(manifest) == 0 {
		archive.hasUntagged = true
	}
	return archive, nil
}

func parseOCIImageLoadManifest(controls imageLoadArchiveControlFiles) (imageLoadArchiveInspection, error) {
	if controls.ociBlobErr != nil {
		return imageLoadArchiveInspection{}, controls.ociBlobErr
	}
	if !controls.seenOCIIndex || !controls.seenOCILayout {
		return imageLoadArchiveInspection{}, errors.New("malformed OCI image archive requires both index.json and oci-layout")
	}

	var layout imageLoadOCILayout
	if err := json.Unmarshal(controls.ociLayout, &layout); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode oci-layout: %w", err)
	}
	if layout.ImageLayoutVersion != "1.0.0" {
		return imageLoadArchiveInspection{}, fmt.Errorf("unsupported OCI image layout version %q", layout.ImageLayoutVersion)
	}

	var rawIndex map[string]json.RawMessage
	if err := json.Unmarshal(controls.ociIndex, &rawIndex); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode index.json: %w", err)
	}
	if _, ok := rawIndex["manifests"]; !ok || string(rawIndex["manifests"]) == "null" {
		return imageLoadArchiveInspection{}, errors.New("decode index.json: manifests must be an array")
	}
	var index imageLoadOCIIndex
	if err := json.Unmarshal(controls.ociIndex, &index); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode index.json: %w", err)
	}
	if index.SchemaVersion != 2 {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode index.json: unsupported schemaVersion %d", index.SchemaVersion)
	}
	if len(index.Manifests) != 1 {
		return imageLoadArchiveInspection{}, fmt.Errorf("decode index.json: Podman requires exactly one image when no OCI reference is selected, got %d", len(index.Manifests))
	}
	if err := validateImageLoadOCIManifestGraph(index.Manifests[0], controls.ociBlobs); err != nil {
		return imageLoadArchiveInspection{}, err
	}

	archive := imageLoadArchiveInspection{format: imageLoadArchiveOCI}
	for _, descriptor := range index.Manifests {
		// Podman names an OCI-archive load from the containerd annotation
		// first and only falls back to the OCI ref-name annotation when it is
		// absent. The policy must inspect that same effective name or a second,
		// lower-priority annotation can disguise the registry Podman records.
		reference := descriptor.Annotations[containerdImageNameAnnotation]
		if reference == "" {
			reference = descriptor.Annotations[ociImageRefNameAnnotation]
		}
		reference = strings.TrimSpace(reference)
		if reference == "" {
			archive.hasUntagged = true
			continue
		}
		archive.references = append(archive.references, reference)
	}
	if len(index.Manifests) == 0 {
		archive.hasUntagged = true
	}
	return archive, nil
}

func validateImageLoadOCIManifestGraph(descriptor imageLoadOCIIndexDescriptor, blobs map[string]imageLoadOCIBlob) error {
	const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	const ociIndexMediaType = "application/vnd.oci.image.index.v1+json"
	const dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	const dockerIndexMediaType = "application/vnd.docker.distribution.manifest.list.v2+json"
	return validateImageLoadOCIDescriptor(descriptor, blobs, map[string]struct{}{}, 0, ociManifestMediaType, ociIndexMediaType, dockerManifestMediaType, dockerIndexMediaType)
}

func validateImageLoadOCIDescriptor(descriptor imageLoadOCIIndexDescriptor, blobs map[string]imageLoadOCIBlob, ancestors map[string]struct{}, depth int, ociManifestMediaType, ociIndexMediaType, dockerManifestMediaType, dockerIndexMediaType string) error {
	if depth > 16 {
		return errors.New("OCI archive manifest graph exceeds 16 levels")
	}
	if _, exists := ancestors[descriptor.Digest]; exists {
		return fmt.Errorf("OCI archive manifest graph contains a cycle at %q", descriptor.Digest)
	}
	ancestors[descriptor.Digest] = struct{}{}
	defer delete(ancestors, descriptor.Digest)

	switch descriptor.MediaType {
	case ociIndexMediaType, dockerIndexMediaType:
		body, err := validatedImageLoadOCIBlob(descriptor, blobs, true)
		if err != nil {
			return fmt.Errorf("validate OCI image index: %w", err)
		}
		var index imageLoadOCIIndex
		if err := json.Unmarshal(body, &index); err != nil {
			return fmt.Errorf("decode OCI image index: %w", err)
		}
		if index.SchemaVersion != 2 || len(index.Manifests) == 0 {
			return fmt.Errorf("decode OCI image index: schemaVersion=%d manifests=%d", index.SchemaVersion, len(index.Manifests))
		}
		for i, child := range index.Manifests {
			if err := validateImageLoadOCIDescriptor(child, blobs, ancestors, depth+1, ociManifestMediaType, ociIndexMediaType, dockerManifestMediaType, dockerIndexMediaType); err != nil {
				return fmt.Errorf("validate OCI image index member %d: %w", i, err)
			}
		}
		return nil
	case ociManifestMediaType, dockerManifestMediaType:
		// Continue below with the image-manifest-specific graph.
	default:
		return fmt.Errorf("OCI archive top-level mediaType %q is not a supported image manifest", descriptor.MediaType)
	}
	body, err := validatedImageLoadOCIBlob(descriptor, blobs, true)
	if err != nil {
		return fmt.Errorf("validate OCI image manifest: %w", err)
	}

	var manifest imageLoadOCIManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("decode OCI image manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 {
		return fmt.Errorf("decode OCI image manifest: unsupported schemaVersion %d", manifest.SchemaVersion)
	}
	if _, err := validatedImageLoadOCIBlob(manifest.Config, blobs, false); err != nil {
		return fmt.Errorf("validate OCI image config: %w", err)
	}
	for i, layer := range manifest.Layers {
		if _, err := validatedImageLoadOCIBlob(layer, blobs, false); err != nil {
			return fmt.Errorf("validate OCI image layer %d: %w", i, err)
		}
	}
	return nil
}

func validatedImageLoadOCIBlob(descriptor imageLoadOCIIndexDescriptor, blobs map[string]imageLoadOCIBlob, requireBody bool) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(descriptor.Digest, prefix) || len(descriptor.Digest) != len(prefix)+sha256.Size*2 {
		return nil, fmt.Errorf("unsupported or malformed digest %q", descriptor.Digest)
	}
	blob, ok := blobs["blobs/sha256/"+strings.TrimPrefix(descriptor.Digest, prefix)]
	if !ok {
		return nil, fmt.Errorf("referenced blob %q is missing", descriptor.Digest)
	}
	if !blob.digestMatch {
		return nil, fmt.Errorf("referenced blob %q does not match its digest", descriptor.Digest)
	}
	if descriptor.Size < 0 || blob.size != descriptor.Size {
		return nil, fmt.Errorf("referenced blob %q has size %d, want %d", descriptor.Digest, blob.size, descriptor.Size)
	}
	if requireBody && blob.body == nil {
		return nil, fmt.Errorf("referenced manifest %q exceeds the inspectable metadata limit", descriptor.Digest)
	}
	return blob.body, nil
}

// This compatibility helper keeps the focused parser tests and mutation tests
// expressed in terms of Docker manifest RepoTags while production uses the
// format-aware archive result above.
func (io_ ioDeps) extractImageLoadRepoTagsFromTar(tr *tar.Reader) ([]string, bool, error) {
	archive, err := io_.extractImageLoadArchiveFromTar(tr, false)
	return archive.references, archive.format == imageLoadArchiveDocker, err
}

func normalizeLibpodImageLoadReference(value string) string {
	reference := strings.TrimSpace(value)
	first, _, hasSlash := strings.Cut(reference, "/")
	if !hasSlash || !looksLikeRegistryComponent(first) {
		return "localhost/" + reference
	}
	return reference
}

func normalizeImageLoadArchivePath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	// Podman's OCI archive extraction runs filepath.Clean over every tar
	// header before writing it. Use slash-path Clean here because tar names
	// are slash-separated on every platform, so spellings such as
	// ./index.json and metadata/../index.json collide exactly as they do in
	// the daemon instead of letting a later control file replace the one we
	// inspected.
	cleaned := strings.TrimPrefix(path.Clean(trimmed), "/")
	if cleaned == "" || cleaned == "." {
		return ""
	}
	return cleaned
}
