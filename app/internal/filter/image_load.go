package filter

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

const maxImageLoadBodyBytes = 512 << 20       // 512 MiB
const maxImageLoadManifestBytes = 1 << 20     // 1 MiB
const maxImageLoadDecompressedBytes = 2 << 30 // 2 GiB (gzip-bomb guard)

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

	archive, err := p.io.extractImageLoadArchive(spool.file)
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
	Annotations map[string]string `json:"annotations"`
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
}

// extractImageLoadArchive classifies and reads policy-relevant references
// from Docker and OCI archives. Docker's /images/load accepts both a raw tar
// and a gzip-compressed tar, so probe gzip first and fall back to a plain tar
// walk only when the body is not gzip-compressed.
func (io_ ioDeps) extractImageLoadArchive(file *os.File) (imageLoadArchiveInspection, error) {
	if archive, compressed, err := io_.extractImageLoadArchiveFromGzip(file); compressed || err != nil {
		return archive, err
	}
	if err := io_.SeekToStart(file); err != nil {
		return imageLoadArchiveInspection{}, fmt.Errorf("rewind image load body: %w", err)
	}
	return io_.extractImageLoadArchiveFromTar(tar.NewReader(file))
}

// extractImageLoadArchiveFromGzip decompresses a gzip-wrapped tar through a
// loud, decompressed-byte-bounded reader (gzip-bomb guard) and walks its
// format control files. A non-gzip header returns compressed=false so the
// caller rewinds and reads the body as a plain tar.
func (io_ ioDeps) extractImageLoadArchiveFromGzip(file *os.File) (imageLoadArchiveInspection, bool, error) {
	gzr, err := gzip.NewReader(file)
	if err != nil {
		if errors.Is(err, gzip.ErrHeader) {
			return imageLoadArchiveInspection{}, false, nil
		}
		return imageLoadArchiveInspection{}, false, fmt.Errorf("create gzip reader: %w", err)
	}

	limited := &limitedReader{r: gzr, remaining: maxImageLoadDecompressedBytes, tooLarge: errImageLoadDecompressedTooLarge}
	archive, err := io_.extractImageLoadArchiveFromTar(tar.NewReader(limited))
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

func (io_ ioDeps) extractImageLoadArchiveFromTar(tr *tar.Reader) (imageLoadArchiveInspection, error) {
	var controls imageLoadArchiveControlFiles

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return parseImageLoadArchiveControlFiles(controls)
		}
		if err != nil {
			return imageLoadArchiveInspection{}, fmt.Errorf("read tar entry: %w", err)
		}

		name := normalizeImageLoadArchivePath(header.Name)
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

func parseImageLoadArchiveControlFiles(controls imageLoadArchiveControlFiles) (imageLoadArchiveInspection, error) {
	hasOCIControl := controls.seenOCIIndex || controls.seenOCILayout
	if controls.seenDocker && hasOCIControl {
		return imageLoadArchiveInspection{}, errors.New("ambiguous image archive contains both Docker and OCI control files")
	}
	if controls.seenDocker {
		var manifest []imageLoadManifestEntry
		if err := json.Unmarshal(controls.dockerManifest, &manifest); err != nil {
			return imageLoadArchiveInspection{}, fmt.Errorf("decode manifest.json: %w", err)
		}

		archive := imageLoadArchiveInspection{format: imageLoadArchiveDocker}
		for _, entry := range manifest {
			archive.references = append(archive.references, entry.RepoTags...)
		}
		archive.hasUntagged = len(archive.references) == 0
		return archive, nil
	}
	if !hasOCIControl {
		return imageLoadArchiveInspection{format: imageLoadArchiveUnknown}, nil
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

	archive := imageLoadArchiveInspection{format: imageLoadArchiveOCI}
	for _, descriptor := range index.Manifests {
		reference := strings.TrimSpace(descriptor.Annotations[ociImageRefNameAnnotation])
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

// This compatibility helper keeps the focused parser tests and mutation tests
// expressed in terms of Docker manifest RepoTags while production uses the
// format-aware archive result above.
func (io_ ioDeps) extractImageLoadRepoTagsFromTar(tr *tar.Reader) ([]string, bool, error) {
	archive, err := io_.extractImageLoadArchiveFromTar(tr)
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
	cleaned := strings.TrimPrefix(trimmed, "/")
	if cleaned == "" {
		return ""
	}
	return cleaned
}
