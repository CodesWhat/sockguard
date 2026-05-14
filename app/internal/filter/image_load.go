package filter

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const maxImageLoadBodyBytes = 512 << 20   // 512 MiB
const maxImageLoadManifestBytes = 1 << 20 // 1 MiB

// ImageLoadOptions configures request-body inspection for POST /images/load.
type ImageLoadOptions struct {
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
	AllowUntagged      bool
}

type imageLoadPolicy struct {
	allowUntagged bool
	imagePolicy   imagePullPolicy
	io            ioDeps
}

func newImageLoadPolicy(opts ImageLoadOptions) imageLoadPolicy {
	return imageLoadPolicy{
		allowUntagged: opts.AllowUntagged,
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
		if spool != nil {
			spool.closeAndRemove()
		}
		return "", nil
	}

	tags, foundManifest, err := p.io.extractImageLoadRepoTags(spool.file)
	if err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("inspect image load manifest: %w", err)
	}
	if !foundManifest {
		if !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: image manifest is not inspectable", nil
		}
	} else {
		if len(tags) == 0 && !p.allowUntagged {
			spool.closeAndRemove()
			return "image load denied: untagged images are not allowed", nil
		}
		for _, tag := range tags {
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

func (io_ ioDeps) extractImageLoadRepoTags(reader io.Reader) ([]string, bool, error) {
	tr := tar.NewReader(reader)
	var tags []string
	found := false

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return tags, found, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("read tar entry: %w", err)
		}
		if header.Typeflag != tar.TypeReg || normalizeImageLoadArchivePath(header.Name) != "manifest.json" {
			continue
		}

		body, err := io_.ReadAllLimited(tr, maxImageLoadManifestBytes+1)
		if err != nil {
			return nil, false, fmt.Errorf("read manifest.json: %w", err)
		}
		if len(body) > maxImageLoadManifestBytes {
			return nil, false, fmt.Errorf("manifest.json exceeds %d byte limit", maxImageLoadManifestBytes)
		}

		var manifest []imageLoadManifestEntry
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, false, fmt.Errorf("decode manifest.json: %w", err)
		}
		found = true
		for _, entry := range manifest {
			tags = append(tags, entry.RepoTags...)
		}
	}
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
