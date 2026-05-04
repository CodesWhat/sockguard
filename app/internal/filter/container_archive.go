package filter

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

const maxContainerArchiveBodyBytes = 512 << 20 // 512 MiB

// ContainerArchiveOptions configures request-body/query inspection for
// PUT /containers/{id}/archive.
type ContainerArchiveOptions struct {
	AllowedPaths       []string
	AllowSetID         bool
	AllowDeviceNodes   bool
	AllowEscapingLinks bool
}

type containerArchivePolicy struct {
	allowedPaths       []string
	allowSetID         bool
	allowDeviceNodes   bool
	allowEscapingLinks bool
}

func newContainerArchivePolicy(opts ContainerArchiveOptions) containerArchivePolicy {
	return containerArchivePolicy{
		allowedPaths:       normalizeContainerArchiveAllowedPaths(opts.AllowedPaths),
		allowSetID:         opts.AllowSetID,
		allowDeviceNodes:   opts.AllowDeviceNodes,
		allowEscapingLinks: opts.AllowEscapingLinks,
	}
}

func (p containerArchivePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesContainerArchiveInspection(r, normalizedPath) || r.Body == nil {
		return "", nil
	}

	targetPath, ok := normalizeContainerArchiveTargetPath(r.URL.Query().Get("path"))
	if !ok {
		return "container archive denied: target path must stay within the container path", nil
	}
	if !p.targetPathAllowed(targetPath) {
		return fmt.Sprintf("container archive denied: target path %q is not allowlisted", targetPath), nil
	}

	spool, size, err := spoolRequestBodyForInspection(r, "sockguard-container-archive-", maxContainerArchiveBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container archive denied: request body exceeds %d byte limit", maxContainerArchiveBodyBytes))
		}
		return "", err
	}
	if spool == nil || size == 0 {
		if spool != nil {
			spool.closeAndRemove()
		}
		return "", nil
	}

	denyReason, err := p.inspectContainerArchiveTar(spool.file)
	if err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("inspect archive body: %w", err)
	}
	if denyReason != "" {
		spool.closeAndRemove()
		return denyReason, nil
	}

	if err := seekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind archive body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func isContainerArchivePath(normalizedPath string) bool {
	if !strings.HasPrefix(normalizedPath, "/containers/") {
		return false
	}
	_, tail, ok := strings.Cut(strings.TrimPrefix(normalizedPath, "/containers/"), "/")
	return ok && tail == "archive"
}

func normalizeContainerArchiveTargetPath(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", true
	}
	cleaned := path.Clean(strings.TrimLeft(trimmed, "/"))
	if cleaned == "." || cleaned == "" {
		return ".", true
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func normalizeContainerArchiveRelativePath(value string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func (p containerArchivePolicy) inspectContainerArchiveTar(reader io.Reader) (string, error) {
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}

		denyReason := p.denyReasonForContainerArchiveEntry(header)
		if denyReason != "" {
			return denyReason, nil
		}
	}
}

func (p containerArchivePolicy) denyReasonForContainerArchiveEntry(header *tar.Header) string {
	if header == nil {
		return ""
	}

	entryPath, ok := normalizeContainerArchiveEntryPath(header.Name)
	if !ok {
		return fmt.Sprintf("container archive denied: tar entry %q must be relative and stay within the archive", header.Name)
	}

	if !p.allowSetID && header.Mode&0o6000 != 0 {
		return fmt.Sprintf("container archive denied: tar entry %q sets setuid/setgid bits", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeChar, tar.TypeBlock:
		if !p.allowDeviceNodes {
			return fmt.Sprintf("container archive denied: tar entry %q is a device node", header.Name)
		}
	case tar.TypeSymlink:
		if !p.allowEscapingLinks && !containerArchiveSymlinkTargetIsSafe(entryPath, header.Linkname) {
			return fmt.Sprintf("container archive denied: symlink %q escapes the archive", header.Name)
		}
	case tar.TypeLink:
		if !p.allowEscapingLinks && !containerArchiveHardlinkTargetIsSafe(header.Linkname) {
			return fmt.Sprintf("container archive denied: hardlink %q escapes the archive", header.Name)
		}
	}

	return ""
}

func normalizeContainerArchiveEntryPath(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "", false
	}
	cleaned := path.Clean(trimmed)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func normalizeContainerArchiveAllowedPaths(values []string) []string {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		trimmed = strings.TrimPrefix(path.Clean(trimmed), "/")
		normalized, ok := normalizeContainerArchiveRelativePath(trimmed)
		if !ok || containerArchivePathInList(normalized, allowed) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func (p containerArchivePolicy) targetPathAllowed(targetPath string) bool {
	if len(p.allowedPaths) == 0 || targetPath == "" {
		return true
	}
	return containerArchivePathInList(targetPath, p.allowedPaths)
}

func containerArchivePathInList(targetPath string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		if allowed == "." || targetPath == allowed || strings.HasPrefix(targetPath, allowed+"/") {
			return true
		}
	}
	return false
}

func containerArchiveSymlinkTargetIsSafe(entryPath string, linkName string) bool {
	trimmed := strings.TrimSpace(linkName)
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return trimmed == ""
	}

	combined := trimmed
	if dir := path.Dir(entryPath); dir != "." {
		combined = path.Join(dir, trimmed)
	}
	_, ok := normalizeContainerArchiveEntryPath(combined)
	return ok
}

func containerArchiveHardlinkTargetIsSafe(linkName string) bool {
	trimmed := strings.TrimSpace(linkName)
	if trimmed == "" {
		return true
	}
	_, ok := normalizeContainerArchiveEntryPath(trimmed)
	return ok
}

func spoolRequestBodyForInspection(r *http.Request, prefix string, maxBytes int64) (*spooledRequestBody, int64, error) {
	if r == nil || r.Body == nil {
		return nil, 0, nil
	}
	if r.ContentLength > maxBytes {
		if err := r.Body.Close(); err != nil {
			return nil, 0, err
		}
		return nil, 0, &bodyTooLargeError{limit: maxBytes}
	}

	spool, size, err := spoolRequestBodyToTempFile(r, prefix, maxBytes)
	if err != nil {
		return nil, 0, err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return nil, size, &bodyTooLargeError{limit: maxBytes}
	}
	return spool, size, nil
}
