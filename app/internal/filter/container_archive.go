package filter

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	io                 ioDeps
}

func newContainerArchivePolicy(opts ContainerArchiveOptions) containerArchivePolicy {
	return containerArchivePolicy{
		allowedPaths:       normalizeContainerArchiveAllowedPaths(opts.AllowedPaths),
		allowSetID:         opts.AllowSetID,
		allowDeviceNodes:   opts.AllowDeviceNodes,
		allowEscapingLinks: opts.AllowEscapingLinks,
		io:                 defaultIODeps(),
	}
}

func (p containerArchivePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !matchesContainerArchiveInspection(normalizedPath) || r.Body == nil {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	query := r.URL.Query()
	targetValue, targetFound, targetAmbiguous := FoldedScalarQueryValue(query, "path")
	switch {
	case targetAmbiguous:
		return "container archive denied: ambiguous path query", nil
	case !targetFound || targetValue == "":
		return "container archive denied: target path is required", nil
	}

	renameValue, _, renameAmbiguous := FoldedScalarQueryValue(query, "rename")
	if renameAmbiguous || renameValue != "" {
		// Podman passes rename through to Buildah, which rewrites tar header
		// names after this inspector would otherwise validate them. A rename
		// can therefore change a safe relative symlink into one that escapes
		// the approved target subtree. Refuse the transformation rather than
		// claiming the original-header inspection covers it.
		return "container archive denied: rename query is not allowed", nil
	}

	targetPath, ok := normalizeContainerArchiveTargetPath(targetValue)
	if !ok {
		return "container archive denied: target path must stay within the container path", nil
	}
	if len(p.allowedPaths) > 0 && !strings.HasPrefix(targetValue, "/") {
		// Podman resolves a relative archive target against the container's
		// configured WorkingDir, not against the container root. Without a
		// daemon lookup there is no sound way to compare that effective path
		// with a root-relative allowed_paths entry, so treat it as
		// unallowlisted. Normalize first so traversal keeps its sharper denial.
		return fmt.Sprintf("container archive denied: target path %q is not allowlisted", targetPath), nil
	}
	if !p.targetPathAllowed(targetPath) {
		return fmt.Sprintf("container archive denied: target path %q is not allowlisted", targetPath), nil
	}

	spool, size, err := p.io.spoolRequestBodyForInspection(r, "sockguard-container-archive-", maxContainerArchiveBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("container archive denied: request body exceeds %d byte limit", maxContainerArchiveBodyBytes))
		}
		return "", err
	}
	if spool == nil || size == 0 {
		// closeAndRemove is nil-safe; this avoids a per-path nil check and
		// eliminates an equivalent mutation point in the inspect hot path.
		spool.closeAndRemove()
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

	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind archive body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

// FoldedScalarQueryValue recognizes the query behavior Podman's handlers get
// from gorilla/schema: field aliases are case-insensitive. It rejects repeated
// values because the supported daemons disagree about which scalar wins (Moby
// reads the first while Podman reads the last), and rejects two case-variant
// spellings because gorilla/schema's winner then depends on url.Values map
// iteration order.
//
// It is exported because the same ambiguity governs any single-valued query
// parameter a policy layer has to agree with the daemon about — the archive
// policy below reads `path` and `rename` with it, and internal/ownership reads
// the `container` parameter of POST /commit with it.
func FoldedScalarQueryValue(query url.Values, field string) (value string, found, ambiguous bool) {
	var spelling string
	for key, values := range query {
		if !strings.EqualFold(key, field) {
			continue
		}
		if found && key != spelling {
			return "", true, true
		}
		if len(values) > 1 {
			return "", true, true
		}
		found = true
		spelling = key
		value = ""
		if len(values) > 0 {
			value = values[len(values)-1]
		}
	}
	return value, found, false
}

// isContainerArchivePath matches the copy-into-container route on BOTH of
// Podman's spellings — Docker-compat "/containers/{id}/archive" and
// libpod-native "/libpod/containers/{id}/archive". It is the one place in
// this package where a single predicate deliberately spans both API families,
// and that is safe here for a reason that does not generalize: Podman v5.8.1
// registers the two paths on the identical compat.Archive handler
// (pkg/api/server/register_archive.go lines 88 and 172, both
// `.Methods(http.MethodGet, http.MethodPut, http.MethodHead)`), so the `path`
// query parameter and the tar request body are not merely similar, they are
// the same code reading the same wire format. There is no second body shape
// for containerArchivePolicy to get wrong, so forking a libpod twin would
// have bought nothing but another list to forget to update.
func isContainerArchivePath(normalizedPath string) bool {
	_, ok := containerSubresourcePath(normalizedPath, "archive")
	return ok
}

func normalizeContainerArchiveTargetPath(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	cleaned := path.Clean(strings.TrimLeft(value, "/"))
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

func (io_ ioDeps) spoolRequestBodyForInspection(r *http.Request, prefix string, maxBytes int64) (*spooledRequestBody, int64, error) {
	if r == nil || r.Body == nil {
		return nil, 0, nil
	}
	if r.ContentLength > maxBytes {
		if err := r.Body.Close(); err != nil {
			return nil, 0, err
		}
		return nil, 0, &bodyTooLargeError{limit: maxBytes}
	}

	spool, size, err := io_.spoolRequestBodyToTempFile(r, prefix, maxBytes)
	if err != nil {
		return nil, 0, err
	}
	if spool.tooLarge {
		spool.closeAndRemove()
		return nil, size, &bodyTooLargeError{limit: maxBytes}
	}
	return spool, size, nil
}
