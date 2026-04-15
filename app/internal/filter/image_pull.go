package filter

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// ImagePullOptions configures query inspection for POST /images/create.
type ImagePullOptions struct {
	AllowImports       bool
	AllowAllRegistries bool
	AllowOfficial      bool
	AllowedRegistries  []string
}

type imagePullPolicy struct {
	allowImports       bool
	allowAllRegistries bool
	allowOfficial      bool
	allowedRegistries  []string
}

func newImagePullPolicy(opts ImagePullOptions) imagePullPolicy {
	allowed := make([]string, 0, len(opts.AllowedRegistries))
	for _, registry := range opts.AllowedRegistries {
		normalized, ok := normalizeRegistryHost(registry)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}

	return imagePullPolicy{
		allowImports:       opts.AllowImports,
		allowAllRegistries: opts.AllowAllRegistries,
		allowOfficial:      opts.AllowOfficial,
		allowedRegistries:  allowed,
	}
}

func (p imagePullPolicy) inspect(r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/images/create" {
		return "", nil
	}

	query := r.URL.Query()
	if fromSrc := strings.TrimSpace(query.Get("fromSrc")); fromSrc != "" {
		if p.allowImports {
			return "", nil
		}
		return fmt.Sprintf("image pull denied: importing images from %q is not allowed", fromSrc), nil
	}

	fromImage := strings.TrimSpace(query.Get("fromImage"))
	if fromImage == "" {
		return "", nil
	}

	if denyReason := p.denyReasonForReference(fromImage, "image pull"); denyReason != "" {
		return denyReason, nil
	}
	return "", nil
}

func (p imagePullPolicy) denyReasonForReference(fromImage, subject string) string {
	if fromImage == "" {
		return ""
	}

	ref, ok := parseImageReference(fromImage)
	if !ok {
		return ""
	}
	if p.allowAllRegistries {
		return ""
	}
	if p.allowOfficial && ref.official {
		return ""
	}
	if slices.Contains(p.allowedRegistries, ref.registry) {
		return ""
	}

	return fmt.Sprintf("%s denied: registry %q is not allowlisted", subject, ref.registry)
}

type parsedImageReference struct {
	registry string
	official bool
}

func parseImageReference(value string) (parsedImageReference, bool) {
	ref := strings.TrimSpace(value)
	if ref == "" {
		return parsedImageReference{}, false
	}

	if withoutDigest, _, ok := strings.Cut(ref, "@"); ok {
		ref = withoutDigest
	}

	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		ref = ref[:lastColon]
	}

	parts := strings.Split(ref, "/")
	if len(parts) == 0 {
		return parsedImageReference{}, false
	}

	registry := "docker.io"
	repository := parts
	if len(parts) > 1 && looksLikeRegistryComponent(parts[0]) {
		normalized, ok := normalizeRegistryHost(parts[0])
		if !ok {
			return parsedImageReference{}, false
		}
		registry = normalized
		repository = parts[1:]
	}
	if len(repository) == 0 {
		return parsedImageReference{}, false
	}

	official := registry == "docker.io" && (len(repository) == 1 || (len(repository) == 2 && repository[0] == "library"))
	return parsedImageReference{
		registry: registry,
		official: official,
	}, true
}

func looksLikeRegistryComponent(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || strings.EqualFold(value, "localhost")
}

func normalizeRegistryHost(value string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") {
		return "", false
	}
	switch trimmed {
	case "index.docker.io":
		return "docker.io", true
	default:
		return trimmed, true
	}
}
