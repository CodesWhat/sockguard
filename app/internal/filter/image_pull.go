package filter

import (
	"fmt"
	"log/slog"
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

func (p imagePullPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/images/create" {
		return "", nil
	}

	if denyReason := denyRegistryAuthHeaderReason(r.Header.Get("X-Registry-Auth"), p.allowAllRegistries, p.allowedRegistries, "image pull"); denyReason != "" {
		return denyReason, nil
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

// libpodRegistryTransportPrefix is the only non-bare reference spelling
// Podman's ImagesPull handler accepts. utils.IsRegistryReference rejects every
// transport except `docker`, and containers/image's docker transport requires
// the remainder to start with "//", so `docker://quay.io/acme/app` reaches
// libimage.Pull -> copyFromRegistry and pulls for real while `dir:/tmp/x` or
// `docker-archive:...` are rejected with 400 before any pull happens. The
// prefix is matched case-sensitively because alltransports resolves the
// transport name through an exact-match map keyed "docker".
const libpodRegistryTransportPrefix = "docker://"

// libpodImagePullSubject prefixes libpod-family denial reasons, matching the
// convention the other libpod inspectors use.
const libpodImagePullSubject = "libpod image pull"

// inspectLibpod applies the same registry allowlist as inspect to Podman's
// native POST /libpod/images/pull, the libpod counterpart of Docker's
// POST /images/create. It shares imagePullPolicy (and therefore
// request_body.image_pull) rather than forking a second config surface, so an
// operator cannot configure an allowlist for one surface and silently leave
// the other open — the same reason request_body.exec and request_body.build
// are shared across both API families.
//
// Three things about libpod's query shape make this a separate method rather
// than a widened path guard on inspect, all verified against Podman v5.8.1's
// pkg/api/handlers/libpod/images_pull.go:
//
//   - The parameter is `reference`, not Docker's `fromImage`/`tag`. Reading
//     the Docker spelling here would find nothing and allow every pull.
//   - Podman decodes the query with gorilla/schema v1.4.1, whose
//     structInfo.get matches tags with strings.EqualFold and whose scalar
//     decode takes the LAST value when a key repeats. net/url does neither, so
//     `?Reference=...` and `?reference=ok&reference=evil` would both slip past
//     a plain Query().Get("reference"). Keys are folded (the same treatment
//     the libpod build controls get) and every value is checked.
//   - There is no `fromSrc` equivalent: libpod imports are a separate endpoint
//     (POST /libpod/images/import), so allow_imports is not consulted here.
//
// A request carrying no usable `reference` is denied rather than passed
// through whenever a registry allowlist posture is in force. Podman itself
// rejects such a request (the handler 500s on an empty reference), so nothing
// legitimate is lost, and it makes "this inspector never allows a libpod pull
// it could not evaluate" hold unconditionally instead of depending on the
// parameter name staying correct.
func (p imagePullPolicy) inspectLibpod(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodImagePullPath(normalizedPath) {
		return "", nil
	}

	if denyReason := denyRegistryAuthHeaderReason(r.Header.Get("X-Registry-Auth"), p.allowAllRegistries, p.allowedRegistries, libpodImagePullSubject); denyReason != "" {
		return denyReason, nil
	}

	evaluated := false
	for _, raw := range foldQueryKeys(r.URL.Query())["reference"] {
		reference := strings.TrimPrefix(strings.TrimSpace(raw), libpodRegistryTransportPrefix)
		if strings.TrimSpace(reference) == "" {
			continue
		}
		evaluated = true
		if denyReason := p.denyReasonForReference(reference, libpodImagePullSubject); denyReason != "" {
			return denyReason, nil
		}
	}
	if !evaluated && !p.allowAllRegistries {
		return libpodImagePullSubject + " denied: no reference parameter to check against the registry allowlist", nil
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

	registry := "docker.io"
	repository := parts
	if len(parts) > 1 && looksLikeRegistryComponent(parts[0]) {
		registry, _ = normalizeRegistryHost(parts[0])
		repository = parts[1:]
	}
	for _, segment := range repository {
		if strings.TrimSpace(segment) == "" {
			return parsedImageReference{}, false
		}
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
