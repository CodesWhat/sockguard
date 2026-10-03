package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
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
	io                 ioDeps
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
		io:                 defaultIODeps(),
	}
}

// inspect applies allow_imports and the registry allowlist to
// POST /images/create. The route is two operations, an import and a pull, and
// the two gates are independent: neither one answers for the other.
//
// The engines disagree on which operation a request is, and on which value of
// a parameter they read:
//
//   - dockerd (postImagesCreate) reads the first `fromImage` under the exact
//     key and pulls when it is not empty. It reads `fromSrc` on the other
//     branch only, so a request carrying both is a pull. Read from moby 28.5.1
//     and 29.5.2 and confirmed against dockerd 29.5.2.
//   - Podman registers the path once per operation and gorilla/mux picks the
//     handler by which exact key is present, `fromImage` first. The handler
//     then decodes its parameter with gorilla/schema v1.4.1, which matches the
//     key in any case and keeps the last value. Read from Podman 5.8.6.
//
// So each parameter is read through queryparam, which refuses one that is
// repeated or spelled other than `fromImage`/`fromSrc`, the only shape the
// two engines read the same way. A `fromSrc` makes the request an import that
// allow_imports has to permit, and a `fromImage` has to pass the registry
// allowlist whether or not the request also names an import source.
// Returning as soon as an import was allowed is what let
// `?fromSrc=-&fromImage=<any registry>` pull from outside the allowlist.
func (p imagePullPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/images/create" {
		return "", nil
	}

	if denyReason := denyRegistryAuthHeaderReason(r.Header.Get("X-Registry-Auth"), p.allowAllRegistries, p.allowedRegistries, "image pull"); denyReason != "" {
		return denyReason, nil
	}

	query := logging.RequestQuery(r)
	if !p.allowImports {
		fromSrc, _, ok := queryparam.Scalar(query, "fromSrc")
		if !ok {
			return ambiguousQueryReason("image pull", "fromSrc"), nil
		}
		if fromSrc != "" {
			return fmt.Sprintf("image pull denied: importing images from %q is not allowed", strings.TrimSpace(fromSrc)), nil
		}
	}

	if p.allowAllRegistries {
		return "", nil
	}
	fromImage, _, ok := queryparam.Scalar(query, "fromImage")
	if !ok {
		return ambiguousQueryReason("image pull", "fromImage"), nil
	}
	return p.denyReasonForReference(strings.TrimSpace(fromImage), "image pull"), nil
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
//     a plain Query().Get("reference"). The parameter is read through
//     queryparam, which refuses both shapes.
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

	if p.allowAllRegistries {
		return "", nil
	}
	raw, _, ok := queryparam.Scalar(logging.RequestQuery(r), "reference")
	if !ok {
		return ambiguousQueryReason(libpodImagePullSubject, "reference"), nil
	}
	reference := strings.TrimPrefix(strings.TrimSpace(raw), libpodRegistryTransportPrefix)
	if strings.TrimSpace(reference) == "" {
		return libpodImagePullSubject + " denied: no reference parameter to check against the registry allowlist", nil
	}
	return p.denyReasonForReference(reference, libpodImagePullSubject), nil
}

// libpodImageImportSubject prefixes libpod-family import denial reasons.
const libpodImageImportSubject = "libpod image import"
const maxLibpodImageImportBodyBytes = 512 << 20 // 512 MiB

// inspectLibpodImport applies request_body.image_pull.allow_imports to
// Podman's native POST /libpod/images/import — the libpod counterpart of the
// Docker-compat import that rides on POST /images/create?fromSrc= and that
// inspect() above already gates. It shares imagePullPolicy for the same
// reason inspectLibpod does: one allow_imports flag has to govern both
// surfaces or an operator configures one and leaves the other open.
//
// Verified against Podman v5.8.1's pkg/api/handlers/libpod/images.go
// ImagesImport: EVERY request to this path is an import. When `URL` is set
// the daemon fetches the tarball from a caller-chosen URL; when it is empty
// the daemon copies the request body to disk without an upstream size cap.
// allow_imports remains the coarse capability gate for both forms. Body-form
// imports are additionally spooled through Sockguard's bounded request-body
// path, while URL imports stay body-independent. Each original case variant
// uses its last value, matching gorilla/schema's scalar decode. If conflicting
// variants make the selected form map-order-dependent, the body form wins so
// the upstream copy cannot become unbounded.
func (p imagePullPolicy) inspectLibpodImport(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || !isLibpodImageImportPath(normalizedPath) {
		return "", nil
	}

	source, bodyImport := classifyLibpodImageImportSource(logging.RequestQuery(r))
	if !p.allowImports {
		if source == "" {
			return libpodImageImportSubject + " denied: importing images is not allowed", nil
		}
		return fmt.Sprintf("%s denied: importing images from %q is not allowed", libpodImageImportSubject, source), nil
	}
	if !bodyImport || r.Body == nil {
		return "", nil
	}
	if p.io.CreateTempFile == nil {
		p.io = defaultIODeps()
	}

	spool, size, err := p.io.spoolRequestBodyForInspection(r, "sockguard-image-import-", maxLibpodImageImportBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			return "", newRequestRejectionError(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s denied: request body exceeds %d byte limit", libpodImageImportSubject, maxLibpodImageImportBodyBytes))
		}
		return "", err
	}
	if spool == nil {
		return "", nil
	}
	if size == 0 {
		spool.closeAndRemove()
		r.Body = http.NoBody
		r.ContentLength = 0
		return "", nil
	}
	if err := p.io.SeekToStart(spool.file); err != nil {
		spool.closeAndRemove()
		return "", fmt.Errorf("rewind libpod image import body: %w", err)
	}
	r.Body = spool.requestBody()
	r.ContentLength = size
	return "", nil
}

func classifyLibpodImageImportSource(query map[string][]string) (source string, bodyImport bool) {
	keys := make([]string, 0, len(query))
	for key := range query {
		if strings.EqualFold(key, "URL") {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return "", true
	}

	for _, key := range keys {
		values := query[key]
		if len(values) == 0 {
			bodyImport = true
			continue
		}
		effective := values[len(values)-1]
		if effective == "" {
			bodyImport = true
			continue
		}
		if source == "" {
			source = effective
		}
	}
	return source, bodyImport
}

// distributionInspectSubject prefixes distribution-inspect denial reasons.
const distributionInspectSubject = "distribution inspect"

// isDistributionInspectPath reports whether normalizedPath is the
// Docker-compatible registry-distribution inspect route, which the daemon
// serves as GET /distribution/{name}/json. {name} is a full image reference
// and can be multi-segment (registry/owner/repo:tag or @digest), so the match
// is a prefix-and-suffix test rather than a fixed segment count. The caller
// has already version-stripped the path (NormalizePath), so no /vX.YZ prefix
// reaches here.
func isDistributionInspectPath(normalizedPath string) bool {
	return distributionInspectReference(normalizedPath) != ""
}

// distributionInspectReference returns the image reference embedded between
// "/distribution/" and "/json", or "" when normalizedPath is not that route
// or carries an empty name.
func distributionInspectReference(normalizedPath string) string {
	rest, ok := strings.CutPrefix(normalizedPath, "/distribution/")
	if !ok {
		return ""
	}
	name, ok := strings.CutSuffix(rest, "/json")
	if !ok || name == "" {
		return ""
	}
	return name
}

// inspectDistribution applies the same registry allowlist as inspect to
// GET /distribution/{name}/json (S38). That route makes the daemon reach out
// to whatever registry the reference names to fetch a manifest descriptor, so
// it is a registry-contact surface exactly like a pull and shares
// request_body.image_pull rather than a second config block.
//
// It is gated on an explicitly configured allowlist: when no allowed_registries
// are set (and allow_all_registries is not in force) the route is left exactly
// as open as it was before S38, so enabling the pull inspector's default
// allow_official posture never silently starts denying distribution queries an
// operator did not opt into restricting. Once an allowlist is configured, the
// reference's registry host must satisfy it on the same terms a pull does
// (allow_official still exempts Docker Hub official images). Credentials in an
// X-Registry-Auth header are not inspected here: the registry the daemon
// contacts is the one named in the path reference, which is what this checks.
func (p imagePullPolicy) inspectDistribution(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodGet {
		return "", nil
	}
	reference := distributionInspectReference(normalizedPath)
	if reference == "" {
		return "", nil
	}
	if p.allowAllRegistries || len(p.allowedRegistries) == 0 {
		return "", nil
	}
	if denyReason := p.denyReasonForReference(reference, distributionInspectSubject); denyReason != "" {
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
