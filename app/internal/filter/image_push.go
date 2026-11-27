package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/apipath"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
	"github.com/codeswhat/sockguard/v3/app/internal/queryparam"
)

// ImagePushOptions configures the registry allowlist for image, plugin and
// manifest pushes (request_body.image_push).
//
// The policy is active only when AllowedRegistries is non-empty. An inactive
// policy inspects nothing, which is the behavior before this option existed:
// pushes stay gated by insecure_allow_read_exfiltration and owner isolation.
type ImagePushOptions struct {
	// AllowedRegistries are bare registry hosts a push may target.
	AllowedRegistries []string
	// RegistryAliases maps a host a client may name to the host the daemon
	// actually reaches for it (a registries.conf mirror, a split-horizon name).
	// The target is what AllowedRegistries is checked against. Single level
	// only: a target is never itself looked up again.
	RegistryAliases map[string]string
	// PodmanUpstream is set from the resolved upstream flavor, not from
	// config. An unqualified name is Docker Hub on dockerd. On Podman it is
	// resolved through registries.conf, which sockguard cannot read, so it is
	// refused there. The zero value is dockerd, like every other flavor flag.
	PodmanUpstream bool
}

// builtinRegistryAliases are the hosts Docker Hub is reached under. They are
// applied before operator aliases and cannot be overridden.
var builtinRegistryAliases = map[string]string{
	"index.docker.io":         "docker.io",
	"registry-1.docker.io":    "docker.io",
	"registry.hub.docker.com": "docker.io",
}

// IsBuiltinRegistryAlias reports whether host is one of the Docker Hub
// spellings the push policy always resolves to docker.io, or docker.io itself.
// Config validation uses it to refuse an operator alias that could never apply.
func IsBuiltinRegistryAlias(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "docker.io" {
		return true
	}
	_, ok := builtinRegistryAliases[host]
	return ok
}

type imagePushPolicy struct {
	active  bool
	allowed []string
	aliases map[string]string
	podman  bool
}

func newImagePushPolicy(opts ImagePushOptions) imagePushPolicy {
	p := imagePushPolicy{podman: opts.PodmanUpstream}
	for _, registry := range opts.AllowedRegistries {
		normalized, ok := normalizeRegistryHost(registry)
		if !ok {
			continue
		}
		if builtin, isBuiltin := builtinRegistryAliases[normalized]; isBuiltin {
			normalized = builtin
		}
		if !slices.Contains(p.allowed, normalized) {
			p.allowed = append(p.allowed, normalized)
		}
	}
	p.active = len(p.allowed) > 0
	if !p.active {
		return p
	}
	if len(opts.RegistryAliases) > 0 {
		p.aliases = make(map[string]string, len(opts.RegistryAliases))
		for from, to := range opts.RegistryAliases {
			from, okFrom := normalizeRegistryHost(from)
			to, okTo := normalizeRegistryHost(to)
			if !okFrom || !okTo || IsBuiltinRegistryAlias(from) {
				continue
			}
			if builtin, isBuiltin := builtinRegistryAliases[to]; isBuiltin {
				to = builtin
			}
			if from == to {
				continue
			}
			p.aliases[from] = to
		}
	}
	return p
}

// resolveHost applies the built-in Docker Hub aliases, then one operator alias.
// An operator alias is never followed twice.
func (p imagePushPolicy) resolveHost(host string) string {
	if target, ok := builtinRegistryAliases[host]; ok {
		host = target
	}
	if target, ok := p.aliases[host]; ok {
		host = target
	}
	return host
}

type pushRoutes uint8

const (
	pushRouteCompatImage pushRoutes = 1 << iota
	pushRoutePlugin
	pushRouteLibpodImage
	pushRouteManifestRegistry
	pushRouteManifestPush
)

const (
	pushPathImages    = "/images/"
	pushPathPlugins   = "/plugins/"
	pushPathLibpodImg = "/libpod/images/"
	pushPathManifests = "/libpod/manifests/"
	pushPathSuffix    = "/push"
	pushPathRegistry  = "/registry/"
)

// classifyPushRoutes names every push route the normalized path can be read as.
// A name is a slash-bearing path in all of them, so one path can be read more
// than one way (a manifest named "x/registry/y" is also a registry push of "y").
// Every reading that applies is enforced.
func classifyPushRoutes(normalizedPath string) pushRoutes {
	var routes pushRoutes
	if pushNameBetween(normalizedPath, pushPathImages, pushPathSuffix) != "" {
		routes |= pushRouteCompatImage
	}
	if pushNameBetween(normalizedPath, pushPathPlugins, pushPathSuffix) != "" {
		routes |= pushRoutePlugin
	}
	if pushNameBetween(normalizedPath, pushPathLibpodImg, pushPathSuffix) != "" {
		routes |= pushRouteLibpodImage
	}
	if rest, ok := strings.CutPrefix(normalizedPath, pushPathManifests); ok {
		if strings.Contains(rest, pushPathRegistry) {
			routes |= pushRouteManifestRegistry
		}
		if pushNameBetween(normalizedPath, pushPathManifests, pushPathSuffix) != "" {
			routes |= pushRouteManifestPush
		}
	}
	return routes
}

func matchesImagePushInspection(normalizedPath string) bool {
	return classifyPushRoutes(normalizedPath) != 0
}

func pushNameBetween(p, prefix, suffix string) string {
	rest, ok := strings.CutPrefix(p, prefix)
	if !ok {
		return ""
	}
	name, ok := strings.CutSuffix(rest, suffix)
	if !ok {
		return ""
	}
	return name
}

// Reason fragments. Every denial is "image push denied: ..." and none of them
// carries X-Registry-Auth content.
const (
	imagePushInvalidReason = "image push denied: invalid destination reference"
	// imagePushReasonMaxLen bounds how much of a caller-supplied value is echoed.
	imagePushReasonMaxLen = 128
)

func imagePushQuote(value string) string {
	if len(value) > imagePushReasonMaxLen {
		value = value[:imagePushReasonMaxLen]
	}
	return fmt.Sprintf("%q", value)
}

// inspect applies request_body.image_push to every route that sends a local
// image, plugin or manifest to a registry. The destination is read the way the
// engine reads it, and anything that cannot be read with certainty is denied:
// unlike the pull inspector, which waves through a reference it cannot parse,
// a push that cannot be attributed to an allowlisted registry never passes.
//
// The path is read three ways at once, the decoded path the router sees, and
// the escaped path Podman routes on, both without path cleaning, and every
// reading has to pass. That is what keeps a URL-escaped manifest destination
// (`%2F`, `%252F`, an escaped "/registry/") from being read one way here and
// another by the daemon.
func (p imagePushPolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !p.active || r == nil || r.URL == nil || r.Method != http.MethodPost {
		return "", nil
	}
	routes := classifyPushRoutes(normalizedPath)
	if routes == 0 {
		return "", nil
	}

	query, err := logging.ParseRequestQuery(r)
	if err != nil {
		return imagePushInvalidReason, nil
	}

	var compat, libpod []string
	if routes&(pushRouteCompatImage|pushRoutePlugin) != 0 {
		prefix := pushPathImages
		if routes&pushRoutePlugin != 0 {
			prefix = pushPathPlugins
		}
		names, ok := rawPushNames(r, prefix)
		if !ok {
			return imagePushInvalidReason, nil
		}
		compat = append(compat, names...)
		if routes&pushRouteCompatImage != 0 {
			if _, _, ok := queryparam.Scalar(query, "tag"); !ok {
				return ambiguousQueryReason("image push", "tag"), nil
			}
		}
		// Podman's compat push also reads `destination`, and dockerd ignores
		// it. Holding it to the allowlist costs a dockerd client nothing.
		dest, _, ok := queryparam.Scalar(query, "destination")
		if !ok {
			return ambiguousQueryReason("image push", "destination"), nil
		}
		if dest != "" {
			libpod = append(libpod, dest)
		}
	}
	if routes&pushRouteLibpodImage != 0 {
		dest, _, ok := queryparam.Scalar(query, "destination")
		if !ok {
			return ambiguousQueryReason("image push", "destination"), nil
		}
		if dest != "" {
			libpod = append(libpod, dest)
		} else {
			names, ok := rawPushNames(r, pushPathLibpodImg)
			if !ok {
				return imagePushInvalidReason, nil
			}
			libpod = append(libpod, names...)
		}
	}
	if routes&pushRouteManifestRegistry != 0 {
		dests, ok := rawManifestRegistryDestinations(r)
		if !ok {
			return imagePushInvalidReason, nil
		}
		libpod = append(libpod, dests...)
	}
	if routes&pushRouteManifestPush != 0 {
		dest, _, ok := queryparam.Scalar(query, "destination")
		if !ok {
			return ambiguousQueryReason("image push", "destination"), nil
		}
		if dest == "" {
			// Nothing to attribute the push to.
			return imagePushInvalidReason, nil
		}
		libpod = append(libpod, dest)
	}

	for _, name := range compat {
		if reason := p.denyReasonForDestination(name, false); reason != "" {
			return reason, nil
		}
	}
	for _, dest := range libpod {
		if reason := p.denyReasonForDestination(dest, true); reason != "" {
			return reason, nil
		}
	}
	return p.denyReasonForRegistryAuth(r), nil
}

// rawPushNames returns the image or plugin name between prefix and the final
// "/push" as the decoded path and as the escaped path (unescaped once) spell
// it. The version prefix is stripped but the path is not cleaned, so "//" and
// "." segments reach the reference parser, which refuses them. A path that
// does not have the expected shape in either spelling reports !ok.
func rawPushNames(r *http.Request, prefix string) ([]string, bool) {
	var names []string
	for _, spelling := range []struct {
		path    string
		escaped bool
	}{{r.URL.Path, false}, {r.URL.EscapedPath(), true}} {
		name := pushNameBetween(apipath.StripVersionPrefix(spelling.path), prefix, pushPathSuffix)
		if name == "" {
			return nil, false
		}
		if spelling.escaped {
			unescaped, err := url.PathUnescape(name)
			if err != nil {
				return nil, false
			}
			name = unescaped
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names, true
}

// rawManifestRegistryDestinations returns every destination the path can name
// in POST /libpod/manifests/{name}/registry/{destination}. {name} may itself
// hold "/registry/", so the first and the last occurrence both count.
func rawManifestRegistryDestinations(r *http.Request) ([]string, bool) {
	var dests []string
	for _, spelling := range []struct {
		path    string
		escaped bool
	}{{r.URL.Path, false}, {r.URL.EscapedPath(), true}} {
		rest, ok := strings.CutPrefix(apipath.StripVersionPrefix(spelling.path), pushPathManifests)
		if !ok {
			return nil, false
		}
		first := strings.Index(rest, pushPathRegistry)
		last := strings.LastIndex(rest, pushPathRegistry)
		if first < 0 || last < 0 {
			return nil, false
		}
		for _, at := range []int{first, last} {
			dest := rest[at+len(pushPathRegistry):]
			if spelling.escaped {
				unescaped, err := url.PathUnescape(dest)
				if err != nil {
					return nil, false
				}
				dest = unescaped
			}
			if !slices.Contains(dests, dest) {
				dests = append(dests, dest)
			}
		}
	}
	return dests, true
}

// pushTransports are the transport names containers/image accepts in front of
// a destination. A destination that names one (or anything else shaped like
// one) is refused: only "docker://" reaches a registry, and it is stripped
// before this check.
var pushTransports = []string{
	"docker", "docker-archive", "docker-daemon", "dir", "oci", "oci-archive",
	"containers-storage", "ostree", "sif", "tarball", "oci-layout",
}

var (
	pushDomainComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`
	pushDomainRE        = regexp.MustCompile(`^(?:` + pushDomainComponent + `(?:\.` + pushDomainComponent + `)*|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?$`)
	pushPathComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	pushTagRE           = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	pushDigestRE        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$`)
)

type pushDestinationProblem uint8

const (
	pushDestinationOK pushDestinationProblem = iota
	pushDestinationInvalid
	pushDestinationTransport
)

type pushDestination struct {
	host      string
	qualified bool
	transport string
	problem   pushDestinationProblem
}

// parsePushDestination reads a destination reference with the distribution
// reference grammar, strictly. With libpod set the "docker://" transport is
// stripped first, the one spelling Podman's native routes accept.
func parsePushDestination(value string, libpod bool) pushDestination {
	invalid := pushDestination{problem: pushDestinationInvalid}
	if value == "" || len(value) > 1024 {
		return invalid
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c <= ' ' || c >= 0x7f || c == '\\' || c == '%' {
			return invalid
		}
	}
	s := value
	if libpod {
		s = strings.TrimPrefix(s, "docker://")
	}

	head, hasSlash := s, false
	if i := strings.IndexByte(s, '/'); i >= 0 {
		head, hasSlash = s[:i], true
	}
	if !strings.HasPrefix(head, "[") {
		if i := strings.IndexByte(head, ':'); i >= 0 {
			pre, post := head[:i], head[i+1:]
			if slices.Contains(pushTransports, strings.ToLower(pre)) || (hasSlash && !allASCIIDigits(post)) {
				return pushDestination{problem: pushDestinationTransport, transport: pre}
			}
		}
	}

	name := s
	if at := strings.IndexByte(name, '@'); at >= 0 {
		if !pushDigestRE.MatchString(name[at+1:]) {
			return invalid
		}
		name = name[:at]
	}
	lastSlash, lastColon := strings.LastIndexByte(name, '/'), strings.LastIndexByte(name, ':')
	if lastColon > lastSlash {
		if !pushTagRE.MatchString(name[lastColon+1:]) {
			return invalid
		}
		name = name[:lastColon]
	}
	if name == "" {
		return invalid
	}

	parts := strings.Split(name, "/")
	host, qualified := "docker.io", false
	repository := parts
	if len(parts) > 1 && pushLooksLikeDomain(parts[0]) {
		if !pushDomainRE.MatchString(parts[0]) {
			return invalid
		}
		host, qualified = strings.ToLower(parts[0]), true
		repository = parts[1:]
	}
	for _, component := range repository {
		if !pushPathComponentRE.MatchString(component) {
			return invalid
		}
	}
	if len(strings.Join(repository, "/")) > 255 {
		return invalid
	}
	return pushDestination{host: host, qualified: qualified}
}

// pushLooksLikeDomain is the distribution grammar's test for a first path
// component being a registry: a dot, a port, "localhost", or any uppercase.
// The uppercase case is the one looksLikeRegistryComponent leaves out, so a
// reference it would read as Docker Hub is read as a registry here and held to
// the allowlist by that name.
func pushLooksLikeDomain(component string) bool {
	return strings.ContainsAny(component, ".:") || component == "localhost" || component != strings.ToLower(component)
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// denyReasonForDestination returns the denial for one destination, or "".
// libpod selects Podman's native spelling: "docker://" is accepted and an
// unqualified name is refused, since its registry comes from registries.conf.
// For the Docker-compatible spelling an unqualified name is Docker Hub on
// dockerd and refused on Podman for the same reason.
func (p imagePushPolicy) denyReasonForDestination(value string, libpod bool) string {
	dest := parsePushDestination(value, libpod)
	switch dest.problem {
	case pushDestinationTransport:
		return fmt.Sprintf("image push denied: destination transport %s is not allowed", imagePushQuote(dest.transport))
	case pushDestinationInvalid:
		return imagePushInvalidReason
	}
	if !dest.qualified && (libpod || p.podman) {
		return fmt.Sprintf("image push denied: unqualified destination %s", imagePushQuote(value))
	}
	if !slices.Contains(p.allowed, p.resolveHost(dest.host)) {
		return fmt.Sprintf("image push denied: registry %s is not allowlisted", imagePushQuote(dest.host))
	}
	return ""
}

// denyReasonForRegistryAuth holds the credentials a push carries to the same
// allowlist as its destination. The registry a daemon sends credentials to is
// the destination's, but a header naming another one is a client trying to
// hand a credential to a registry the operator did not list. The decoded
// fields are never echoed.
func (p imagePushPolicy) denyReasonForRegistryAuth(r *http.Request) string {
	values := r.Header.Values("X-Registry-Auth")
	switch len(values) {
	case 0:
		return ""
	case 1:
	default:
		return "image push denied: X-Registry-Auth header is repeated"
	}
	trimmed := strings.TrimSpace(values[0])
	if trimmed == "" {
		return ""
	}
	decoded, err := decodeRegistryAuthHeaderBytes(trimmed, "X-Registry-Auth", "image push")
	if err != nil {
		return err.Error()
	}
	var auth registryAuthHeader
	if err := json.Unmarshal(decoded, &auth); err != nil {
		return "image push denied: X-Registry-Auth header is not valid JSON"
	}
	server := strings.TrimSpace(auth.ServerAddress)
	if server == "" {
		return ""
	}
	host := strings.ToLower(stripRegistryHeaderScheme(server))
	if !pushDomainRE.MatchString(host) || !slices.Contains(p.allowed, p.resolveHost(host)) {
		return "image push denied: X-Registry-Auth serveraddress is not allowlisted"
	}
	return ""
}
