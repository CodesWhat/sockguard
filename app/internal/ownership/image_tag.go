package ownership

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/imageselector"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const (
	imageTagRepoQueryField = "repo"
	imageTagTagQueryField  = "tag"

	// imageTagDefaultTag is the tag both engines fall back to when the
	// request names none: moby's httputils.RepoTagReference through
	// reference.TagNameOnly, Podman's compat.TagImage by literal.
	imageTagDefaultTag = "latest"

	// imageTagRepoMaxLen is the repository-name bound of the image reference
	// grammar (distribution/reference: RepositoryNameTotalLengthMax).
	imageTagRepoMaxLen = 255

	// imageTagBareRepoMaxLen is that bound for a name with no slash. dockerd
	// completes such a name to library/<name> before it measures the path, so
	// the eight characters come out of what the client may spell.
	imageTagBareRepoMaxLen = imageTagRepoMaxLen - len("library/")

	imageTagDenyNoRepo        = "owner policy denied image tag without a repo parameter: there is no target reference to authorize"
	imageTagDenyAmbiguous     = "owner policy denied image tag with an ambiguous repo or tag parameter"
	imageTagDenyDigest        = "owner policy denied image tag whose repo carries a digest"
	imageTagDenyQualifiedRepo = "owner policy denied image tag whose repo already carries a tag beside a tag parameter"
	imageTagDenyInvalidRepo   = "owner policy denied image tag with a repo outside the image reference grammar"
	imageTagDenyInvalidTag    = "owner policy denied image tag with a tag outside the image reference grammar"
	imageTagDenyDigestName    = "owner policy denied image tag whose repo is a digest algorithm name: the engines read such a reference as an image ID"
	imageTagDenyTarget        = "owner policy denied image tag onto a reference that already names an image outside this owner"
	imageTagDenyLibpodSegment = "owner policy denied image tag on an unversioned path whose image name starts with a libpod segment: Podman reads that request as a native one, so send it on a versioned path"
)

// imageTagOwnershipReference is the second image a retag names: the reference
// the daemon will create or move. Either target or denyReason is set.
type imageTagOwnershipReference struct {
	// target is that reference as name:tag, always tag-qualified, spelled
	// the way the engine builds it. See imageTagTarget.
	target string
	// storedTarget is a second name the same request can land on, set only
	// when the daemon may store the reference under another name than the
	// one target spells. Both have to pass. See imageTagNamedEitherWay.
	storedTarget string
	// denyReason refuses a request whose target cannot be read the way the
	// daemon will read it.
	denyReason string
}

// imageTagNaming is which name, or names, the target of a retag is checked
// under.
type imageTagNaming int

const (
	// imageTagNamedAsSpelled is the Docker-compatible route on dockerd, where
	// a name means one reference.
	imageTagNamedAsSpelled imageTagNaming = iota
	// imageTagNamedAsStored is Podman's native route, which stores a `repo`
	// that names no registry under localhost/ without looking anything up.
	// See podmanStoredImageName.
	imageTagNamedAsStored
	// imageTagNamedEitherWay is the Docker-compatible route on an upstream
	// that is, or may be, Podman. Where the tag lands there depends on
	// compat_api_enforce_docker_hub in the daemon's containers.conf, which
	// this layer cannot see:
	//
	//   - On, the default, NormalizeToDockerHub looks a short name up locally
	//     (alias first) and the tag moves the name that lookup found, or the
	//     Docker Hub one when nothing holds it. The inspect's handler starts
	//     with the same call, so the image the inspect of the name as spelled
	//     answers with is the one holding the name the tag moves.
	//   - Off, NormalizeToDockerHub returns the name untouched and libimage
	//     stores it under localhost/, the way the native route does. The
	//     inspect of the name as spelled still resolves alias-first, so it can
	//     answer for the caller's own image while the tag moves
	//     localhost/<repo> off someone else's.
	//
	// So a short name is checked under both: as spelled, and as
	// localhost/<repo>, which no resolution rule applies to and which Podman
	// answers for exactly under either setting. Each check covers the
	// destination of one setting, and the request goes through only when
	// both pass. The cost is on the default setting, where a caller whose
	// short name resolves to its own image through an alias is refused while
	// another owner holds localhost/<repo>:<tag>. Spelling the registry in
	// `repo` names one reference and gets one check. Read from Podman 5.8.6.
	imageTagNamedEitherWay
)

// imageTagNamingFor picks the names a Docker-compatible retag is checked
// under from the resolved upstream.flavor.
//
// Docker is dockerd, and so is the zero Flavor, as it is everywhere else (see
// Options.UpstreamFlavor). Podman gets both names whether the operator set it
// or the startup probe detected it: the two arrive here as the same value.
// Anything else is a flavor nobody resolved. Startup fails before it builds a
// chain from one, but a value that did arrive would leave no way to tell
// which engine reads the request, so it gets the check that holds on both.
// Asking dockerd about localhost/<repo> costs one inspect and can only refuse.
func imageTagNamingFor(flavor upstreamflavor.Flavor) imageTagNaming {
	if flavor == upstreamflavor.Docker || flavor == "" {
		return imageTagNamedAsSpelled
	}
	return imageTagNamedEitherWay
}

// The name production of the image reference grammar (distribution/reference):
// an optional domain[:port], whose host may be an IPv6 literal, then lowercase
// path components.
const (
	imageRefDomainComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`
	imageRefDomain          = `(?:` + imageRefDomainComponent + `(?:\.` + imageRefDomainComponent + `)*|\[[a-fA-F0-9:]+\])(?::[0-9]+)?`
	imageRefPathComponent   = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	imageRefPath            = imageRefPathComponent + `(?:/` + imageRefPathComponent + `)*`
)

// imageTagRepoName matches that production against the name as the client
// spells it, instead of the Docker Hub-normalized form the library matches.
// Normalizing only prefixes "docker.io/" and "library/", so every name dockerd
// accepts matches here too. The capture group is the domain the way the
// library's own anchored name pattern captures it, which is what
// reference.Domain reports for a name parsed without normalization.
var imageTagRepoName = regexp.MustCompile(`^(?:(` + imageRefDomain + `)/)?` + imageRefPath + `$`)

// isImageTagRoutePath reports whether normPath is a retag route: the
// Docker-compatible POST /images/{name}/tag that dockerd and Podman's compat
// layer both serve, or Podman's native POST /libpod/images/{name}/tag. Podman
// registers the two on one handler (compat.TagImage), so they read their
// parameters identically.
//
// POST /libpod/images/{name}/untag is deliberately not matched, although it
// takes the same two parameters. Podman resolves {name} to one image and
// removes a name only when that image holds it (libimage's Image.Untag
// answers "tag not known" otherwise), so `repo` and `tag` can only pick which
// of the source image's own names to drop. The source image is the whole
// effect, and the path check already authorizes it. Read from Podman 5.8.6.
func isImageTagRoutePath(method, normPath string) bool {
	if method != http.MethodPost {
		return false
	}
	for _, prefix := range []string{"/images/", libpodPrefix + "images/"} {
		if rest, ok := strings.CutPrefix(normPath, prefix); ok {
			return strings.HasSuffix(rest, "/tag") && len(rest) > len("/tag")
		}
	}
	return false
}

// imageTagOwnershipReferences reads the target of a retag for the
// authorization pass.
//
// A retag names two images. The path names the source, and `repo` and `tag`
// name a reference the daemon points at it. Both engines move that reference
// off whatever image held it: moby's reference store and containerd image
// service overwrite the name, and c/storage's AddNames removes it from the
// other image first. Authorizing the source alone therefore let a client take
// a name away from another owner's image by tagging one of its own images
// with it, after which the name resolves to an image of the client's
// choosing for everyone who refers to it.
//
// The target is a second subject, so it gets the same treatment the push
// route's tag does (see imagePushOwnershipReferences): it is authorized only
// when this layer can read it exactly the way the daemon will, and every
// shape where the two readings can part is refused. It reads the URL query
// only. Both engines read these parameters from r.Form, which a form-encoded
// body populates ahead of the query, so the check holds only while such a
// body never reaches the daemon. That is a property of every handler that
// reads r.Form, so it has to be refused for the whole proxy and not route by
// route here.
//
// A Docker-compatible path Podman would read as a native request is refused
// before the query is looked at. See compatPathReadAsLibpod. Every other
// Docker-compatible request is named by the engine behind the upstream. See
// imageTagNamingFor.
func imageTagOwnershipReferences(r *http.Request, normPath string, flavor upstreamflavor.Flavor) *ownershipRequestReferences {
	naming := imageTagNamedAsStored
	if !isLibpodOwnershipPath(normPath) {
		if compatPathReadAsLibpod(r.URL) {
			return &ownershipRequestReferences{imageTag: &imageTagOwnershipReference{denyReason: imageTagDenyLibpodSegment}}
		}
		naming = imageTagNamingFor(flavor)
	}
	target, storedTarget, denyReason := imageTagTarget(r.URL.RawQuery, naming)
	return &ownershipRequestReferences{imageTag: &imageTagOwnershipReference{target: target, storedTarget: storedTarget, denyReason: denyReason}}
}

// compatPathReadAsLibpod reports whether Podman reads the request as a native
// libpod one, whatever route it matches.
//
// Podman does not take that from the route. IsLibpodRequest splits the request
// URL on "/" and compares the third piece with "libpod": the segment after the
// version in /v5.0.0/libpod/images/..., and the first segment of the image
// name in an unversioned /images/{name}/tag. Both run compat.TagImage, and
// what the answer changes is NormalizeToDockerHub. A compat request has its
// target looked up the same way the inspect's handler looks it up. A native
// one skips that, so libimage stores a `repo` that names no registry under
// localhost/ (see podmanStoredImageName), while this layer, having classified
// the path as Docker-compatible, inspects the name as spelled and Podman
// answers that inspect through short-name resolution. A client could name one
// of its images "libpod", plant another under the name an alias resolves to,
// and move a localhost/ name off another owner's image. Read from Podman
// 5.8.6 (pkg/api/handlers/utils/apiutil).
//
// So an unversioned retag of an image named "libpod", or of one whose name
// starts with "libpod/", is refused, for every upstream: the flavor is a
// setting, and refusing costs a dockerd client only that one spelling. On an
// upstream resolved as Podman the two names imageTagNamedEitherWay checks
// would cover this target as well. The refusal does not lean on that. The
// versioned path, which is what the docker CLI, the SDKs and Podman's own
// compat clients send, has "images" in that position and is a compat request
// to Podman as well.
//
// The comparison is on the escaped path because that is the string Podman
// splits. The proxy forwards the path as it arrived and Podman's router
// matches it encoded, so "%6Cibpod" is "libpod" to neither, and
// "libpod%2Fapp" is one piece to both. Podman's split also runs over the
// query, which cannot matter here: a path its router sends to the tag handler
// always has the third piece.
func compatPathReadAsLibpod(u *url.URL) bool {
	pieces := strings.SplitN(u.EscapedPath(), "/", 4)
	return len(pieces) >= 3 && pieces[2] == "libpod"
}

// imageTagRoute words a retag's refusals. See imageDestinationRoute.
var imageTagRoute = imageDestinationRoute{action: "image tag", field: "repo"}

// imageTagTarget builds the reference a retag creates, as name:tag, or returns
// the reason the request is refused. storedTarget is the second name the same
// request can land on, and is empty wherever there is only one.
//
// The reference is built from `repo` and `tag` by imageDestinationFor, which
// also says which shapes of the two are refused and why. Confirmed against
// dockerd 29.5.2. What this adds is the reading of the query itself.
//
// Refused before a reference is built:
//
//   - A query net/url cannot parse cleanly. See imagePushOwnershipReferences.
//   - A repeated `repo` or `tag`, or any spelling of either key other than
//     the exact lowercase one. Both engines read the first value of the
//     exact key today (r.Form.Get), so this is narrower than they are on
//     purpose: one value under one spelling is the only shape whose reading
//     does not depend on which decoder the handler happens to use.
//   - No `repo`, or an empty one. dockerd answers 200 and does nothing,
//     Podman answers 400, and there is no target to authorize.
func imageTagTarget(rawQuery string, naming imageTagNaming) (target, storedTarget, denyReason string) {
	query, err := imageselector.Parse(rawQuery)
	if err != nil {
		return "", "", imageTagDenyAmbiguous
	}
	repo, ok := exactQueryScalar(query, imageTagRepoQueryField)
	if !ok {
		return "", "", imageTagDenyAmbiguous
	}
	tag, ok := exactQueryScalar(query, imageTagTagQueryField)
	if !ok {
		return "", "", imageTagDenyAmbiguous
	}

	if repo == "" {
		return "", "", imageTagDenyNoRepo
	}
	dest, problem := imageDestinationFor(repo, tag, naming)
	if problem != imageDestinationReadable {
		return "", "", imageTagRoute.refusal(problem)
	}
	return dest.target, dest.storedTarget, ""
}

// podmanStoredImageName completes name the way Podman stores it when it tags
// without a lookup: on its native tag route, and on the Docker-compatible one
// once compat_api_enforce_docker_hub is off.
//
// Both hand repo:tag to libimage's Image.Tag as it came, and NormalizeName
// prefixes "localhost/" to any name whose domain, as the reference grammar
// captures it, has no "." or ":" and is not "localhost". A Docker-compatible
// inspect of the short name goes through short-name resolution instead, which
// tries a registries.conf alias ahead of localhost/. With both images present
// it would answer for the aliased image while the tag lands on the localhost/
// one, so the inspect asks for the stored name, which no resolution rule
// applies to. Read from Podman 5.8.6 and its libimage (go.podman.io/common
// v0.67.1).
//
// A short name whose first component carries an upper-case letter is refused.
// The grammar allows one only in a domain, and under localhost/ that
// component becomes part of the path, which Podman rejects. Its default
// compat setting rejects the same name one step earlier, as a Docker Hub
// repository that is not lowercase. The caller also refuses a completed name
// over the length bound, because Podman's reference grammar measures the
// whole name, registry included.
//
// On the native route the stored name is the only one checked. On the
// Docker-compatible route it depends on the engine:
//
//   - dockerd is left as the client spelled it, which is exact: a name means
//     one reference there.
//   - Podman is checked under the name as spelled and under the stored one,
//     because which of the two the tag moves is a daemon setting. See
//     imageTagNamedEitherWay.
//   - Whether Podman reads the request as a compat one at all is decided by
//     its URL, not by this layer's route. compatPathReadAsLibpod refuses the
//     one Docker-compatible path it reads as native.
func podmanStoredImageName(name, domain string) (string, bool) {
	if strings.ContainsAny(domain, ".:") || domain == "localhost" {
		return name, true
	}
	if domain != strings.ToLower(domain) {
		return "", false
	}
	return "localhost/" + name, true
}

// exactQueryScalar returns the value of the one parameter spelled exactly
// key. It reports false when the request repeats the key or spells it in any
// other case, the two shapes a first-value decoder (net/http's Form.Get) and
// a case-folding last-value one (gorilla/schema) read differently. An absent
// parameter is an empty value with ok true.
func exactQueryScalar(query imageselector.Query, key string) (value string, ok bool) {
	found := false
	for _, field := range query {
		if !strings.EqualFold(field.Key, key) {
			continue
		}
		if found || field.Key != key {
			return "", false
		}
		value, found = field.Value, true
	}
	return value, true
}

// checkOwnedImageRoute authorizes a per-image route. Every route but a retag
// names one image and gets the ordinary check. A retag names two and has to
// clear both, the source first so its missing and foreign answers stay what
// they were. The target is authorized by checkImageDestination.
//
// A retag that reaches this pass with no captured target is refused, the same
// way imagePushIdentifier refuses a push with no captured tag: falling back
// to the source alone would be the check this route was fixed to stop doing.
func checkOwnedImageRoute(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	identifier string,
	opts Options,
	refs *ownershipRequestReferences,
	method, normPath string,
) (ownershipVerdict, string, error) {
	if !isImageTagRoutePath(method, normPath) {
		return checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	}
	if refs == nil || refs.imageTag == nil || (refs.imageTag.target == "" && refs.imageTag.denyReason == "") {
		return verdictDeny, imageTagDenyNoRepo, nil
	}
	if refs.imageTag.denyReason != "" {
		return verdictDeny, refs.imageTag.denyReason, nil
	}
	verdict, reason, err := checkOwnedResource(ctx, inspectResource, dockerresource.KindImage, identifier, opts, opts.AllowUnownedImages)
	if err != nil || verdict.denied() {
		return verdict, reason, err
	}
	return checkImageDestination(ctx, inspectResource, imageDestination{target: refs.imageTag.target, storedTarget: refs.imageTag.storedTarget}, opts, imageTagRoute.heldByAnotherOwner())
}
