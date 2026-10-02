package ownership

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/imageselector"
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

	imageTagDenyNoRepo        = "owner policy denied image tag without a repo parameter: there is no target reference to authorize"
	imageTagDenyAmbiguous     = "owner policy denied image tag with an ambiguous repo or tag parameter"
	imageTagDenyDigest        = "owner policy denied image tag whose repo carries a digest"
	imageTagDenyQualifiedRepo = "owner policy denied image tag whose repo already carries a tag beside a tag parameter"
	imageTagDenyInvalidRepo   = "owner policy denied image tag with a repo outside the image reference grammar"
	imageTagDenyInvalidTag    = "owner policy denied image tag with a tag outside the image reference grammar"
	imageTagDenyDigestName    = "owner policy denied image tag whose repo is a digest algorithm name: the engines read such a reference as an image ID"
	imageTagDenyTarget        = "owner policy denied image tag onto a reference that already names an image outside this owner"
)

// imageTagOwnershipReference is the second image a retag names: the reference
// the daemon will create or move. Exactly one of the two fields is set.
type imageTagOwnershipReference struct {
	// target is that reference as name:tag, always tag-qualified, spelled
	// the way the engine builds it. See imageTagTarget.
	target string
	// denyReason refuses a request whose target cannot be read the way the
	// daemon will read it.
	denyReason string
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
func imageTagOwnershipReferences(r *http.Request, normPath string) *ownershipRequestReferences {
	target, denyReason := imageTagTarget(r.URL.RawQuery, isLibpodOwnershipPath(normPath))
	return &ownershipRequestReferences{imageTag: &imageTagOwnershipReference{target: target, denyReason: denyReason}}
}

// imageTagTarget builds the reference a retag creates, as name:tag, or returns
// the reason the request is refused.
//
// The result follows moby's httputils.RepoTagReference, confirmed against
// dockerd 29.5.2, and is the same string Podman's compat.TagImage builds
// wherever Podman accepts the request at all:
//
//   - `repo` with no tag of its own and a `tag` parameter is repo:tag.
//   - `repo` with no tag and no `tag` parameter, or an empty one, is
//     repo:latest.
//   - `repo` that already carries a tag and no `tag` parameter keeps its own.
//     This is what docker-py sends for image.tag("name:v1"). Podman appends
//     ":latest" to it and rejects the result.
//
// The tag separator is a colon in the last path segment, so the port of
// "registry.example:5000/team/app" is not one. A single-segment
// "localhost:5000" is name "localhost" with tag "5000" to the reference
// parser, and is read that way here.
//
// On Podman's native route the name is then completed the way Podman stores
// it. See podmanStoredImageName.
//
// Refused, because the engines disagree with each other or with any reading
// this layer could check:
//
//   - A query net/url cannot parse cleanly. See imagePushOwnershipReferences.
//   - A repeated `repo` or `tag`, or any spelling of either key other than
//     the exact lowercase one. Both engines read the first value of the
//     exact key today (r.Form.Get), so this is narrower than they are on
//     purpose: one value under one spelling is the only shape whose reading
//     does not depend on which decoder the handler happens to use.
//   - No `repo`, or an empty one. dockerd answers 200 and does nothing,
//     Podman answers 400, and there is no target to authorize.
//   - A `repo` carrying a digest. dockerd refuses it today, and daemons from
//     before the check dropped the digest whenever a `tag` came with it.
//   - A `repo` that carries a tag next to a `tag` parameter. dockerd replaces
//     the tag `repo` spelled, Podman concatenates both and rejects the result.
//   - A name or tag outside the image reference grammar. The engines reject
//     those themselves, and refusing here keeps a string only one of them can
//     parse out of the inspect.
//   - A name that is a digest algorithm ("sha256"). The reference it builds,
//     sha256:<tag>, is an image ID to both engines' lookups, so the inspect
//     would answer for a different image than the tag names. dockerd and
//     libimage both refuse to create it.
func imageTagTarget(rawQuery string, libpod bool) (target, denyReason string) {
	query, err := imageselector.Parse(rawQuery)
	if err != nil {
		return "", imageTagDenyAmbiguous
	}
	repo, ok := exactQueryScalar(query, imageTagRepoQueryField)
	if !ok {
		return "", imageTagDenyAmbiguous
	}
	tag, ok := exactQueryScalar(query, imageTagTagQueryField)
	if !ok {
		return "", imageTagDenyAmbiguous
	}

	if repo == "" {
		return "", imageTagDenyNoRepo
	}
	if strings.Contains(repo, "@") {
		return "", imageTagDenyDigest
	}
	name := repo
	if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
		if tag != "" {
			return "", imageTagDenyQualifiedRepo
		}
		name, tag = repo[:colon], repo[colon+1:]
	} else if tag == "" {
		tag = imageTagDefaultTag
	}

	if len(name) > imageTagRepoMaxLen {
		return "", imageTagDenyInvalidRepo
	}
	match := imageTagRepoName.FindStringSubmatch(name)
	switch {
	case match == nil:
		return "", imageTagDenyInvalidRepo
	case !isImagePushTag(tag):
		return "", imageTagDenyInvalidTag
	case name == "sha256" || name == "sha384" || name == "sha512":
		return "", imageTagDenyDigestName
	}
	if libpod {
		if name, ok = podmanStoredImageName(name, match[1]); !ok {
			return "", imageTagDenyInvalidRepo
		}
	}
	return name + ":" + tag, ""
}

// podmanStoredImageName completes name the way Podman's native tag route
// stores it.
//
// That route hands repo:tag to libimage's Image.Tag with no lookup, and
// NormalizeName prefixes "localhost/" to any name whose domain, as the
// reference grammar captures it, has no "." or ":" and is not "localhost". A
// Docker-compatible inspect of the short name goes through short-name
// resolution instead, which tries a registries.conf alias ahead of
// localhost/. With both images present it would answer for the aliased image
// while the tag lands on the localhost/ one, so the inspect asks for the
// stored name, which no resolution rule applies to. Read from Podman 5.8.6
// and its libimage (go.podman.io/common v0.67.1).
//
// A short name whose first component carries an upper-case letter is refused.
// The grammar allows one only in a domain, and under localhost/ that
// component becomes part of the path, which Podman rejects.
//
// The Docker-compatible route is left as the client spelled it: dockerd has
// no such rule, and Podman's default compat_api_enforce_docker_hub resolves
// that route's target through the same lookup the inspect uses.
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
// they were.
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
	return checkImageTagTarget(ctx, inspectResource, refs.imageTag.target, opts)
}

// checkImageTagTarget authorizes the reference a retag points at its source.
//
// A reference no image holds yet is allowed: tagging it takes nothing from
// anyone, and it is what every first `docker tag` of a new name looks like.
// This is the one place a not-found inspect is not a denial, because the
// target is a name being created, not a resource being acted on.
//
// A reference an image already holds is being taken away from that image, so
// the image has to pass the same test as the subject of any other per-image
// request: the caller's own label always passes, another owner's never does,
// and no owner label at all follows allow_unowned_images. The flag already
// decides whether this caller may act on an unlabeled image, including
// removing one of its names through Podman's untag route, so a stricter rule
// here would not hold on a Podman upstream and would only add a second
// meaning to the option. With the flag at its default, a name held by an
// unlabeled image is therefore movable by any owner, the same way that image
// is usable, taggable and pushable by any owner. allow_unowned_images: false
// closes that for a deployment whose owners do not trust each other.
//
// Like every preflight inspect, this cannot close the window between the
// inspect and the daemon's write.
func checkImageTagTarget(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	target string,
	opts Options,
) (ownershipVerdict, string, error) {
	labels, found, err := inspectResource(ctx, dockerresource.KindImage, target)
	if err != nil {
		return verdictPassThrough, "", err
	}
	if !found || ownerMatches(labels, opts.LabelKey, opts.Owner, opts.AllowUnownedImages) {
		return verdictAllow, "", nil
	}
	return verdictDeny, imageTagDenyTarget, nil
}
