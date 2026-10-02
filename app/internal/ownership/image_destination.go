package ownership

import (
	"context"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// image_destination.go authorizes the image name a request writes.
//
// Several routes give an image a name: a retag, a commit, a build, an import,
// a load and a pull. Both engines move that name off whatever image held it.
// Moby's reference store and containerd image service overwrite the name, and
// c/storage's AddNames removes it from the other image first. A client that
// may run any of these routes could therefore take a name away from another
// owner's image, after which the name resolves to an image of the client's
// choosing for everyone who refers to it. Confirmed for retag, commit, the
// classic builder, import and load against dockerd 29.5.2, and read from moby
// 28.5.1 and Podman 5.8.6 for the rest.
//
// The name is a second subject of the request, next to whatever the path or
// the body names, so it is authorized only when this layer can read it exactly
// the way the daemon will, and every shape where the two readings can part is
// refused. Each route reads its own parameters. What they share is here: the
// reference those parameters build, the names it can land on, and the check
// against the image that holds it.

// imageDestination is one reference a request writes. See imageDestinationFor.
type imageDestination struct {
	// target is the reference as name:tag, always tag-qualified, spelled the
	// way the engine builds it.
	target string
	// storedTarget is a second name the same request can land on, set only
	// when the daemon may store the reference under another name than the one
	// target spells. Both have to pass. See imageTagNamedEitherWay.
	storedTarget string
}

// imageDestinationRoute words the refusals of one name-assigning route.
type imageDestinationRoute struct {
	// action is the request as the reason names it: "image tag", "commit".
	action string
	// field is what the name was read from: "repo", "t parameter".
	field string
}

// imageDestinationProblem is why a destination cannot be read the way the
// daemon reads it.
type imageDestinationProblem int

const (
	imageDestinationReadable imageDestinationProblem = iota
	imageDestinationHasDigest
	imageDestinationTaggedTwice
	imageDestinationBadName
	imageDestinationBadTag
	imageDestinationDigestName
)

// refusal is the deny reason for a destination this layer will not read.
func (route imageDestinationRoute) refusal(problem imageDestinationProblem) string {
	denied := "owner policy denied " + route.action
	switch problem {
	case imageDestinationHasDigest:
		return denied + " whose " + route.field + " carries a digest"
	case imageDestinationTaggedTwice:
		return denied + " whose " + route.field + " already carries a tag beside a tag parameter"
	case imageDestinationBadName:
		return denied + " with a " + route.field + " outside the image reference grammar"
	case imageDestinationBadTag:
		return denied + " with a tag outside the image reference grammar"
	case imageDestinationDigestName:
		return denied + " whose " + route.field + " is a digest algorithm name: the engines read such a reference as an image ID"
	default:
		return ""
	}
}

// heldByAnotherOwner is the deny reason for a destination another owner's
// image holds.
func (route imageDestinationRoute) heldByAnotherOwner() string {
	return "owner policy denied " + route.action + " onto a reference that already names an image outside this owner"
}

// imageDestinationReferences is every reference one request writes, captured
// by the mutation pass for the authorization pass.
type imageDestinationReferences struct {
	route        imageDestinationRoute
	destinations []imageDestination
}

// add records dest once. A build can name the same reference twice, and one
// inspect answers for both.
func (refs *imageDestinationReferences) add(dest imageDestination) {
	for _, known := range refs.destinations {
		if known == dest {
			return
		}
	}
	refs.destinations = append(refs.destinations, dest)
}

// imageDestinationFor builds the reference a request writes from the name the
// client spelled and the tag it sent beside it, or reports why it cannot. tag
// is empty on a route that has no separate tag parameter, where the name
// carries its own.
//
// The result follows moby's httputils.RepoTagReference, which the retag,
// commit and import handlers all call, and its build tag sanitizer, which
// parses each name the same way. It is the same string Podman builds wherever
// Podman accepts the request at all:
//
//   - A name with no tag of its own and a tag beside it is name:tag.
//   - A name with no tag and no tag beside it, or an empty one, is
//     name:latest.
//   - A name that already carries a tag and no tag beside it keeps its own.
//     This is what docker-py sends for image.tag("name:v1"). Podman's retag
//     and commit append ":latest" to it and reject the result.
//
// The tag separator is a colon in the last path segment, so the port of
// "registry.example:5000/team/app" is not one. A single-segment
// "localhost:5000" is name "localhost" with tag "5000" to the reference
// parser, and is read that way here.
//
// naming decides which names the reference is checked under. Named as stored,
// the name is completed the way Podman stores it and that is the target.
// Named either way, the target stays as spelled and the completed name comes
// back as storedTarget, unless the name spells its registry and the two are
// the same. See podmanStoredImageName and imageTagNamedEitherWay.
//
// Refused, because the engines disagree with each other or with any reading
// this layer could check:
//
//   - A name carrying a digest. dockerd refuses it today, and daemons from
//     before the check dropped the digest whenever a tag came with it.
//   - A name that carries a tag next to a tag parameter. dockerd replaces the
//     tag the name spelled, Podman concatenates both and rejects the result.
//   - A name or tag outside the image reference grammar. The engines reject
//     those themselves, and refusing here keeps a string only one of them can
//     parse out of the inspect. That includes a name that only outgrows the
//     length bound once the engine completes it: one with no slash that
//     dockerd reads as library/<name>, and a short one Podman stores under
//     localhost/. Either would have the inspect answer with an error, which
//     is a 502 a client could produce at will. The Podman bound applies on
//     its Docker-compatible routes too, where the default setting completes
//     the name to docker.io/<name> instead: that is no shorter than
//     localhost/<name>, so Podman accepts such a name under neither setting.
//     It also keeps a transport out of a Podman build tag: buildah writes an
//     output such as "dir:/path" or "docker://registry/name" to that
//     transport, and neither matches the grammar.
//   - A name that is a digest algorithm: "sha256", "sha384" or "sha512". The
//     reference it builds, <algorithm>:<tag>, can be a well-formed digest,
//     and a lookup that parses it as one searches by image ID instead of by
//     name, so the inspect could answer for a different image than the one
//     the request names, or for none. Both engines' lookups read
//     sha256:<hex> that way, and dockerd and libimage both refuse to create a
//     tag named "sha256". Neither refuses "sha384" or "sha512", whose 96 and
//     128 character hex values fit the tag grammar and still parse as digests
//     to dockerd's reference parser. This layer refuses all three, because
//     the inspect has no way to ask for such a reference by name.
func imageDestinationFor(repo, tag string, naming imageTagNaming) (imageDestination, imageDestinationProblem) {
	if strings.Contains(repo, "@") {
		return imageDestination{}, imageDestinationHasDigest
	}
	name := repo
	if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
		if tag != "" {
			return imageDestination{}, imageDestinationTaggedTwice
		}
		name, tag = repo[:colon], repo[colon+1:]
	} else if tag == "" {
		tag = imageTagDefaultTag
	}

	if len(name) > imageTagRepoMaxLen || (len(name) > imageTagBareRepoMaxLen && !strings.Contains(name, "/")) {
		return imageDestination{}, imageDestinationBadName
	}
	match := imageTagRepoName.FindStringSubmatch(name)
	switch {
	case match == nil:
		return imageDestination{}, imageDestinationBadName
	case !isImagePushTag(tag):
		return imageDestination{}, imageDestinationBadTag
	case name == "sha256" || name == "sha384" || name == "sha512":
		return imageDestination{}, imageDestinationDigestName
	}
	if naming == imageTagNamedAsSpelled {
		return imageDestination{target: name + ":" + tag}, imageDestinationReadable
	}
	stored, ok := podmanStoredImageName(name, match[1])
	if !ok || len(stored) > imageTagRepoMaxLen {
		return imageDestination{}, imageDestinationBadName
	}
	if naming == imageTagNamedAsStored || stored == name {
		return imageDestination{target: stored + ":" + tag}, imageDestinationReadable
	}
	return imageDestination{target: name + ":" + tag, storedTarget: stored + ":" + tag}, imageDestinationReadable
}

// imageNameSpellsRegistry reports whether name, a repository with no tag,
// starts with a registry. A name that does means one reference to both
// engines. One that does not is a short name, which Podman completes from
// local state or from registries.conf. See podmanStoredImageName.
func imageNameSpellsRegistry(name string) bool {
	match := imageTagRepoName.FindStringSubmatch(name)
	return match != nil && (strings.ContainsAny(match[1], ".:") || match[1] == "localhost")
}

// checkImageDestinations authorizes every reference a request writes. The
// first denial or failed lookup ends it.
func checkImageDestinations(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	refs *imageDestinationReferences,
	opts Options,
) (ownershipVerdict, string, error) {
	if refs == nil {
		return verdictPassThrough, "", nil
	}
	strictest := verdictPassThrough
	for _, dest := range refs.destinations {
		verdict, reason, err := checkImageDestination(ctx, inspectResource, dest, opts, refs.route.heldByAnotherOwner())
		if err != nil || verdict.denied() {
			return verdict, reason, err
		}
		strictest = verdictAllow
	}
	return strictest, "", nil
}

// checkImageDestination authorizes one reference a request writes. Where the
// reference can land on either of two names, each is checked on the same
// terms.
//
// A reference no image holds yet is allowed: writing it takes nothing from
// anyone, and it is what every first `docker tag` or `docker build -t` of a
// new name looks like. This is the one place a not-found inspect is not a
// denial, because the destination is a name being created, not a resource
// being acted on.
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
func checkImageDestination(
	ctx context.Context,
	inspectResource func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error),
	dest imageDestination,
	opts Options,
	denyReason string,
) (ownershipVerdict, string, error) {
	for _, target := range [...]string{dest.target, dest.storedTarget} {
		if target == "" {
			continue
		}
		labels, found, err := inspectResource(ctx, dockerresource.KindImage, target)
		if err != nil {
			return verdictPassThrough, "", err
		}
		if found && !ownerMatches(labels, opts.LabelKey, opts.Owner, opts.AllowUnownedImages) {
			return verdictDeny, denyReason, nil
		}
	}
	return verdictAllow, "", nil
}
