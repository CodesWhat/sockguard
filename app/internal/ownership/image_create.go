package ownership

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/imageselector"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const (
	imageCreatePath       = "/images/create"
	libpodImageImportPath = libpodPrefix + "images/import"
	libpodImagePullPath   = libpodPrefix + "images/pull"

	imageCreateFromImageQueryField = "fromImage"
	imageCreatePlatformQueryField  = "platform"
	libpodImageReferenceQueryField = "reference"
	libpodImagePullAllTagsField    = "allTags"

	// libpodImagePullTransportPrefix is the one transport Podman's native
	// pull accepts in front of a reference (utils.IsRegistryReference).
	libpodImagePullTransportPrefix = "docker://"

	imageCreateDenyAmbiguous          = "owner policy denied image create with an ambiguous fromImage, repo or tag parameter"
	libpodImageImportDenyAmbiguousRef = "owner policy denied image import with an ambiguous reference parameter"
	libpodImagePullDenyAmbiguousRef   = "owner policy denied image pull with an ambiguous reference parameter"

	imagePullDenyNoTag        = "owner policy denied image pull without a tag or digest: dockerd pulls every tag of the repository"
	imagePullDenyAllTags      = "owner policy denied image pull of every tag of a repository"
	imagePullDenyTagAndDigest = "owner policy denied image pull that names both a tag and a digest"
	imagePullDenyDigest       = "owner policy denied image pull with a digest outside the digest grammar"
	imagePullDenyPlatform     = "owner policy denied image pull of a name with no registry for a named platform: Podman resolves it through registries.conf, so spell the registry"
)

// The routes that bring an image in from outside the daemon and name it. See
// imageDestinationRoute.
var (
	imageImportRoute       = imageDestinationRoute{action: "image import", field: "repo"}
	libpodImageImportRoute = imageDestinationRoute{action: "image import", field: libpodImageReferenceQueryField}
	imagePullRoute         = imageDestinationRoute{action: "image pull", field: imageCreateFromImageQueryField}
	libpodImagePullRoute   = imageDestinationRoute{action: "image pull", field: libpodImageReferenceQueryField}
)

// libpodImagePullPlatformFields are the parameters of Podman's native pull
// that name a platform.
var libpodImagePullPlatformFields = [...]string{"Arch", "OS", "Variant"}

// isImageCreateRoutePath reports whether normPath is a route that brings an
// image in from outside the daemon and names it from the query: the
// Docker-compatible POST /images/create, which both engines serve, and
// Podman's native POST /libpod/images/import and POST /libpod/images/pull.
func isImageCreateRoutePath(method, normPath string) bool {
	if method != http.MethodPost {
		return false
	}
	return normPath == imageCreatePath || normPath == libpodImageImportPath || normPath == libpodImagePullPath
}

// imageCreateOwnershipReferences reads the name such a request gives its
// image, for the authorization pass.
func imageCreateOwnershipReferences(r *http.Request, normPath string, flavor upstreamflavor.Flavor) *ownershipRequestReferences {
	query, err := imageselector.Parse(r.URL.RawQuery)
	if err != nil {
		reason := imageCreateDenyAmbiguous
		switch normPath {
		case libpodImageImportPath:
			reason = libpodImageImportDenyAmbiguousRef
		case libpodImagePullPath:
			reason = libpodImagePullDenyAmbiguousRef
		}
		return &ownershipRequestReferences{denyReason: reason}
	}
	var (
		destinations *imageDestinationReferences
		denyReason   string
	)
	switch normPath {
	case libpodImageImportPath:
		destinations, denyReason = libpodImageImportDestination(query)
	case libpodImagePullPath:
		destinations, denyReason = libpodImagePullDestination(query)
	default:
		destinations, denyReason = imageCreateDestination(query, flavor)
	}
	return &ownershipRequestReferences{imageDestinations: destinations, denyReason: denyReason}
}

// imageCreateDestination reads the name POST /images/create writes, or
// returns the reason the request is refused.
//
// The route is two operations. Both engines pull when `fromImage` is set and
// import otherwise: dockerd branches on the value in one handler, and Podman
// routes on the parameter to one of two. An empty `fromImage` is an import to
// dockerd and an error to Podman, so it is read as an import here.
//
// `fromImage`, `repo` and `tag` are each read as one value under the exact
// key. A repeated one, or one in any other spelling, is refused: dockerd reads
// the first value of the exact key, and Podman's decoder folds the key's case
// and keeps the last.
func imageCreateDestination(query imageselector.Query, flavor upstreamflavor.Flavor) (*imageDestinationReferences, string) {
	fromImage, ok := exactQueryScalar(query, imageCreateFromImageQueryField)
	if !ok {
		return nil, imageCreateDenyAmbiguous
	}
	repo, ok := exactQueryScalar(query, imageTagRepoQueryField)
	if !ok {
		return nil, imageCreateDenyAmbiguous
	}
	tag, ok := exactQueryScalar(query, imageTagTagQueryField)
	if !ok {
		return nil, imageCreateDenyAmbiguous
	}
	if fromImage != "" {
		return imagePullDestination(imagePullRoute, fromImage, tag, imageTagNamingFor(flavor), queryNamesAny(query, imageCreatePlatformQueryField))
	}
	return imageImportDestination(repo, tag, flavor)
}

// imageImportDestination reads the name an import gives the image it makes.
//
// An import makes an image from a tarball in the body, or from a URL the
// daemon fetches, and `repo` and `tag` name it. Both engines move that name
// off whatever image held it. The image an import makes carries no owner
// label unless the client sets one, so the name ends up on an image every
// owner may use while allow_unowned_images is at its default: the image that
// held it loses the name, and its owner goes on to run whatever was imported.
// Confirmed against dockerd 29.5.2.
//
// dockerd builds the reference with httputils.RepoTagReference, the call its
// retag handler makes, and Podman's compat handler builds repo:tag and tags
// through libimage's Image.Tag, the way its retag does. So the name is read by
// imageDestinationFor and checked under the names a retag on this route is.
// An import with no `repo` makes an image with no name and has no
// destination. Read from moby 28.5.1 and Podman 5.8.6.
func imageImportDestination(repo, tag string, flavor upstreamflavor.Flavor) (*imageDestinationReferences, string) {
	if repo == "" {
		return nil, ""
	}
	dest, problem := imageDestinationFor(repo, tag, imageTagNamingFor(flavor))
	if problem != imageDestinationReadable {
		return nil, imageImportRoute.refusal(problem)
	}
	refs := &imageDestinationReferences{route: imageImportRoute}
	refs.add(dest)
	return refs, ""
}

// libpodImageImportDestination reads the name Podman's native import gives
// the image it makes, or returns the reason the request is refused.
//
// The route takes the whole reference in `reference` and tags the imported
// image through libimage's Image.Tag, which stores a name with no registry
// under localhost/ without looking anything up. That is what a native retag
// does, so the name is checked the same way, as stored. An import with no
// `reference` has no destination.
//
// `reference` is read as one value under the exact key. Podman decodes it
// with gorilla/schema, which folds the key's case and keeps the last value,
// so a repeated one or one in another spelling is refused instead of guessed
// at. Read from Podman 5.8.6 (pkg/api/handlers/libpod.ImagesImport).
func libpodImageImportDestination(query imageselector.Query) (*imageDestinationReferences, string) {
	reference, ok := exactQueryScalar(query, libpodImageReferenceQueryField)
	if !ok {
		return nil, libpodImageImportDenyAmbiguousRef
	}
	if reference == "" {
		return nil, ""
	}
	dest, problem := imageDestinationFor(reference, "", imageTagNamedAsStored)
	if problem != imageDestinationReadable {
		return nil, libpodImageImportRoute.refusal(problem)
	}
	refs := &imageDestinationReferences{route: libpodImageImportRoute}
	refs.add(dest)
	return refs, ""
}

// imagePullDestination reads the local name a pull writes, or returns the
// reason the request is refused. name is the reference as the client spelled
// it and tag the separate tag parameter, which only the Docker-compatible
// route has.
//
// A pull is a write to the local store as well as a read from a registry:
// whatever the registry serves under the name replaces whatever image held it
// locally. Both engines force that. Moby's reference store and containerd
// image service overwrite the name, and Podman's copy into c/storage takes it
// from the image that had it. So a client could move a name another owner had
// built, committed or tagged locally by pulling it. It does not choose the
// content unless it can also push under that name, but the name moves either
// way: at the least the other owner's image is swapped for the registry's
// copy, an older one if they had rebuilt since pushing, and where the name is
// one the client does control upstream (a local `team/app` nobody registered
// on Docker Hub) the content is the client's. A pulled image is not stamped.
// It carries whatever labels the registry copy has, usually none, so the
// other owner goes on to run it while allow_unowned_images is at its default.
//
// Overwriting a name by pulling is also what every `docker pull` of a moving
// tag does, and it stays allowed where it takes nothing from another owner.
// The name is checked like a retag target: nothing holds it, the caller's own
// image holds it, or an unlabeled one does and allow_unowned_images is on. A
// refresh of a shared base image is the last case. Only a name another
// owner's labeled image holds is refused, and that is a name this caller
// could not have used anyway.
//
// How each engine builds the reference:
//
//   - dockerd keeps a tag carried in the name unless `tag` replaces it, reads
//     a `tag` that parses as a digest as a pull by digest, and with neither
//     pulls every tag the registry lists for the repository.
//   - Podman joins the name and `tag` with ":" or "@" and rejects a name that
//     then carries two tags. A bare name is :latest.
//
// Where the name lands on Podman depends on local state. A name some local
// image holds is pulled under that image's name, alias first, and the inspect
// of the name as spelled resolves the same way, so it answers for the image
// the pull replaces. A name nothing holds lands on a name nothing holds. That
// is exact, and the second name a short name is also checked under only ever
// refuses.
//
// Refused, beyond what imageDestinationFor refuses:
//
//   - A name with no tag and no digest. On dockerd that is a pull of every
//     tag, which one inspect cannot enumerate, the same reason a push without
//     a tag is refused. It is refused on Podman too, where it would mean
//     :latest: the flavor is a setting, and spelling the tag costs nothing.
//   - A name carrying a digest next to a tag, in either parameter. dockerd
//     pulls by the digest and the engines differ on what happens to the tag.
//   - A digest outside the digest grammar: an algorithm other than sha256,
//     sha384 or sha512, or hex of the wrong length or case. The engines read
//     such a value as a tag and reject it.
//   - On an upstream that is or may be Podman, a name with no registry on a
//     request that names a platform. Podman then skips the local lookup and
//     resolves the name through registries.conf, which this layer cannot
//     read, so the pull can land on a name the inspect never asked about.
//
// A pull by digest writes no tag on either engine and has no destination.
// Read from moby 28.5.1 and from Podman 5.8.6 and its libimage
// (go.podman.io/common v0.67.1, copySingleImageFromRegistry).
func imagePullDestination(route imageDestinationRoute, name, tag string, naming imageTagNaming, namesPlatform bool) (*imageDestinationReferences, string) {
	repository, digest, digested := strings.Cut(name, "@")
	switch {
	case digested && tag != "":
		return nil, imagePullDenyTagAndDigest
	case !digested && isImageDigest(tag):
		repository, digest, digested, tag = name, tag, true, ""
	}
	if digested {
		// The tag stands in for the one a name pulled by digest must not
		// carry, so a name that does carry one is reported the usual way.
		switch _, problem := imageDestinationFor(repository, imageTagDefaultTag, naming); {
		case problem == imageDestinationTaggedTwice:
			return nil, imagePullDenyTagAndDigest
		case problem != imageDestinationReadable:
			return nil, route.refusal(problem)
		case !isImageDigest(digest):
			return nil, imagePullDenyDigest
		}
		return nil, ""
	}

	carriesTag := strings.LastIndex(name, ":") > strings.LastIndex(name, "/")
	if tag == "" && !carriesTag {
		return nil, imagePullDenyNoTag
	}
	dest, problem := imageDestinationFor(name, tag, naming)
	if problem != imageDestinationReadable {
		return nil, route.refusal(problem)
	}
	if naming != imageTagNamedAsSpelled && namesPlatform && !imageNameSpellsRegistry(dest.target[:strings.LastIndex(dest.target, ":")]) {
		return nil, imagePullDenyPlatform
	}
	refs := &imageDestinationReferences{route: route}
	refs.add(dest)
	return refs, ""
}

// libpodImagePullDestination reads the local name Podman's native pull
// writes, or returns the reason the request is refused.
//
// The route takes the whole reference in `reference`, optionally behind the
// docker:// transport, and pulls it through the same libimage code as the
// compat route, so imagePullDestination reads it with no tag beside it. It is
// checked as spelled and, for a name with no registry, under localhost/.
//
// Refused here: a repeated `reference` or one in another spelling, which
// Podman's decoder would fold and take the last of, an `allTags` in any
// spelling that is not plainly false, because that pulls every tag the
// registry lists, and a bare name, which this route would pull as :latest but
// which is refused for the reason imagePullDestination gives. A request with
// no `reference` is an error to Podman and has no destination. Read from
// Podman 5.8.6 (pkg/api/handlers/libpod.ImagesPull).
func libpodImagePullDestination(query imageselector.Query) (*imageDestinationReferences, string) {
	reference, ok := exactQueryScalar(query, libpodImageReferenceQueryField)
	if !ok {
		return nil, libpodImagePullDenyAmbiguousRef
	}
	for _, field := range query {
		if !strings.EqualFold(field.Key, libpodImagePullAllTagsField) || field.Value == "" {
			continue
		}
		if all, err := strconv.ParseBool(field.Value); err != nil || all {
			return nil, imagePullDenyAllTags
		}
	}
	if reference == "" {
		return nil, ""
	}
	reference = strings.TrimPrefix(reference, libpodImagePullTransportPrefix)
	return imagePullDestination(libpodImagePullRoute, reference, "", imageTagNamedEitherWay, queryNamesAny(query, libpodImagePullPlatformFields[:]...))
}

// queryNamesAny reports whether query carries a non-empty value under any of
// keys, in any spelling of them. It is for a parameter whose presence matters
// more than its value, read the way the more permissive decoder reads it.
func queryNamesAny(query imageselector.Query, keys ...string) bool {
	for _, field := range query {
		if field.Value == "" {
			continue
		}
		for _, key := range keys {
			if strings.EqualFold(field.Key, key) {
				return true
			}
		}
	}
	return false
}

// isImageDigest reports whether value is a digest both engines' parsers
// accept (opencontainers/go-digest): sha256, sha384 or sha512, a colon, and
// lowercase hex of exactly that algorithm's length. Nothing else parses as a
// digest there, and no such string is a valid tag, so a `tag` parameter is
// one or the other.
func isImageDigest(value string) bool {
	algorithm, encoded, found := strings.Cut(value, ":")
	if !found {
		return false
	}
	var length int
	switch algorithm {
	case "sha256":
		length = 64
	case "sha384":
		length = 96
	case "sha512":
		length = 128
	default:
		return false
	}
	if len(encoded) != length {
		return false
	}
	for i := 0; i < len(encoded); i++ {
		if c := encoded[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
