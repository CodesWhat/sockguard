package ownership

import (
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/imageselector"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const (
	imageCreatePath       = "/images/create"
	libpodImageImportPath = libpodPrefix + "images/import"

	imageCreateFromImageQueryField    = "fromImage"
	libpodImageReferenceQueryField    = "reference"
	imageCreateDenyAmbiguous          = "owner policy denied image create with an ambiguous fromImage, repo or tag parameter"
	libpodImageImportDenyAmbiguousRef = "owner policy denied image import with an ambiguous reference parameter"
)

// The routes that make an image from outside the daemon and name it. See
// imageDestinationRoute.
var (
	imageImportRoute       = imageDestinationRoute{action: "image import", field: "repo"}
	libpodImageImportRoute = imageDestinationRoute{action: "image import", field: libpodImageReferenceQueryField}
)

// isImageCreateRoutePath reports whether normPath is a route that brings an
// image in from outside the daemon and names it from the query: the
// Docker-compatible POST /images/create, which both engines serve, and
// Podman's native POST /libpod/images/import.
func isImageCreateRoutePath(method, normPath string) bool {
	return method == http.MethodPost && (normPath == imageCreatePath || normPath == libpodImageImportPath)
}

// imageCreateOwnershipReferences reads the name such a request gives its
// image, for the authorization pass.
func imageCreateOwnershipReferences(r *http.Request, normPath string, flavor upstreamflavor.Flavor) *ownershipRequestReferences {
	query, err := imageselector.Parse(r.URL.RawQuery)
	if err != nil {
		reason := imageCreateDenyAmbiguous
		if normPath == libpodImageImportPath {
			reason = libpodImageImportDenyAmbiguousRef
		}
		return &ownershipRequestReferences{denyReason: reason}
	}
	var (
		destinations *imageDestinationReferences
		denyReason   string
	)
	if normPath == libpodImageImportPath {
		destinations, denyReason = libpodImageImportDestination(query)
	} else {
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
		return nil, ""
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
