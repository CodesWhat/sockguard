package ownership

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/upstreamflavor"
)

const (
	imageLoadPath       = "/images/load"
	libpodImageLoadPath = libpodPrefix + "images/load"

	// imageLoadMaxNames bounds the names one load is checked for, the way
	// buildMaxTags bounds a build. An archive's manifest can list far more.
	imageLoadMaxNames = buildMaxTags

	// imageLoadUntaggedName is the placeholder a Docker archive carries for
	// an image with no name.
	imageLoadUntaggedName = "<none>:<none>"

	imageLoadDenyUninspected  = "owner policy denied image load whose archive was not inspected for image names: request_body.image_load reads them"
	imageLoadDenyUnreadable   = "owner policy denied image load of an archive in no format its image names can be read from"
	imageLoadDenyTooManyNames = "owner policy denied image load of an archive with more image names than it can authorize"
)

// imageLoadRoute words the refusals of a load's image names. See
// imageDestinationRoute.
var imageLoadRoute = imageDestinationRoute{action: "image load", field: "name"}

// isImageLoadRoutePath reports whether normPath is an image load that carries
// its archive in the body: the Docker-compatible POST /images/load, which
// both engines serve, and Podman's native POST /libpod/images/load.
//
// POST /libpod/local/images/load is not matched. It names an archive by a
// path on the daemon's host, so there is no body for anyone to read a name
// out of, and the filter admits it only under
// insecure_allow_body_blind_writes, which is the operator saying so.
func isImageLoadRoutePath(method, normPath string) bool {
	return method == http.MethodPost && (normPath == imageLoadPath || normPath == libpodImageLoadPath)
}

// imageLoadOwnershipReferences reads the names a load gives its images, for
// the authorization pass. The names are in the archive, which the filter's
// image-load inspector has already spooled and parsed on the way here. It
// leaves what it read on the request metadata, and this reads that instead of
// the body. See logging.ImageLoadRecord.
func imageLoadOwnershipReferences(r *http.Request, normPath string, flavor upstreamflavor.Flavor) *ownershipRequestReferences {
	var record *logging.ImageLoadRecord
	if meta := logging.Meta(r.Context()); meta != nil {
		record = meta.ImageLoad
	}
	destinations, denyReason := imageLoadDestinations(record, normPath, flavor)
	return &ownershipRequestReferences{imageDestinations: destinations, denyReason: denyReason}
}

// imageLoadDestinations builds the references a load writes from the names
// its archive carries, or returns the reason the request is refused.
//
// A load is the one route where the client supplies everything: the content,
// the names, and the labels, the owner label among them. Both engines point
// each name at the loaded image and off whatever held it. So a client could
// load an archive naming another owner's image and labeled as that owner's:
// the name then resolves to the client's content and still passes every
// ownership check its real owner makes. Confirmed against dockerd 29.5.2.
//
// Where a name lands:
//
//   - dockerd holds it as the archive spells it. The classic store reads
//     manifest.json's RepoTags, and the containerd store reads the name
//     annotation of each index.json entry. The record carries both sets when
//     the archive has both, and each is checked.
//   - Podman completes every name with libimage's NormalizeName, on both
//     routes and for both archive formats, so a name with no registry is
//     stored under localhost/ without a lookup. The native route is checked
//     as stored. The compat route is checked the way a retag there is: as
//     spelled on dockerd, and under both names when the upstream is or may be
//     Podman.
//
// A name with a digest and no tag (what `docker save name@sha256:...` writes)
// gives the image no tag and has no destination. An entry with no name, or
// the "<none>:<none>" placeholder, names nothing.
//
// Refused: a load whose archive nobody inspected, which is a request that
// reached this layer without passing the filter's inspector; an archive in
// neither format, which request_body.image_load.allow_untagged admits
// unread, and which a daemon may still find names in (moby's classic store
// falls back to the legacy `repositories` file when there is no
// manifest.json); more names than imageLoadMaxNames; and every name
// imageDestinationFor refuses. Read from moby 28.5.1 and libimage
// (go.podman.io/common v0.67.1).
func imageLoadDestinations(record *logging.ImageLoadRecord, normPath string, flavor upstreamflavor.Flavor) (*imageDestinationReferences, string) {
	switch {
	case record == nil:
		return nil, imageLoadDenyUninspected
	case record.Unreadable:
		return nil, imageLoadDenyUnreadable
	}
	naming := imageTagNamedAsStored
	if !isLibpodOwnershipPath(normPath) {
		naming = imageTagNamingFor(flavor)
	}

	refs := &imageDestinationReferences{route: imageLoadRoute}
	names := 0
	for _, name := range record.References {
		if name == "" || name == imageLoadUntaggedName {
			continue
		}
		if names++; names > imageLoadMaxNames {
			return nil, imageLoadDenyTooManyNames
		}
		if repository, digest, digested := strings.Cut(name, "@"); digested {
			if problem := imageDigestedNameProblem(repository, digest, naming); problem != imageDestinationReadable {
				return nil, imageLoadRoute.refusal(problem)
			}
			continue
		}
		dest, problem := imageDestinationFor(name, "", naming)
		if problem != imageDestinationReadable {
			return nil, imageLoadRoute.refusal(problem)
		}
		refs.add(dest)
	}
	if len(refs.destinations) == 0 {
		return nil, ""
	}
	return refs, ""
}
