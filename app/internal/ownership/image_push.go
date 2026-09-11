package ownership

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

const (
	imagePushTagQueryField = "tag"

	imagePushDenyNoTag      = "owner policy denied image push without an explicit tag: it pushes every local tag of the repository"
	imagePushDenyAmbiguous  = "owner policy denied image push with an ambiguous tag parameter"
	imagePushDenyUnresolved = "owner policy could not resolve image"
)

// isImagePushRoutePath reports whether normPath is the Docker-compatible
// per-image push route, the one both dockerd and Podman's compat handler
// serve as POST /images/{name}/push. Podman's native POST
// /libpod/images/{name}/push carries the full reference (tag included) in
// the path itself, so it has no query tag to capture and stays out of scope
// here.
func isImagePushRoutePath(method, normPath string) bool {
	return method == http.MethodPost &&
		strings.HasPrefix(normPath, "/images/") &&
		strings.HasSuffix(normPath, "/push")
}

// imagePushOwnershipReferences reads the push query and returns either the
// tag qualifier the authorization pass appends to the path identifier, or
// the reason the request is refused outright.
//
// The Docker-compatible push route names its subject in two pieces: the
// repository in the path and the tag in ?tag=. imageIdentifier strips the
// "/push" suffix and hands back the bare repository, whose inspect resolves
// the daemon's default tag (typically :latest) — a reference that is neither
// the one the daemon will push nor a stable one the authorization can rely
// on. With a tag present, the authorization pass checks exactly
// {name}:{tag}; two shapes are refused rather than guessed at:
//
//   - No `tag` parameter at all. Moby's postImagesPush treats an empty tag
//     as "push every local tag of the repository", an effect one image
//     inspect cannot enumerate — the same reason imageEffectDenial refuses
//     per-image exports and deletes outright.
//   - A repeated or two-case-variant `tag`. Moby reads the first value of a
//     repeated parameter and Podman's compat handler the last, so a request
//     naming an owned tag and a foreign one would be checked against one and
//     pushed as the other. filter.FoldedScalarQueryValue is the same helper
//     the container-archive policy and commit's container parameter use for
//     this disagreement.
//
// The retag route POST /images/{name}/tag deliberately keeps its bare-path
// authorization: the resource it mutates is the source image the path names,
// and docker tag src dst spells the full source reference (tag included)
// into the path.
func imagePushOwnershipReferences(r *http.Request) *ownershipRequestReferences {
	refs := &ownershipRequestReferences{}
	tag, found, ambiguous := filter.FoldedScalarQueryValue(r.URL.Query(), imagePushTagQueryField)
	switch {
	case ambiguous:
		refs.denyReason = imagePushDenyAmbiguous
	case !found || strings.TrimSpace(tag) == "":
		refs.denyReason = imagePushDenyNoTag
	default:
		refs.imagePushTag = strings.TrimSpace(tag)
	}
	return refs
}

// appendImagePushTag qualifies a Docker-compatible push identifier with the
// captured tag, so checkOwnedResource inspects the exact local image the
// daemon will push. The refs must come from the same request; a nil refs (a
// direct caller of the authorization functions with no mutation pass behind
// it) leaves the identifier untouched.
func appendImagePushTag(identifier string, refs *ownershipRequestReferences, method, normPath string) string {
	if refs == nil || refs.imagePushTag == "" || !isImagePushRoutePath(method, normPath) {
		return identifier
	}
	return identifier + ":" + refs.imagePushTag
}
