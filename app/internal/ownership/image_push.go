package ownership

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/imageselector"
)

const (
	imagePushTagQueryField = "tag"

	imagePushDenyNoTag     = "owner policy denied image push without an explicit tag: it pushes every local tag of the repository"
	imagePushDenyAmbiguous = "owner policy denied image push with an ambiguous tag parameter"
	imagePushDenyFormBody  = "owner policy denied image push with a form-encoded request body: the daemon reads the tag from it"
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

// imagePushOwnershipReferences reads the push request and returns either the
// tag qualifier the authorization pass appends to the path identifier, or
// the reason the request is refused outright.
//
// The Docker-compatible push route names its subject in two pieces: the
// repository in the path and the tag in ?tag=. imageIdentifier strips the
// "/push" suffix and hands back the bare repository, whose inspect resolves
// the daemon's default tag (typically :latest) — a reference that is neither
// the one the daemon will push nor a stable one the authorization can rely
// on. With a tag present, the authorization pass checks exactly
// {name}:{tag}. That only holds while the tag read here is the tag the
// daemon reads, so every shape where the two can differ is refused rather
// than guessed at:
//
//   - A form-encoded request body. See imagePushHasFormBody.
//   - A query net/url cannot parse cleanly (a semicolon or a bad escape).
//     r.URL.Query() drops such a pair silently, current dockerd answers 400
//     for it, and a daemon built with a pre-1.17 Go runtime splits on the
//     semicolon and reads a tag out of the pair this layer never saw.
//   - No `tag` parameter at all, or an empty one. Moby's postImagesPush
//     treats an empty tag as "push every local tag of the repository", an
//     effect one image inspect cannot enumerate — the same reason
//     imageEffectDenial refuses per-image exports and deletes outright.
//   - A repeated `tag`. Moby reads the first value of a repeated parameter
//     and Podman's compat handler the last, so a request naming an owned tag
//     and a foreign one would be checked against one and pushed as the
//     other.
//   - Any spelling of the key other than the exact lowercase `tag`, even on
//     its own. Podman decodes the query with gorilla/schema, which folds
//     case, so it reads ?Tag=v1 as the tag. Dockerd reads r.Form.Get("tag")
//     and sees no tag, which is the push-every-tag shape above. This is where
//     the route parts ways with commit's container parameter, which can use
//     filter.FoldedScalarQueryValue: a commit dockerd finds no container for
//     is an error, while a push dockerd finds no tag for is a wider push.
//
// imageselector.Parse is used instead of r.URL.Query() because it keeps the
// exact key spelling and arrival order and reports what url.Values hides.
//
// The retag route POST /images/{name}/tag deliberately keeps its bare-path
// authorization: the resource it mutates is the source image the path names,
// and docker tag src dst spells the full source reference (tag included)
// into the path.
func imagePushOwnershipReferences(r *http.Request) *ownershipRequestReferences {
	refs := &ownershipRequestReferences{}
	if imagePushHasFormBody(r) {
		refs.denyReason = imagePushDenyFormBody
		return refs
	}
	query, err := imageselector.Parse(r.URL.RawQuery)
	if err != nil {
		refs.denyReason = imagePushDenyAmbiguous
		return refs
	}
	tag, found := "", false
	for _, field := range query {
		if !strings.EqualFold(field.Key, imagePushTagQueryField) {
			continue
		}
		if found || field.Key != imagePushTagQueryField {
			refs.denyReason = imagePushDenyAmbiguous
			return refs
		}
		tag, found = field.Value, true
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		refs.denyReason = imagePushDenyNoTag
		return refs
	}
	refs.imagePushTag = tag
	return refs
}

// imagePushHasFormBody reports whether the request declares a form-encoded
// body, which dockerd reads the tag from in preference to the query.
//
// Moby's postImagesPush calls httputils.ParseForm and then
// r.Form.Get("tag"). net/http's ParseForm parses an
// application/x-www-form-urlencoded POST body and puts its fields in r.Form
// ahead of the query string's, so ?tag=owned with a body of tag=foreign is
// authorized here as the owned tag and pushed as the foreign one, and a body
// of "tag=" turns it into a push of every tag. Verified against dockerd
// 29.5.2. Podman's handlers decode r.URL.Query() and never see the body.
//
// The match is deliberately wider than net/http's: it reads only the first
// Content-Type line and compares the parsed media type, while this refuses
// the substring on any line, so a header the daemon would parse differently
// from this layer cannot slip between the two. No client sends a form body on
// a push (the docker CLI sends none, docker-py sends a JSON "{}"), so nothing
// legitimate is narrowed.
func imagePushHasFormBody(r *http.Request) bool {
	for _, value := range r.Header.Values("Content-Type") {
		if strings.Contains(strings.ToLower(value), "x-www-form-urlencoded") {
			return true
		}
	}
	return false
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
