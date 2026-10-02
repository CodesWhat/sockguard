package ownership

import (
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/v2/app/internal/imageselector"
)

const (
	imagePushTagQueryField = "tag"

	imagePushDenyNoTag         = "owner policy denied image push without an explicit tag: it pushes every local tag of the repository"
	imagePushDenyAmbiguous     = "owner policy denied image push with an ambiguous tag parameter"
	imagePushDenyFormBody      = "owner policy denied image push with a form-encoded request body: the daemon reads the tag from it"
	imagePushDenyQualifiedName = "owner policy denied image push whose path already carries a tag or digest"
	imagePushDenyInvalidTag    = "owner policy denied image push with a tag outside the image reference grammar"

	// imagePushTagMaxLen is the tag length bound of the image reference
	// grammar (distribution/reference: [\w][\w.-]{0,127}).
	imagePushTagMaxLen = 128
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
//   - A path that already carries a tag or digest. See
//     imagePushNameIsQualified.
//   - A tag outside the image reference grammar. See isImagePushTag.
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
// The retag route POST /images/{name}/tag keeps its bare-path identifier for
// the source, because docker tag src dst spells the full source reference
// (tag included) into the path. Its `repo` and `tag` name a second image, the
// one the new reference is taken from, which imageTagOwnershipReferences
// authorizes separately.
func imagePushOwnershipReferences(r *http.Request, normPath string) *ownershipRequestReferences {
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
	tag, ok := exactQueryScalar(query, imagePushTagQueryField)
	if !ok {
		refs.denyReason = imagePushDenyAmbiguous
		return refs
	}
	switch {
	case tag == "":
		refs.denyReason = imagePushDenyNoTag
	case !isImagePushTag(tag):
		refs.denyReason = imagePushDenyInvalidTag
	case imagePushNameIsQualified(normPath):
		refs.denyReason = imagePushDenyQualifiedName
	default:
		refs.imagePushTag = tag
	}
	return refs
}

// isImagePushTag reports whether tag matches the image reference grammar's
// tag production, [\w][\w.-]{0,127} over ASCII, which is what dockerd's
// reference.WithTag enforces before it pushes anything.
//
// The value is compared as it arrived, with no trimming: a tag this layer
// tidied up before the inspect is not the tag that gets forwarded. Podman's
// compat handler does no validation of its own and concatenates the tag onto
// the name, so without this a value such as "v1@sha256:..." would be handed
// to the inspect as a reference whose meaning depends on the engine's lookup
// rules instead of on a tag.
func isImagePushTag(tag string) bool {
	if tag == "" || len(tag) > imagePushTagMaxLen {
		return false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case (c == '.' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// imagePushNameIsQualified reports whether the {name} of a push route already
// carries a tag or a digest.
//
// Dockerd does not append the query tag to such a name. reference.WithTag
// replaces the tag the path spelled, so /images/app:foreign/push?tag=owned
// pushes app:owned (verified against dockerd 29.5.2), and a digest in the
// path is an error on current daemons and a push by digest on older ones.
// Appending the tag here would build "app:foreign:owned", which the daemon
// answers with a 400 on inspect; that fails closed, but as a 502 and an
// error-level log line for a request the client fully controls. The docker
// CLI never sends this shape: it splits the reference and puts only the
// repository in the path.
//
// A colon counts only in the last path segment, because a registry port
// ("registry.example:5000/team/app") puts one earlier. A single-segment name
// with a colon ("localhost:5000") is read as name:tag by the reference
// parser, so it counts too.
func imagePushNameIsQualified(normPath string) bool {
	name := strings.TrimSuffix(strings.TrimPrefix(normPath, "/images/"), "/push")
	if strings.Contains(name, "@") {
		return true
	}
	return strings.Contains(name[strings.LastIndex(name, "/")+1:], ":")
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

// imagePushIdentifier qualifies a Docker-compatible push identifier with the
// captured tag, so checkOwnedResource inspects the exact local image the
// daemon will push. It returns false for a push route that reaches the
// authorization pass with no captured tag, which the caller refuses: falling
// back to the bare identifier would be the default-tag inspect this route was
// fixed to stop doing. Every other image route gets its identifier back
// untouched.
func imagePushIdentifier(identifier string, refs *ownershipRequestReferences, method, normPath string) (string, bool) {
	if !isImagePushRoutePath(method, normPath) {
		return identifier, true
	}
	if refs == nil || refs.imagePushTag == "" {
		return "", false
	}
	return identifier + ":" + refs.imagePushTag, true
}
