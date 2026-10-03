package ownership

import (
	"encoding/json"
	"strings"

	"github.com/codeswhat/sockguard/v2/app/internal/imageselector"
	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
)

const (
	buildTagQueryField      = "t"
	buildOutputsQueryField  = "outputs"
	buildManifestQueryField = "manifest"

	// buildMaxTags bounds the names one build is checked for. Each costs up
	// to two inspects, and the query is the client's to fill. It is the bound
	// the image batch routes already use (imageselector's reference limit).
	buildMaxTags = 256

	buildDenyUnreadableQuery = "owner policy denied build with a query that cannot be parsed cleanly"
	buildDenyAmbiguousTag    = "owner policy denied build with a t parameter spelled in another case: the engines disagree on whether it names the image"
	buildDenyTooManyTags     = "owner policy denied build with more t parameters than it can authorize"
	buildDenyTransport       = "owner policy denied build whose t parameter starts with an image transport name: Podman's builder writes such an output outside the name it spells"
	buildDenyOutputs         = "owner policy denied build with an outputs parameter that cannot be decoded"
	buildDenyOutputName      = "owner policy denied build whose outputs parameter names an image: name the image in t"
	buildDenyManifest        = "owner policy denied build with a manifest parameter: Podman adds the image to the manifest list it names"
)

// buildRoute words the refusals of a build's image names. See
// imageDestinationRoute.
var buildRoute = imageDestinationRoute{action: "build", field: "t parameter"}

// buildOutputTransports are the names containers/image registers as image
// transports (go.podman.io/image/v5 5.39.2, transports/alltransports, plus the
// storage and docker-daemon ones registered beside it). "docker" is left out:
// that transport only takes a reference starting with "//", which is not an
// image name, so "docker:dind" stays the image it reads as. See
// buildTagIsTransport.
var buildOutputTransports = map[string]struct{}{
	"atomic":             {},
	"containers-storage": {},
	"dir":                {},
	"docker-archive":     {},
	"docker-daemon":      {},
	"oci":                {},
	"oci-archive":        {},
	"ostree":             {},
	"sif":                {},
	"tarball":            {},
}

// buildImageDestinations reads every name a build gives its image, or returns
// the reason the request is refused. It reads the query as it arrived, before
// the owner label is written into it.
//
// A build is stamped with the caller's owner label, and until this check that
// was all ownership did with it. The names went through unread, and both
// engines move each one off whatever image held it, so `docker build -t` onto
// a name another owner's image held took the name from that image. Confirmed
// against dockerd 29.5.2 with the classic builder.
//
// `t` names the image, once per value:
//
//   - dockerd reads every value of the exact key (r.Form["t"]), skips an empty
//     one, refuses a digest, and completes a name with no tag to :latest. The
//     classic builder and BuildKit share that sanitizer.
//   - Podman serves POST /build and POST /libpod/build on one handler and
//     decodes `t` with gorilla/schema, which folds the key's case. The first
//     value is buildah's output and the rest are tagged through libimage's
//     Image.Tag, so a name with no registry is stored under localhost/ on the
//     native route, and on the compat one it depends on
//     compat_api_enforce_docker_hub, the way a retag's target does.
//
// Each value is therefore a whole reference with no tag parameter beside it,
// built by imageDestinationFor under the naming a retag on the same route
// gets. A build that names nothing has no destination.
//
// Refused, beyond what imageDestinationFor refuses:
//
//   - A query net/url cannot parse cleanly. The label stamp rewrites the query
//     from the pairs that did parse, so nothing is lost by refusing here, and
//     it keeps this route on the one reading the others have.
//   - `t` in any spelling but the exact lowercase one. dockerd ignores `T`
//     and Podman reads it as a tag, and with both spellings present Podman
//     keeps whichever its decoder reaches last.
//   - More values than buildMaxTags.
//   - On an upstream that is or may be Podman, a value whose text before the
//     first colon is an image transport. See buildTagIsTransport.
//   - An `outputs` value that names an image. See buildOutputsNameImage.
//   - A `manifest` parameter in any spelling. Podman adds the built image to
//     the manifest list of that name and creates the list when nothing holds
//     it, on both routes. A manifest list is not an image this layer can
//     inspect for an owner, so there is no check to run. dockerd has no such
//     parameter.
//
// Read from moby 28.5.1, Podman 5.8.6 and buildah 1.43.2.
func buildImageDestinations(rawQuery, normPath string, flavor upstreamflavor.Flavor) (*imageDestinationReferences, string) {
	query, err := imageselector.Parse(rawQuery)
	if err != nil {
		return nil, buildDenyUnreadableQuery
	}
	naming := imageTagNamedAsStored
	if !isLibpodOwnershipPath(normPath) {
		naming = imageTagNamingFor(flavor)
	}

	refs := &imageDestinationReferences{route: buildRoute}
	tags := 0
	for _, field := range query {
		switch {
		case strings.EqualFold(field.Key, buildManifestQueryField):
			if field.Value != "" {
				return nil, buildDenyManifest
			}
		case field.Key == buildOutputsQueryField:
			if reason := buildOutputsNameImage(field.Value); reason != "" {
				return nil, reason
			}
		case !strings.EqualFold(field.Key, buildTagQueryField):
		case field.Key != buildTagQueryField:
			return nil, buildDenyAmbiguousTag
		case field.Value == "":
		default:
			if tags++; tags > buildMaxTags {
				return nil, buildDenyTooManyTags
			}
			if naming != imageTagNamedAsSpelled && buildTagIsTransport(field.Value) {
				return nil, buildDenyTransport
			}
			dest, problem := imageDestinationFor(field.Value, "", naming)
			if problem != imageDestinationReadable {
				return nil, buildRoute.refusal(problem)
			}
			refs.add(dest)
		}
	}
	if len(refs.destinations) == 0 {
		return nil, ""
	}
	return refs, ""
}

// buildTagIsTransport reports whether Podman's builder reads tag as a
// transport reference instead of as an image name.
//
// Buildah resolves a build's output with alltransports.ParseImageName before
// it tries the name as an image: the text before the first colon is looked up
// as a transport, and when it is one the image is written there. The reference
// grammar rejects most of those on its own ("dir:/path" and
// "docker://registry/name" are not names), but a transport whose reference
// reads as a tag or a registry port passes it. "containers-storage:app" is
// the image "app" in the daemon's store, and "dir:5000/out" is a directory on
// the daemon's host, while this layer would inspect an image named
// "containers-storage" or a registry called "dir". Podman's compat route with
// its default setting normalizes the name to Docker Hub first and never sees
// a transport, but that setting is not visible here. dockerd has no
// transports, so a dockerd upstream is not narrowed. Read from buildah 1.43.2
// (imagebuildah.Executor.resolveNameToImageRef).
func buildTagIsTransport(tag string) bool {
	transport, _, found := strings.Cut(tag, ":")
	if !found {
		return false
	}
	_, registered := buildOutputTransports[transport]
	return registered
}

// buildOutputsNameImage returns the reason a build's `outputs` value is
// refused, or "" when it names no image.
//
// dockerd's BuildKit builder takes its exporter from `outputs`, a JSON list
// of {Type, Attrs}, and an image exporter names the image in Attrs["name"]
// when the request carries no `t`. That name is not a reference this layer
// can inspect. A containerd-store dockerd 29.5.2 stored it exactly as
// spelled, with no Docker Hub completion and no default tag, as an image
// record beside the normalized one a `t` would have written, so the same
// string means different records depending on the store behind the daemon.
// The request is refused instead, and `t` is the parameter that is checked.
// An output that names nothing (a local or tar export) is left alone.
//
// The value is decoded into the shape moby decodes it into
// (build.ImageBuildOutput), with the same decoder, so the two agree on field
// case and on a repeated key. A value that does not decode is refused:
// dockerd answers 400 for it from API 1.40 on and ignores it before.
// Podman has no `outputs` parameter. Read from moby 28.5.1.
func buildOutputsNameImage(value string) string {
	if value == "" {
		return ""
	}
	var outputs []struct {
		Type  string
		Attrs map[string]string
	}
	if err := json.Unmarshal([]byte(value), &outputs); err != nil {
		return buildDenyOutputs
	}
	for _, output := range outputs {
		if output.Attrs["name"] != "" {
			return buildDenyOutputName
		}
	}
	return ""
}
