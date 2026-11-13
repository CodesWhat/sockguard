package ownership

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/imageselector"
	"github.com/codeswhat/sockguard/v3/app/internal/upstreamflavor"
)

const (
	imageCreatePath       = "/images/create"
	libpodImageImportPath = libpodPrefix + "images/import"
	libpodImagePullPath   = libpodPrefix + "images/pull"

	imageImportChangesQueryField   = "changes"
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

	imagePullDenyNoTag    = "owner policy denied image pull without a tag or digest: dockerd pulls every tag of the repository"
	imagePullDenyAllTags  = "owner policy denied image pull of every tag of a repository"
	imagePullDenyPlatform = "owner policy denied image pull of a name with no registry for a named platform: Podman resolves it through registries.conf, so spell the registry"
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

// mutateImageCreateOwnershipRequest reads the name an image create names, and
// stamps the owner label on the image an import makes.
//
// An import makes an image from the body, and `changes` carries Dockerfile
// instructions applied to its config, a LABEL among them. The image carries no
// other labels, so the client chose all of them, the owner label included: it
// could import under a name nothing held, labeled as another owner's, and that
// owner would go on to use the name (build, tag or run it) and get the
// client's content. The check on the name only covers a name something holds.
// So the stamp goes on every import, held name or not: a
// `LABEL <key>=<owner>` appended after the client's own `changes`, which both
// engines apply in order, so it overwrites any LABEL of the same key.
//
// dockerd reads the values of the exact key `changes` and Podman's compat and
// native imports read every spelling of it. A spelling dockerd would ignore and
// Podman would read, or one that could land after the stamp, is refused instead
// of ordered.
//
// A pull is not stamped. The labels of a pulled image come from the registry's
// copy and the route has no parameter that sets them, so the owner label can't
// be written there, and a load takes its labels from the archive. Read from
// moby 28.5.1 and Podman 5.8.6 (compat CreateImageFromSrc, libpod ImagesImport).
func mutateImageCreateOwnershipRequest(r *http.Request, normPath string, opts Options) (*ownershipRequestReferences, error) {
	refs := imageCreateOwnershipReferences(r, normPath, opts.UpstreamFlavor)
	query := r.URL.Query()
	isImport := normPath == libpodImageImportPath || (normPath == imageCreatePath && query.Get(imageCreateFromImageQueryField) == "")
	if !isImport {
		return refs, nil
	}
	if err := addOwnerLabelToImportQuery(r, query, opts.LabelKey, opts.Owner); err != nil {
		return nil, err
	}
	return refs, nil
}

func addOwnerLabelToImportQuery(r *http.Request, query url.Values, labelKey, owner string) error {
	for key := range query {
		if key != imageImportChangesQueryField && strings.EqualFold(key, imageImportChangesQueryField) {
			return fmt.Errorf("image import changes parameter is spelled %q: the engines disagree on whether it applies", key)
		}
	}
	for _, change := range query[imageImportChangesQueryField] {
		if reason := imageImportChangeRefusal(change, labelKey); reason != "" {
			return fmt.Errorf("image import changes entry refused: %s", reason)
		}
	}
	instruction, ok := dockerfileLabelInstruction(labelKey, owner)
	if !ok {
		return fmt.Errorf("image import can't stamp an owner label whose key or value holds a control character")
	}
	query[imageImportChangesQueryField] = append(query[imageImportChangesQueryField], instruction)
	r.URL.RawQuery = query.Encode()
	return nil
}

// imageImportChangeRefusal returns why a client `changes` entry can't be
// ordered safely ahead of the owner stamp, or "" when it can.
//
// dockerd joins every entry with "\n" into one Dockerfile and parses that, so
// an entry is not a line of its own: one ending in a backslash continues onto
// the stamp, an unterminated quote runs through it (`LABEL z='\`), a parser
// directive changes how the rest is read (`# escape=`), and a CR or LF inside
// an entry adds lines the client chose. Any of those can swallow the stamp
// appended after it, which is why the stamp's position isn't enough on its
// own. Podman does not join: util.DecodeChanges splits each entry on "\n" and
// parses the lines one by one (v6.1.3, pkg/util/changes.go, used by the compat
// and native imports), so there a continuation or quote can't reach the next
// entry. The rules are the same on both, because the engine behind the
// socket isn't always known and a legitimate client sends one plain
// instruction per entry.
//
// Three more shapes are refused because they act on the stamp without
// ending in a backslash or a quote: `<<` anywhere (`ONBUILD RUN <<'<stamp>'`
// opens a heredoc whose terminator is the stamp line, which it then consumes),
// any ONBUILD instruction, and a LABEL holding `$` or `{` (`ENV K=<key>` then
// `LABEL ${K}=x` sets the owner label with no literal key). The LABEL check
// covers the whole entry, values included, since telling a key from a value
// means parsing the quoting.
//
// A LABEL naming the owner label key is refused outright as well, in any
// quoting (quotes and backslashes are dropped before the key is looked for).
// The stamp would overwrite it, but a client has no reason to set it.
func imageImportChangeRefusal(change, labelKey string) string {
	if strings.ContainsAny(change, "\r\n") {
		return "it holds a line break"
	}
	trimmed := strings.TrimSpace(change)
	switch {
	case strings.Contains(trimmed, "<<"):
		return "it holds <<, which opens a heredoc that can end on the owner stamp"
	case commitChangeInstruction(trimmed) == "ONBUILD":
		return "it is an ONBUILD instruction"
	case commitChangeInstruction(trimmed) == "LABEL" && strings.ContainsAny(trimmed, "${"):
		return "its LABEL holds $ or {, which can spell the owner label key through a variable"
	case strings.HasPrefix(trimmed, "#"):
		return "it starts with # (a comment or parser directive)"
	case strings.HasSuffix(trimmed, "\\"):
		return "it ends with a backslash"
	case !quotesBalanced(trimmed):
		return "it has an unterminated quote"
	}
	if commitChangeInstruction(trimmed) == "LABEL" {
		bare := strings.NewReplacer("\"", "", "'", "", "\\", "").Replace(trimmed)
		if strings.Contains(bare, labelKey) {
			return "it sets the owner label"
		}
	}
	return ""
}

// quotesBalanced reports whether every ' and " in s that isn't escaped opens
// a quote that closes before the end. A backslash escapes the next character
// outside single quotes, the way the Dockerfile word parser reads it.
func quotesBalanced(s string) bool {
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case r == quote:
			quote = 0
		}
	}
	return quote == 0
}

// dockerfileLabelInstruction spells `LABEL key=value` so the Dockerfile
// parser reads back exactly key and value. Both are double-quoted, with the
// three characters the parser treats specially inside the quotes escaped (\,
// " and $, which it would otherwise expand as a variable). A control character
// can't be spelled on one line.
func dockerfileLabelInstruction(key, value string) (string, bool) {
	quoted := make([]string, 0, 2)
	for _, word := range [...]string{key, value} {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range word {
			if r < 0x20 || r == 0x7f {
				return "", false
			}
			if r == '\\' || r == '"' || r == '$' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
		quoted = append(quoted, b.String())
	}
	return "LABEL " + quoted[0] + "=" + quoted[1], true
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
//   - Both pull a reference that carries a digest by that digest, and drop a
//     tag that comes with it.
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
//   - A name carrying a digest with a `tag` parameter beside it. dockerd
//     builds one reference out of the two and pulls it by a digest, and
//     Podman joins them into a string it cannot parse and answers with an
//     error. No client sends that.
//   - A digest outside the digest grammar: an algorithm other than sha256,
//     sha384 or sha512, or hex of the wrong length or case. The engines read
//     such a value as a tag and reject it.
//   - On an upstream that is or may be Podman, a name with no registry on a
//     request that names a platform. Podman then skips the local lookup and
//     resolves the name through registries.conf, which this layer cannot
//     read, so the pull can land on a name the inspect never asked about.
//
// A pull by digest writes no tag on either engine and has no destination. It
// fetches the content the digest names, so whatever reference it leaves can
// only sit on that content, and nothing is taken from anyone.
//
// That holds when a tag comes with the digest, which is how a pinned
// reference such as nginx:1.27@sha256:... is written. The tag is not pulled
// and not written: moby's classic store records the digest reference alone,
// its containerd store keeps one image record under the whole string, which
// the tag by itself does not resolve to, and libimage strips the tag before it
// does anything else ("the digest is the sole source of truth"). So the
// request is a pull by digest in both shapes a client sends it in: the whole
// reference in `fromImage`, and the name with its tag in `fromImage` beside
// the digest in `tag`, which is how docker-py and dockerode split it. Both
// were pulled against dockerd 28.5.1 on each image store with a tag the
// registry does not have, and neither wrote that tag.
//
// Read from moby 28.5.1 and 29.5.2 and from Podman 5.8.6 and its libimage
// (go.podman.io/common v0.67.1, Pull and copySingleImageFromRegistry).
func imagePullDestination(route imageDestinationRoute, name, tag string, naming imageTagNaming, namesPlatform bool) (*imageDestinationReferences, string) {
	repository, digest, digested := strings.Cut(name, "@")
	switch {
	case digested && tag != "":
		return nil, route.refusal(imageDestinationTagAndDigest)
	case !digested && isImageDigest(tag):
		repository, digest, digested, tag = name, tag, true, ""
	}
	if digested {
		if refusal := route.refusal(imagePullByDigestProblem(repository, digest, naming)); refusal != "" {
			return nil, refusal
		}
		// No name is written, so there is no destination to authorize. The
		// reference is kept for the check after the pull, without the tag the
		// engines drop.
		if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
			repository = repository[:colon]
		}
		return &imageDestinationReferences{route: route, digests: []string{repository + "@" + digest}}, ""
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

// imagePullByDigestProblem reports why a pull by digest cannot be read the way
// the daemon reads it. repository is the name the digest came with, and may
// carry a tag, which the engines drop. A readable one has no destination. See
// imagePullDestination.
//
// The name and a tag it carries are held to the grammar a tagged pull is, so
// a string only one engine can parse is refused here as well.
func imagePullByDigestProblem(repository, digest string, naming imageTagNaming) imageDestinationProblem {
	if _, problem := imageDestinationFor(repository, "", naming); problem != imageDestinationReadable {
		return problem
	}
	if !isImageDigest(digest) {
		return imageDestinationBadDigest
	}
	return imageDestinationReadable
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
