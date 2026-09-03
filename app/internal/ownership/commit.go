package ownership

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// commit.go authorizes the container-commit endpoint, which is the one write
// in the API that turns a container into an image and names neither of them
// in its path.
//
// Nothing classified it before, because every other ownership check starts
// from a path identifier and `/commit` has none: allowPathOwnershipRequest
// only ever matched `/containers/`-prefixed paths, so a client with the
// `POST /commit` rule that portainer.yaml ships (and that Tecnativa's
// COMMIT=1 generates) could commit ANOTHER owner's container into a new
// image, and the image came out unlabeled — invisible to the owner-filtered
// image list and outside every later ownership check.
//
// The container comes from the `container` query parameter on all three
// registered spellings: moby's POST /commit (api/server/router/container at
// v28 reads r.Form.Get("container")), Podman's compat POST /commit and its
// native POST /libpod/commit (both decode a `container` schema field at
// v5.8.1). So the check reads the query and authorizes the named container as
// an embedded reference, which is the same machinery a create body's Image or
// Mounts reference already travels.

const (
	commitContainerQueryField = "container"
	commitChangesQueryField   = "changes"

	commitDenyNoContainer        = "owner policy denied commit with no container parameter"
	commitDenyAmbiguousContainer = "owner policy denied commit with an ambiguous container parameter"
	commitDenyLabelChange        = "owner policy denied commit with a LABEL change instruction"
)

// mutateCommitOwnershipRequest stamps the owner label into the commit body and
// returns the container reference the request has to be authorized against.
//
// A refusal short-circuits before the body is touched: a request that will not
// be forwarded has nothing to gain from a stamp, and the LABEL refusal below
// exists precisely because the stamp would not survive.
func mutateCommitOwnershipRequest(r *http.Request, opts Options) (*ownershipRequestReferences, error) {
	refs := commitOwnershipReferences(r)
	if refs.denyReason != "" {
		return refs, nil
	}
	if err := mutateCommitOwnershipBody(r, opts.LabelKey, opts.Owner); err != nil {
		return nil, err
	}
	return refs, nil
}

// commitOwnershipReferences reads the commit query and returns either the
// container to authorize or the reason the request is refused outright.
//
// Three shapes are refused rather than authorized:
//
//   - No `container` parameter. There is no source container to check, and
//     the daemon would answer its own error anyway (moby's GetContainer("")
//     is an invalid-parameter 400). Owner isolation does not forward a write
//     it could not classify.
//   - A repeated or two-case-variant `container`. Moby reads the first value
//     of a repeated parameter and Podman reads the last, so a request naming
//     an owned container and a foreign one would be checked against one and
//     executed against the other. filter.FoldedScalarQueryValue is the same
//     helper the container-archive policy uses for the same disagreement.
//   - A `changes` value carrying a LABEL instruction. See
//     commitChangesSetLabel.
func commitOwnershipReferences(r *http.Request) *ownershipRequestReferences {
	refs := &ownershipRequestReferences{}
	query := r.URL.Query()
	if commitChangesSetLabel(query) {
		refs.denyReason = commitDenyLabelChange
		return refs
	}
	identifier, found, ambiguous := filter.FoldedScalarQueryValue(query, commitContainerQueryField)
	switch {
	case ambiguous:
		refs.denyReason = commitDenyAmbiguousContainer
	case !found || strings.TrimSpace(identifier) == "":
		refs.denyReason = commitDenyNoContainer
	default:
		appendEmbeddedOwnershipReference(&refs.embeddedResources, dockerresource.KindContainer, identifier, "commit container parameter")
	}
	return refs
}

// mutateCommitOwnershipBody injects the owner label into the commit request's
// ContainerConfig body so the committed image carries it, synthesizing a body
// when the client sent none.
//
// The body is the config the new image is built from, not a wrapper: moby
// decodes it as a container.Config and, in daemon/commit.go, merges the source
// container's config into it for keys the body did not set — so a client-set
// `Labels` entry wins over the container's, which is why the stamp has to
// overwrite the key rather than only fill it in. Podman decodes the same body
// into buildah's OverrideConfig (a manifest.Schema2Config, whose labels field
// is also spelled `Labels`) and copies it over the image config last.
//
// A commit with no body at all is legal on both engines — moby's postCommit
// ignores an io.EOF from the decoder, and Podman guards the decode on a
// non-nil body — so the missing case is synthesized rather than rejected. The
// synthesized body carries a Content-Type, because moby runs
// httputils.CheckForJSON before decoding and answers 400 for a body sent with
// no JSON content type.
func mutateCommitOwnershipBody(r *http.Request, labelKey, owner string) error {
	var body []byte
	if r.Body != nil {
		// One byte past the limit, so at-limit and over-limit are
		// distinguishable without giving the client room to OOM the proxy.
		read, err := io.ReadAll(io.LimitReader(r.Body, maxOwnershipBodyBytes+1))
		if closeErr := r.Body.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
		if int64(len(read)) > maxOwnershipBodyBytes {
			return fmt.Errorf("request body exceeds %d byte limit", maxOwnershipBodyBytes)
		}
		body = read
	}

	if len(bytes.TrimSpace(body)) == 0 {
		encoded, err := json.Marshal(map[string]map[string]string{"Labels": {labelKey: owner}})
		if err != nil {
			return fmt.Errorf("encode commit config: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(encoded))
		r.ContentLength = int64(len(encoded))
		r.Header.Set("Content-Type", "application/json")
		return nil
	}

	// Restore what was read so the shared mutator can do its own bounded
	// read, duplicate-case-variant-key rejection and re-encode.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return addOwnerLabelToBody(r, labelKey, owner)
}

// commitChangesSetLabel reports whether the commit query carries a Dockerfile
// LABEL instruction in `changes`.
//
// Such a request is refused because the change instructions are applied ON TOP
// of the body config on both engines, so a LABEL there overwrites the owner
// label this layer just stamped. Moby: postCommit passes r.Form["changes"]
// through to daemon/commit.go, which calls
// dockerfile.BuildFromConfig(c.Config, c.Changes, ...) — the changes run
// against the stamped config — and the merge that follows only fills label
// keys the result does not already have. Podman: both commit handlers pass
// query.Changes to buildah as OverrideChanges, and buildah's
// internal/config.parseOverrideChanges seeds a builder from the override
// config and replays the instructions over it before the result is copied
// onto the image config with maps.Copy.
//
// The refusal is on the instruction, not on the label key it sets. Deciding
// which key a LABEL line touches means parsing Dockerfile quoting, multi-pair
// lines and line continuations, and getting that wrong is a silent bypass
// rather than a broken request. A commit that needs image labels can set them
// in the body config, which is the surface this layer can reason about.
//
// The scan matches Podman's own normalization: util.DecodeChanges at v5.8.1
// splits every value on newlines and rewrites the first "=" into a space when
// it comes before any whitespace, so `LABEL=k=v` is a LABEL instruction there
// even though moby would fail to parse it. The `changes` key itself is matched
// case-insensitively because Podman decodes it with gorilla/schema, whose
// field lookup folds case.
func commitChangesSetLabel(query url.Values) bool {
	for key, values := range query {
		if !strings.EqualFold(key, commitChangesQueryField) {
			continue
		}
		for _, value := range values {
			for _, line := range strings.Split(value, "\n") {
				if commitChangeInstruction(line) == "LABEL" {
					return true
				}
			}
		}
	}
	return false
}

// commitChangeInstruction returns the upper-cased instruction token of one
// change line, taking the token to end at the first whitespace or the first
// "=", whichever comes first. See commitChangesSetLabel for why both count.
func commitChangeInstruction(line string) string {
	trimmed := strings.TrimSpace(line)
	end := strings.IndexFunc(trimmed, func(r rune) bool { return unicode.IsSpace(r) || r == '=' })
	if end >= 0 {
		trimmed = trimmed[:end]
	}
	return strings.ToUpper(trimmed)
}
