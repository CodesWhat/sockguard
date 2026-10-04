package ownership

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v2/app/internal/filter"
	"github.com/codeswhat/sockguard/v2/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
	"github.com/codeswhat/sockguard/v2/app/internal/queryparam"
)

const (
	libpodSecretCreateDenyAmbiguousName    = "owner policy denied secret create with an ambiguous name parameter"
	libpodSecretCreateDenyAmbiguousReplace = "owner policy denied secret create with an ambiguous replace parameter"
	libpodSecretCreateDenyAmbiguousIgnore  = "owner policy denied secret create with an ambiguous ignore parameter"
	libpodSecretCreateDenyDotName          = "owner policy denied secret create naming a secret it can't look up"
)

// denyPodmanCompatSecretList refuses the Docker-compat GET (or HEAD) /secrets
// with a 403 without contacting the upstream, so the host's secret inventory
// is never read.
//
// Status, rollout-mode independence and reason-code shape are
// denyUnscopeableLibpodRead's, for the same reasons: /secrets is a fixed
// endpoint of the API whose existence is public, so 403 rather than 404, and
// warn mode has no measurement to take because the request owner isolation
// would otherwise have sent is the one Podman answers with a 500.
//
// The code is spelled out here rather than assembled from a table stem
// because there is one compat path in this position, matching how
// reasonCodeOwnerVisibilityPodmanEventsUnscopeable is spelled out for the
// other flavor-gated refusal. The reason string is shared with the visibility
// middleware through internal/filter so the two layers cannot explain the same
// refusal differently.
func denyPodmanCompatSecretList(w http.ResponseWriter, r *http.Request) {
	reason := filter.PodmanCompatSecretListDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeOwnerPodmanSecretList, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}

// mutateLibpodSecretCreateOwnershipRequest stamps the owner label on
// POST /libpod/secrets/create and returns the existing secret the request
// would act on, if any.
//
// The create has no JSON body. The body is the raw secret payload, and
// `driver`, `labels` and the rest are query parameters (see
// internal/filter/libpod_secret.go), so the build-query mutator's "decode the
// `labels` query parameter as a JSON map, stamp it, re-encode it" is the
// stamp this route needs too. The flags are read from the query as it
// arrived, before the stamp rewrites it.
func mutateLibpodSecretCreateOwnershipRequest(r *http.Request, opts Options) (*ownershipRequestReferences, error) {
	refs := libpodSecretCreateOwnershipReferences(r.URL.Query())
	if err := addOwnerLabelToBuildQuery(r, opts.LabelKey, opts.Owner); err != nil {
		return nil, err
	}
	return refs, nil
}

// libpodSecretCreateOwnershipReferences returns the secret a libpod secret
// create acts on in place, or the reason it's refused.
//
// A create normally names a secret that doesn't exist yet, and Podman refuses
// a name already in use. Two flags change that. With `replace` Podman deletes
// the existing secret and stores a new one under its name with the request's
// labels and data, so a caller could take over another owner's secret, and
// every container of theirs that mounts it by name would read the caller's
// data on its next start. With `ignore` it answers with the existing secret's
// ID and changes nothing, which hands the caller the ID of a secret it can't
// inspect and a 200 saying its create worked. Read from Podman 5.8.6
// pkg/api/handlers/libpod/secrets.go and go.podman.io/common v0.67.1
// pkg/secrets/secrets.go (Store). The compat POST /secrets/create never sets
// either flag on Podman, and dockerd has neither.
//
// So when either flag may be set, the named secret has to be absent or the
// caller's own. Store matches the name against every secret's exact name and
// exact ID, and the inspect owner isolation makes resolves exact matches the
// same way first, so it answers for the secret Store would act on. The
// inspect then falls back to a unique ID prefix, which Store doesn't, so a
// name that is only a prefix of another owner's ID is refused as well.
//
// The libpod handler decodes the flags with gorilla/schema's own bool
// converter: "on" and whatever strconv.ParseBool reads as true are true, an
// empty value leaves the flag false, and anything else is a 400. A value is
// only treated as unset when Podman would read it as false, so a value it
// would refuse costs one lookup rather than a guess. `name`, `replace` and
// `ignore` are read through queryparam, so a parameter repeated or spelled in
// another case, which gorilla/schema would fold and take the last of, is
// refused. That only matters while a flag may be set: without one, Podman
// refuses a name in use on its own.
//
// "." and ".." are valid secret names that the lookup can't address. Podman's
// router redirects GET /secrets/.. to "/" and GET /secrets/. to the secret
// list, so neither inspect would answer for the secret, and a create naming
// either is refused while a flag may be set. An empty name is left to Podman,
// which refuses it.
func libpodSecretCreateOwnershipReferences(query url.Values) *ownershipRequestReferences {
	replace, _, ok := queryparam.Scalar(query, "replace")
	if !ok {
		return &ownershipRequestReferences{denyReason: libpodSecretCreateDenyAmbiguousReplace}
	}
	ignore, _, ok := queryparam.Scalar(query, "ignore")
	if !ok {
		return &ownershipRequestReferences{denyReason: libpodSecretCreateDenyAmbiguousIgnore}
	}
	var source string
	switch {
	case libpodQueryBoolMaySet(replace):
		source = "secret create replace"
	case libpodQueryBoolMaySet(ignore):
		source = "secret create ignore"
	default:
		return nil
	}
	name, _, ok := queryparam.Scalar(query, "name")
	switch {
	case !ok:
		return &ownershipRequestReferences{denyReason: libpodSecretCreateDenyAmbiguousName}
	case name == "":
		return nil
	case name == "." || name == "..":
		return &ownershipRequestReferences{denyReason: libpodSecretCreateDenyDotName}
	}
	return &ownershipRequestReferences{existingResources: []embeddedOwnershipReference{{
		kind:       dockerresource.KindSecret,
		identifier: name,
		source:     source,
	}}}
}

// libpodQueryBoolMaySet reports whether a libpod route could read value as a
// true bool. Only the values gorilla/schema's converter reads as false, and
// an empty value, which leaves the field alone, are certainly unset.
func libpodQueryBoolMaySet(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	return err != nil || parsed
}
