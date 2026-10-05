package ownership

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
	"github.com/codeswhat/sockguard/app/internal/queryparam"
)

const (
	libpodSecretCreateDenyAmbiguousName    = "owner policy denied secret create with an ambiguous name parameter"
	libpodSecretCreateDenyAmbiguousReplace = "owner policy denied secret create with an ambiguous replace parameter"
	libpodSecretCreateDenyAmbiguousIgnore  = "owner policy denied secret create with an ambiguous ignore parameter"
	libpodSecretCreateDenyDotName          = "owner policy denied secret create naming a secret it can't look up"

	libpodContainerCreateDenySecretReference = "owner policy denied container create with a secret reference it can't look up"
	libpodContainerCreateDenySecretID        = "owner policy denied container create with a secret reference that could be a secret ID or ID prefix"
	libpodContainerCreateDenySecretEnv       = "owner policy denied container create with secret_env, which Podman reads by name at every start"
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

// libpodContainerCreateSecretReferences returns the secrets a libpod container
// create body mounts, or the reason the create is refused when it names a
// secret in a way the lookup can't vouch for.
//
// A SpecGenerator names secrets in two places: `secrets`, a list of objects
// whose Source is mounted under /run/secrets, and `secret_env`, a map from an
// environment variable to the source it's set from. Podman resolves every
// source with SecretsManager.Lookup while it creates the container, and the
// container then reads that secret's data, so a source is a reference to check
// like the create's image or pod. Read from Podman 5.8.6
// pkg/specgen/specgen.go:201, :351 and :647,
// pkg/specgen/generate/container_create.go:667-691 and
// libpod/options.go:1812-1830.
//
// Only `secrets` can be checked. Podman copies a mounted secret's data into
// the container while it creates it and never reads the secret again. It
// doesn't copy an environment secret anywhere: it keeps the secret it resolved
// and reads the data by that secret's name at every start and every exec, and
// nothing stops a secret being removed while a container still names it. So a
// check at create says nothing about those reads. A caller could create the
// container with a secret of its own, remove the secret, and have the
// container read whatever secret another owner later creates under the same
// name. A `secret_env` that names anything is refused. Read from
// libpod/runtime_ctr.go:479-484, container_internal_common.go:753-765,
// oci_conmon_exec_common.go:711-722 and pkg/domain/infra/abi/secrets.go:127-157.
//
// Lookup matches a full ID, then a name, then a unique ID prefix. The compat
// secret inspect owner isolation looks a reference up with is the same Lookup,
// so it answers for the secret the create would get. Read from
// go.podman.io/common v0.67.1 pkg/secrets/secretsdb.go:71-119.
//
// A source goes to the lookup exactly as it arrived. Podman doesn't trim it,
// and a secret name can start or end with a space, so " mine" and "mine" are
// two secrets.
//
// Three sources resolve in Podman and can't be looked up, so a create naming
// one is refused. Every ID has the empty prefix, so an empty source is the
// only secret in a store that holds one, and it's ambiguous in any larger
// store. Podman reads a missing or null Source and a null list element as an
// empty source. "." and ".." are valid secret names, and Podman's router
// redirects the inspect for either one somewhere else (see
// libpodSecretCreateOwnershipReferences).
//
// A source that could be an ID or an ID prefix is refused too, whatever it
// resolves to. Podman resolves the source, then reads the data of the secret
// it got by that secret's name, in a second Lookup, and a name falls through
// to an ID prefix as soon as no secret holds it. A caller could store a secret
// of its own named after the first characters of another owner's secret ID,
// pass the owner check with it, delete it before Podman's read, and have that
// read answer with the other owner's secret. A source that can't be an ID or
// a prefix of one only ever matches a name, at the check and at both of
// Podman's reads. Read from libpod/container_internal.go:2769-2775. See
// couldBePodmanSecretID.
//
// The body is decoded with encoding/json, which matches keys in any letter
// case, so the keys are folded here. mutateJSONBody has already refused a body
// that spells one key two ways. A `secrets` that isn't a list of objects and a
// source that isn't a string both fail Podman's decode, and they're refused
// here too instead of being forwarded on the strength of that.
func libpodContainerCreateSecretReferences(decoded map[string]any) (refs []embeddedOwnershipReference, denyReason string) {
	add := func(value any) string {
		identifier, isString := value.(string)
		switch {
		case (value != nil && !isString) || identifier == "" || identifier == "." || identifier == "..":
			return libpodContainerCreateDenySecretReference
		case couldBePodmanSecretID(identifier):
			return libpodContainerCreateDenySecretID
		}
		if !slices.ContainsFunc(refs, func(ref embeddedOwnershipReference) bool { return ref.identifier == identifier }) {
			refs = append(refs, embeddedOwnershipReference{kind: dockerresource.KindSecret, identifier: identifier, source: "container create secrets"})
		}
		return ""
	}

	for _, value := range foldedValues(decoded, "secrets") {
		if value == nil {
			continue
		}
		mounts, isList := value.([]any)
		if !isList {
			return nil, libpodContainerCreateDenySecretReference
		}
		for _, mount := range mounts {
			// A null element and an object with no Source both decode to an
			// empty source.
			sources := []any{nil}
			if mount != nil {
				object, isObject := mount.(map[string]any)
				if !isObject {
					return nil, libpodContainerCreateDenySecretReference
				}
				if named := foldedValues(object, "Source"); len(named) > 0 {
					sources = named
				}
			}
			for _, source := range sources {
				if reason := add(source); reason != "" {
					return nil, reason
				}
			}
		}
	}

	for _, value := range foldedValues(decoded, "secret_env") {
		// A null and an empty object name nothing. Podman's decode refuses
		// anything that isn't an object, and that's refused here as well.
		if variables, isObject := value.(map[string]any); value != nil && (!isObject || len(variables) > 0) {
			return nil, libpodContainerCreateDenySecretEnv
		}
	}
	return refs, ""
}

// podmanSecretIDLength is the length of a Podman secret ID, which is that many
// lowercase hex digits (go.podman.io/common v0.67.1 pkg/secrets/secrets.go:25
// and :150-163).
const podmanSecretIDLength = 25

// couldBePodmanSecretID reports whether Podman's Lookup could match reference
// against a secret ID, in full or as a prefix: it's lowercase hex and no longer
// than an ID. Lookup compares case-sensitively, so "CAFE" can only be a name.
func couldBePodmanSecretID(reference string) bool {
	if reference == "" || len(reference) > podmanSecretIDLength {
		return false
	}
	for _, c := range []byte(reference) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// foldedValues returns the value of every key in m that case-folds to key, in
// key order so that what a request is refused for doesn't depend on map
// iteration.
func foldedValues(m map[string]any, key string) []any {
	var values []any
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if strings.EqualFold(k, key) {
			values = append(values, m[k])
		}
	}
	return values
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
