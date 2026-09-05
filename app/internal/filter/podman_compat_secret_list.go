package filter

// podman_compat_secret_list.go names the one Docker-compat GET that both
// isolation layers refuse on a Podman upstream and leave completely alone on a
// Docker one. It is the compat twin of the LibpodSecretListPath entry in
// libpod_unscopeable_reads.go, and it is deliberately NOT in that table:
// every entry there is refused unconditionally, because a /libpod/ path only
// exists on Podman. "/secrets" exists on both engines and means different
// things on each, so its refusal has to be gated on the resolved
// upstream.flavor the way GET /events already is.
//
// The reason string lives here rather than in either middleware for the same
// reason libpod_unscopeable_reads.go's do: internal/ownership and
// internal/visibility both report it, and two copies would drift into
// explaining one refusal two ways.

// PodmanCompatSecretListPath is the normalized path of the Docker-compat
// secret list. It is the spelling every Docker client sends, and on a Podman
// upstream it is served by the same handler as GET /libpod/secrets/json:
// pkg/api/server/register_secrets.go at v5.8.1 wires
// VersionedPath("/secrets"), the bare "/secrets", and
// VersionedPath("/libpod/secrets/json") all onto compat.ListSecrets, which
// branches on utils.IsLibpodRequest only when it comes to writing the
// response envelope. The filter grammar is reached before that branch, so
// both spellings share it exactly.
const PodmanCompatSecretListPath = "/secrets" // #nosec G101 -- a URL path, not a credential; "secrets" is the Docker API's route segment.

// PodmanCompatSecretListDenyReason is reported when either middleware refuses
// GET (or HEAD) /secrets because the upstream is Podman.
//
// The shape argument is LibpodSecretListDenyReason's, verbatim, because it is
// the same handler. abi.SecretList runs every secret through
// utils.IfPassesSecretsFilter (pkg/domain/utils/secrets_filters.go at v5.8.1),
// whose switch accepts "name" and "id" and returns fmt.Errorf("invalid filter
// %q", key) on anything else, and compat.ListSecrets turns that error into
// utils.InternalServerError. So the `label` filter that owner isolation and
// visibility inject into every other list does not merely fail to narrow this
// one, it answers 500 for every request. That 500 is the behavior this
// refusal replaces.
//
// Dropping the injection instead would forward a cross-owner enumeration of
// every secret ID and name on the host, which is the disclosure both layers
// exist to deny.
//
// A response-side filter is the third option and is not taken here, for the
// reason LibpodSecretListDenyReason gives about its own path. The items do
// carry Spec.Labels — entities.SecretInfoReportCompat embeds
// entities.SecretInfoReport, whose Spec is a SecretSpec{Name, Driver, Labels},
// so the compat body carries the same label map the libpod body does — and a
// filter of the GET /system/df kind could scope either. Building one for the
// compat spelling alone would leave one Podman handler answering 403 through
// its native path and a filtered list through its compat path off the same
// policy, which is exactly the drift the shared reason strings exist to
// prevent. Implementing that filter is what moves BOTH entries out, together.
//
// A Docker upstream is untouched: dockerd's swarm secret list honors `label`
// conjunctively like every other list it serves, so the injection is correct
// there and neither layer consults this constant.
const PodmanCompatSecretListDenyReason = "compat secret list denied: " +
	"this upstream is Podman, which serves GET /secrets from the same handler as GET /libpod/secrets/json; it " +
	"accepts only name and id filters and answers 500 for any other key, so the label filter that scopes every " +
	"other list cannot be pushed upstream, and no response-side owner filter exists for its shape, so it cannot " +
	"be scoped to one caller"
