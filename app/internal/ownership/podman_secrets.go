package ownership

import (
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
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
