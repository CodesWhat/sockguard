package visibility

import (
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

// denyPodmanCompatSecretList refuses the Docker-compat GET /secrets with a 403
// without contacting the upstream, so the host's secret inventory is never
// read.
//
// The status is 403 rather than the 404 handleVisibilityInspectRequest returns
// for a hidden resource, for denyPodmanCompatEvents' reason: 404 exists there
// to deny an existence oracle for a caller-named resource, and /secrets is a
// fixed endpoint of the API whose existence is public.
//
// Rollout mode is not consulted, matching denyUnscopeableLibpodRead and every
// other refusal in this package. Warn mode buys an operator a measurement of
// what enforcement would cost, and the measurement is not worth taking here:
// forwarding means the whole host's secret list goes out, and the alternative
// the operator would be measuring against does not exist — the request the
// policy would have sent is the one Podman answers with a 500.
func denyPodmanCompatSecretList(w http.ResponseWriter, r *http.Request) {
	reason := filter.PodmanCompatSecretListDenyReason
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPodmanSecretList, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
}
