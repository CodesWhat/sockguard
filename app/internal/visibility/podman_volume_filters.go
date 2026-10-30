package visibility

import (
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// refuseUnsupportedPodmanVolumeFilters answers 403 and reports true when a
// Podman upstream's volume list carries a filter key other than `label` while
// a visibility selector applies. Podman before 6.0 ORs volume filters across
// keys, so the appended selector would not narrow the result; see
// filter.PodmanVolumeFilterDenyReason. The flavor probe doesn't read the
// Podman version, so this applies to every Podman upstream. A filters
// parameter that doesn't decode is left to the list path to report.
func refuseUnsupportedPodmanVolumeFilters(w http.ResponseWriter, r *http.Request) bool {
	encoded := r.URL.Query().Get("filters")
	if encoded == "" {
		return false
	}
	filters, err := dockerfilters.Decode(encoded)
	if err != nil {
		return false
	}
	// An invalid filter key is answered later by addVisibilityLabelFilters
	// with its own 400 and reason code. Step aside here so the client and the
	// log see that category rather than this 403.
	if dockerfilters.CheckKeys(filters) != nil {
		return false
	}
	reason, denied := filter.PodmanVolumeFilterDenyReason(filters)
	if !denied {
		return false
	}
	logging.SetDeniedWithCode(w, r, reasonCodeVisibilityPodmanVolumeFilter, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
	return true
}
