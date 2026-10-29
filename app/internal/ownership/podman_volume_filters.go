package ownership

import (
	"net/http"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const reasonCodeOwnerPodmanVolumeFilterUnscopeable = "owner_podman_volume_filter_unscopeable"

// isPodmanVolumeFilterPath reports whether method and normPath name a volume
// list or prune route whose filters Podman evaluates.
func isPodmanVolumeFilterPath(method, normPath string) bool {
	switch method {
	case http.MethodGet, http.MethodHead:
		return filter.IsPodmanVolumeListPath(normPath)
	case http.MethodPost:
		return filter.IsPodmanVolumePrunePath(normPath)
	default:
		return false
	}
}

// refuseUnsupportedPodmanVolumeFilters answers 403 and reports true when a
// Podman upstream's volume list or prune carries a filter key other than
// `label`.
//
// See filter.PodmanVolumeFilterDenyReason for why. It is a refusal rather than
// a silent strip so the behavior is explicit to the client. Podman 6.0 fixed
// the combinator, but the flavor probe doesn't read the Podman version, so the
// refusal applies to every Podman upstream. A Docker upstream is unchanged.
//
// Like the other unscopeable refusals it does not honor warn mode: a prune
// that has run cannot be measured after the fact.
func refuseUnsupportedPodmanVolumeFilters(w http.ResponseWriter, r *http.Request, normPath string, podmanUpstream bool) bool {
	if !podmanUpstream || !isPodmanVolumeFilterPath(r.Method, normPath) {
		return false
	}
	encoded := r.URL.Query().Get("filters")
	if encoded == "" {
		return false
	}
	filters, err := dockerfilters.Decode(encoded)
	if err != nil {
		return false
	}
	reason, denied := filter.PodmanVolumeFilterDenyReason(filters)
	if !denied {
		return false
	}
	logging.SetDeniedWithCode(w, r, reasonCodeOwnerPodmanVolumeFilterUnscopeable, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
	return true
}
