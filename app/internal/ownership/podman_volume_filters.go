package ownership

import (
	"net/http"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/httpjson"
	"github.com/codeswhat/sockguard/app/internal/logging"
)

const reasonCodeOwnerPodmanVolumeFilterUnscopeable = "owner_podman_volume_filter_unscopeable"

const ownerPodmanVolumeFilterDenyReason = "volume filter denied: this upstream is Podman, which combines volume filters of different keys disjunctively, so only `label` filters can be scoped to one owner"

// isPodmanVolumeFilterPath reports whether method and normPath name a volume
// list or prune route whose filters Podman evaluates: the Docker-compat list
// and prune, and their libpod spellings.
func isPodmanVolumeFilterPath(method, normPath string) bool {
	switch method {
	case http.MethodGet, http.MethodHead:
		return normPath == "/volumes" || normPath == libpodPrefix+"volumes/json"
	case http.MethodPost:
		return normPath == "/volumes/prune" || normPath == libpodPrefix+"volumes/prune"
	default:
		return false
	}
}

// refuseUnsupportedPodmanVolumeFilters answers 403 and reports true when a
// Podman upstream's volume list or prune carries a filter key other than
// `label`.
//
// Podman before 6.0 combines volume filters of different keys with OR
// (libpod/runtime_volume.go accumulates `include = include || filter(vol)`),
// so any extra key (driver, name, label!, until, dangling, ...) widens the
// result past the injected owner `label` selector, and on prune removes other
// owners' unused volumes. It is a refusal rather than a silent strip so the
// behavior is explicit to the client. Podman 6.0 fixed the combinator, but
// upstream flavor detection cannot see the Podman version, so the refusal
// applies to every Podman upstream. A Docker upstream is unchanged.
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
	var unsupported []string
	for key := range filters {
		if key != "label" {
			unsupported = append(unsupported, key)
		}
	}
	if len(unsupported) == 0 {
		return false
	}
	slices.Sort(unsupported)
	reason := ownerPodmanVolumeFilterDenyReason + " (unsupported: " + strings.Join(unsupported, ", ") + ")"
	logging.SetDeniedWithCode(w, r, reasonCodeOwnerPodmanVolumeFilterUnscopeable, reason, nil)
	_ = httpjson.Write(w, http.StatusForbidden, httpjson.ErrorResponse{Message: reason})
	return true
}
