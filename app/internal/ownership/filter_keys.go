package ownership

import (
	"net/http"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

const reasonCodeOwnerFilterKeyInvalid = "owner_filter_key_invalid"

// refuseInvalidFilterKeys answers 400 and reports true when the request's
// `filters` parameter has a key containing "=". Podman flattens query filters
// into "key=value" strings and splits them again on the first "=", so such a
// key would reach it as an extra value of another filter, and on its
// disjunctive event filter that widens past the owner selector. It runs before
// any filter rewrite, on every request the owner filter applies to, whatever
// the upstream flavor. A filters parameter that does not decode is left to the
// existing owner-filter path to report.
func refuseInvalidFilterKeys(w http.ResponseWriter, r *http.Request) bool {
	encoded := r.URL.Query().Get("filters")
	if encoded == "" {
		return false
	}
	filters, err := dockerfilters.Decode(encoded)
	if err != nil {
		return false
	}
	if err := dockerfilters.CheckKeys(filters); err != nil {
		logging.SetDeniedWithCode(w, r, reasonCodeOwnerFilterKeyInvalid, err.Error(), nil)
		_ = httpjson.Write(w, http.StatusBadRequest, httpjson.ErrorResponse{Message: err.Error()})
		return true
	}
	return false
}
