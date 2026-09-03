package ownership

import (
	"net/http"
	"strings"
)

// imageEffectDenial reports the routes whose full effect an ordinary image
// inspect cannot authorize, so ownership refuses them outright rather than
// checking the one image the URL happens to name.
//
// The per-image export arm covers HEAD as well as GET. imageIdentifier already
// trims the "/get" suffix for both methods, so without it here a HEAD would be
// owner-checked against {name} and admitted for an owned image while the GET
// spelling of the same route is refused. Moby registers the exporter GET-only,
// which makes the HEAD a 405 upstream today, but that is the daemon's routing
// table rather than a property of the request.
func imageEffectDenial(method, normPath string) (string, bool) {
	if method == http.MethodGet || method == http.MethodHead {
		if _, ok := imageSubresourceIdentifier(normPath, "/images/", "get"); ok {
			return "owner policy cannot safely authorize Docker-compatible multi-platform image export", true
		}
	}
	if method != http.MethodDelete {
		return "", false
	}
	if _, ok := imageIdentifier(method, normPath); ok {
		return "owner policy cannot safely authorize Docker-compatible image removal effects", true
	}
	if _, ok := libpodImageIdentifier(method, normPath); ok {
		return "owner policy denied access to image because recursive removal effects cannot be safely authorized", true
	}
	return "", false
}

func imageSubresourceIdentifier(normPath, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(normPath, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(normPath, prefix)
	identifier := strings.TrimSuffix(rest, "/"+suffix)
	return identifier, identifier != rest && identifier != ""
}
