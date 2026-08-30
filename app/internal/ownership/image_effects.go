package ownership

import (
	"net/http"
	"strings"
)

func imageEffectDenial(method, normPath string) (string, bool) {
	if method == http.MethodGet {
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
