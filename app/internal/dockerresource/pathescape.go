package dockerresource

import "net/url"

// pathEscape forwards to url.PathEscape; isolated so the InspectPath table
// stays focused on the kind→path mapping.
func pathEscape(s string) string {
	return url.PathEscape(s)
}
