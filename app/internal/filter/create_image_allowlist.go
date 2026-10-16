package filter

import "fmt"

// createImageAllowlist matches the exact reference sent to the daemon. It does
// not resolve tags, expand aliases, or consult a registry. Empty is unrestricted.
type createImageAllowlist map[string]struct{}

func newCreateImageAllowlist(images []string) createImageAllowlist {
	allowed := make(createImageAllowlist, len(images))
	for _, image := range images {
		allowed[image] = struct{}{}
	}
	return allowed
}

func (p createImageAllowlist) denyReason(image, subject string) string {
	if len(p) == 0 {
		return ""
	}
	if _, allowed := p[image]; allowed && image != "" {
		return ""
	}
	return fmt.Sprintf("%s denied: image %q is not allowlisted", subject, image)
}
