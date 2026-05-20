package filter

import (
	"path"
	"strings"
)

// normalizeBindMount cleans an absolute bind-mount source path. It returns the
// cleaned absolute path and true when the input is non-empty and rooted at
// "/"; otherwise it returns "", false. The helper is shared by the
// container/exec, service, and plugin inspectors because all three reject
// relative bind sources for the same reason — they would resolve against the
// proxy's filesystem, not the client's.
func normalizeBindMount(value string) (string, bool) {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "", false
	}
	return path.Clean(value), true
}
