package filter

import "net/http"

// IsHijackCandidatePath reports whether method+normalizedPath is one of the
// connection-upgrade endpoints — Docker-compat or libpod — that
// internal/proxy's hijack layer must recognize identically to this package's
// own routing.
//
// Exported (unlike the individual isXxxPath matchers it composes) solely so
// the cross-package parity invariant test in internal/proxy can exercise the
// real production matchers on both sides of the filter/proxy package split.
// A path this reports true for that the hijack layer treats as false (or the
// reverse) is a two-parser-drift smuggling bug, not a cosmetic mismatch: see
// internal/proxy's TestHijackFilterParity, and #148's design doc ("Agreed
// core" item 3) for why this must hold for the libpod namespace too.
func IsHijackCandidatePath(method, normalizedPath string) bool {
	if method != http.MethodPost {
		return false
	}
	return isContainerAttachPath(normalizedPath) ||
		isExecStartPath(normalizedPath) ||
		isLibpodContainerAttachPath(normalizedPath) ||
		isLibpodExecStartPath(normalizedPath)
}
