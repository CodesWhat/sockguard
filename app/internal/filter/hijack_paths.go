package filter

import "github.com/codeswhat/sockguard/app/internal/apipath"

// IsHijackCandidatePath reports whether method+normalizedPath is one of the
// connection-upgrade endpoints — Docker-compat or libpod — that
// internal/proxy's hijack layer must recognize identically to this package's
// own routing.
//
// Thin wrapper over apipath.IsHijackCandidatePath, which owns the definition
// so both sides of the filter/proxy package split read one matcher rather
// than each keeping its own. The name stays here because internal/proxy
// already calls it, and because the cross-package parity invariant test in
// internal/proxy exercises the real production matchers through it.
func IsHijackCandidatePath(method, normalizedPath string) bool {
	return apipath.IsHijackCandidatePath(method, normalizedPath)
}
