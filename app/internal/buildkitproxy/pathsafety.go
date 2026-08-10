// Package buildkitproxy — this file carries Phase 5 (issue #185)'s path
// validation for fsutil Stat entries carried over FileSync/DiffCopy: see
// filesync.go for where it's consulted.
package buildkitproxy

import "strings"

// validateFsutilPath rejects a fsutil Stat.Path or Stat.Linkname value that
// could escape the directory sockguard is mediating a sync for, or that is
// otherwise structurally unsafe to hand the daemon. All paths fsutil
// transfers over the wire are normalized to unix-style ('/'-separated,
// relative) paths — see tonistiigi/fsutil's own receive-side path handling
// — so this checks exactly that shape:
//
//   - empty: rejected (buildkit_path_rejected) — a non-terminator Stat entry
//     naming no path at all is not a legitimate protocol message.
//   - longer than maxLen (when maxLen > 0): rejected — a single
//     pathologically long path is a resource-exhaustion/parsing-cost
//     concern independent of file count or data volume (Limits.
//     MaxFileSyncPathLength).
//   - contains a NUL byte: rejected outright — defense in depth against
//     any downstream C-string-based path handling sockguard doesn't control.
//   - absolute (a leading '/'): rejected — the receiving side of a
//     FileSync/DiffCopy stream (the daemon) resolves entries relative to
//     its own destination directory; an absolute path is meaningless as a
//     relative entry and, for any implementation that ever treated it
//     otherwise, is exactly the trick this check exists to close.
//   - contains a ".." path segment: rejected — the same directory-escape
//     concern, whether the ".." appears at the front, middle, or end of the
//     path.
//
// Applied identically to both Stat.Path (every entry) and Stat.Linkname
// (only symlink entries, which carry a non-empty Linkname) — see filesync.go
// — per the #185 synthesis's "reject symlink trickery to the extent the
// protocol exposes it": a symlink whose OWN path is safe but whose TARGET
// escapes the synced directory is the same class of attack via one more
// level of indirection, so the same rule applies to both fields. This is
// deliberately stricter than what a real filesystem would consider invalid
// (an absolute symlink target is unremarkable on disk) — sockguard's job
// here is constraining what a BuildKit-mediated sync can smuggle past it,
// not reproducing every legitimate filesystem semantic.
func validateFsutilPath(path string, maxLen int) *mediationDenial {
	if path == "" {
		return deny(grpcCodeInvalidArgument, "buildkit_path_rejected", "FileSync entry path must not be empty")
	}
	if maxLen > 0 && len(path) > maxLen {
		return deny(grpcCodeResourceExhausted, "buildkit_path_rejected", "FileSync entry path exceeds sockguard's configured length limit")
	}
	if strings.ContainsRune(path, 0) {
		return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "FileSync entry path is malformed")
	}
	if strings.HasPrefix(path, "/") {
		return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "absolute FileSync entry paths are not permitted")
	}
	for part := range strings.SplitSeq(path, "/") {
		if part == ".." {
			return deny(grpcCodePermissionDenied, "buildkit_path_rejected", "FileSync entry path traversal is not permitted")
		}
	}
	return nil
}
