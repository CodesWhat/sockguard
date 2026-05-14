//go:build !windows

package reload

import (
	"os"
	"syscall"
)

// inodeOf extracts the underlying inode number from a FileInfo on Unix-like
// systems. The inode catches atomic-rename edits (vim, gofmt, kustomize)
// where size and mtime can roundtrip but the file is a new inode. Returns 0
// on backends that do not expose a syscall.Stat_t — the poll fallback then
// degrades to size+mtime detection only, which is still enough for most
// editors' direct-write paths.
func inodeOf(info os.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0
	}
	return uint64(stat.Ino)
}
