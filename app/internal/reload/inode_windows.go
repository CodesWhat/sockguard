//go:build windows

package reload

import "os"

// inodeOf is a no-op on Windows: NTFS doesn't expose stat-style inode numbers
// through os.FileInfo.Sys(), and the watch path on Windows uses ReadDirectoryChangesW
// rather than inotify so atomic-rename detection happens at a different layer.
func inodeOf(_ os.FileInfo) uint64 { return 0 }
