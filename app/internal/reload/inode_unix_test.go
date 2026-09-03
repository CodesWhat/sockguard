//go:build !windows

package reload

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestInodeOf covers the two guard conditions in inodeOf: the nil FileInfo
// short-circuit and the failed/nil type-assertion short-circuit. Both guard
// against otherwise-legitimate FileInfo/Sys() shapes returning the wrong
// value, so the boundary is a real file whose *syscall.Stat_t is present and
// non-nil versus a nil FileInfo.
func TestInodeOf(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		t.Fatalf("expected *syscall.Stat_t from Sys(), got %#v", info.Sys())
	}
	wantInode := uint64(stat.Ino)
	if wantInode == 0 {
		t.Fatal("test file has zero inode; cannot exercise the non-nil path meaningfully")
	}

	t.Run("nil FileInfo returns zero", func(t *testing.T) {
		t.Parallel()
		if got := inodeOf(nil); got != 0 {
			t.Fatalf("inodeOf(nil) = %d, want 0", got)
		}
	})

	t.Run("real FileInfo returns the actual inode", func(t *testing.T) {
		t.Parallel()
		if got := inodeOf(info); got != wantInode {
			t.Fatalf("inodeOf(info) = %d, want %d", got, wantInode)
		}
	})
}
