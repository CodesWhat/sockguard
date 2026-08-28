//go:build unix

package boundedio

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := ReadFile(path, 4)
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("ReadFile FIFO error = %v, want ErrNotRegular", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFile blocked while opening a FIFO")
	}
}
