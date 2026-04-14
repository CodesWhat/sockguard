//go:build !windows

package banner

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// winsize mirrors struct winsize from <sys/ioctl.h>. Only Col is
// used; the other fields are present so the kernel fills the layout
// the ioctl expects.
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// terminalCols returns the column width of w when w is an *os.File
// attached to a terminal, or 0 when it is not (pipes, buffers, etc).
// Non-TTY writers produce 0 so piped output and tests keep using the
// original left-aligned banner without any centering.
func terminalCols(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return 0
	}
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
