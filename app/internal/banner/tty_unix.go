//go:build !windows

package banner

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

var ioctlGetWinsize = func(fd uintptr, ws *winsize) syscall.Errno {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)),
	)
	return errno
}

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
	// TIOCGWINSZ is the POSIX way to read a terminal's column count
	// and requires passing a pointer to a kernel-filled struct. The
	// unsafe.Pointer conversion is exactly what syscall.Syscall
	// documents for this pattern, and the write only ever lands in
	// the local `ws` struct above.
	//nolint:gosec // G103: intentional unsafe.Pointer for ioctl(TIOCGWINSZ)
	errno := ioctlGetWinsize(f.Fd(), &ws)
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
