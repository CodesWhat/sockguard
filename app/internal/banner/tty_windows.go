//go:build windows

package banner

import "io"

// terminalCols on Windows is a no-op; sockguard ships as a Linux
// container and runtime TTY probing via ioctl is POSIX-specific.
// Returning 0 tells the banner renderer to fall back to the stock
// left-aligned art, which still renders correctly in any terminal.
func terminalCols(w io.Writer) int { return 0 }
