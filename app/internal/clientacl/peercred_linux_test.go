//go:build linux

package clientacl

import (
	"math"
	"strings"
	"syscall"
	"testing"
)

type fakeRawConn struct {
	fd         uintptr
	controlErr error
}

func (f fakeRawConn) Control(fn func(uintptr)) error {
	if f.controlErr != nil {
		return f.controlErr
	}
	fn(f.fd)
	return nil
}

func (fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error { return nil }

type fakeSyscallConner struct {
	raw syscall.RawConn
	err error
}

func (f fakeSyscallConner) SyscallConn() (syscall.RawConn, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.raw, nil
}

func TestPeerCredentialsFromSyscallerRejectsFDOverflow(t *testing.T) {
	_, err := peerCredentialsFromSyscaller(fakeSyscallConner{
		raw: fakeRawConn{fd: uintptr(math.MaxInt) + 1},
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds int range") {
		t.Fatalf("peerCredentialsFromSyscaller() error = %v, want fd range error", err)
	}
}
