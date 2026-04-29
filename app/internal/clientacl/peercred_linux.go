//go:build linux

package clientacl

import (
	"fmt"
	"math"
	"net"
	"syscall"
)

type unixPeerCredentials struct {
	UID uint32
	GID uint32
	PID int32
}

type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

var rawConnControl = func(raw syscall.RawConn, fn func(uintptr)) error {
	return raw.Control(fn)
}

var readPeerUCred = func(fd int) (*syscall.Ucred, error) {
	return syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}

func peerCredentialsFromConn(conn net.Conn) (unixPeerCredentials, bool, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return unixPeerCredentials{}, false, nil
	}

	creds, err := peerCredentialsFromSyscaller(unixConn)
	if err != nil {
		return unixPeerCredentials{}, true, err
	}
	return creds, true, nil
}

func peerCredentialsFromSyscaller(conn syscallConner) (unixPeerCredentials, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return unixPeerCredentials{}, err
	}

	var creds unixPeerCredentials
	var lookupErr error
	if err := rawConnControl(raw, func(fd uintptr) {
		socketFD, ok := socketFDFromRawConn(fd)
		if !ok {
			lookupErr = fmt.Errorf("socket file descriptor %d exceeds int range", fd)
			return
		}
		creds, lookupErr = peerCredentialsFromFD(socketFD)
	}); err != nil {
		return unixPeerCredentials{}, err
	}
	if lookupErr != nil {
		return unixPeerCredentials{}, lookupErr
	}

	return creds, nil
}

func socketFDFromRawConn(fd uintptr) (int, bool) {
	if fd > uintptr(math.MaxInt) {
		return 0, false
	}
	return int(fd), true //nolint:gosec // G115: fd is range-checked against math.MaxInt above.
}

func peerCredentialsFromFD(fd int) (unixPeerCredentials, error) {
	ucred, err := readPeerUCred(fd)
	if err != nil {
		return unixPeerCredentials{}, err
	}
	return unixPeerCredentials{
		UID: ucred.Uid,
		GID: ucred.Gid,
		PID: ucred.Pid,
	}, nil
}
