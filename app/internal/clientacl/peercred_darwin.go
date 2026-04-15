//go:build darwin

package clientacl

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	solLocal            = 0
	localPeercredOption = 0x001
	localPeerPIDOption  = 0x002
	xucredVersion       = 0
	xucredGroupCount    = 16
)

type unixPeerCredentials struct {
	UID uint32
	GID uint32
	PID int32
}

type xucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	_       int16
	Groups  [xucredGroupCount]uint32
}

func peerCredentialsFromConn(conn net.Conn) (unixPeerCredentials, bool, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return unixPeerCredentials{}, false, nil
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return unixPeerCredentials{}, true, err
	}

	var creds unixPeerCredentials
	var lookupErr error
	if err := raw.Control(func(fd uintptr) {
		creds, lookupErr = peerCredentialsFromFD(int(fd))
	}); err != nil {
		return unixPeerCredentials{}, true, err
	}
	if lookupErr != nil {
		return unixPeerCredentials{}, true, lookupErr
	}

	return creds, true, nil
}

func peerCredentialsFromFD(fd int) (unixPeerCredentials, error) {
	var rawCreds xucred
	size := uint32(unsafe.Sizeof(rawCreds))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solLocal),
		uintptr(localPeercredOption),
		uintptr(unsafe.Pointer(&rawCreds)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return unixPeerCredentials{}, errno
	}
	if rawCreds.Version != xucredVersion {
		return unixPeerCredentials{}, fmt.Errorf("unexpected xucred version %d", rawCreds.Version)
	}

	pid, err := syscall.GetsockoptInt(fd, solLocal, localPeerPIDOption)
	if err != nil {
		return unixPeerCredentials{}, err
	}

	var gid uint32
	if rawCreds.NGroups > 0 {
		gid = rawCreds.Groups[0]
	}

	return unixPeerCredentials{
		UID: rawCreds.UID,
		GID: gid,
		PID: int32(pid),
	}, nil
}
