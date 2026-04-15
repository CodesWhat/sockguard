//go:build linux

package clientacl

import (
	"net"
	"syscall"
)

type unixPeerCredentials struct {
	UID uint32
	GID uint32
	PID int32
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
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			lookupErr = err
			return
		}
		creds = unixPeerCredentials{
			UID: ucred.Uid,
			GID: ucred.Gid,
			PID: ucred.Pid,
		}
	}); err != nil {
		return unixPeerCredentials{}, true, err
	}
	if lookupErr != nil {
		return unixPeerCredentials{}, true, lookupErr
	}

	return creds, true, nil
}
