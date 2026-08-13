//go:build !linux && !darwin

package clientacl

import "net"

type unixPeerCredentials struct {
	UID uint32
	GID uint32
	PID int32
}

func peerCredentialsFromConn(net.Conn) (unixPeerCredentials, bool, error) {
	return unixPeerCredentials{}, false, nil
}
