//go:build darwin

package clientacl

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func strconvTimeDarwin() string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", ""), ":", ""), "0")
}

// TestPeerCredentialsFromConn_RealUnixSocket exercises both peerCredentialsFromConn
// and (via it) peerCredentialsFromFD through a real unix socket pair.
func TestPeerCredentialsFromConn_RealUnixSocket(t *testing.T) {
	socketPath := filepath.Join("/tmp", "sockguard-peercred-"+strconvTimeDarwin()+".sock")
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	var serverConn net.Conn
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case serverConn = <-accepted:
	}
	defer serverConn.Close()

	creds, ok, err := peerCredentialsFromConn(serverConn)
	if err != nil {
		t.Fatalf("peerCredentialsFromConn() error = %v", err)
	}
	if !ok {
		t.Fatal("peerCredentialsFromConn() ok = false, want true")
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Fatalf("UID = %d, want %d", creds.UID, os.Getuid())
	}
	if creds.GID != uint32(os.Getgid()) {
		t.Fatalf("GID = %d, want %d", creds.GID, os.Getgid())
	}
	if creds.PID <= 0 {
		t.Fatalf("PID = %d, want > 0", creds.PID)
	}
}

// TestPeerCredentialsFromConn_NonUnixConn verifies that a non-unix connection
// returns ok=false with no error.
func TestPeerCredentialsFromConn_NonUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer client.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	_, ok, err := peerCredentialsFromConn(serverConn)
	if err != nil {
		t.Fatalf("peerCredentialsFromConn(tcp) error = %v, want nil", err)
	}
	if ok {
		t.Fatal("peerCredentialsFromConn(tcp) ok = true, want false")
	}
}
