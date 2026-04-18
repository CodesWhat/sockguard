//go:build darwin

package clientacl

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestPeerCredentialsFromSyscallerSyscallConnError(t *testing.T) {
	sentinel := errors.New("syscall conn failed")

	_, err := peerCredentialsFromSyscaller(fakeSyscallConner{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("peerCredentialsFromSyscaller() error = %v, want %v", err, sentinel)
	}
}

func TestPeerCredentialsFromSyscallerControlError(t *testing.T) {
	sentinel := errors.New("control failed")

	_, err := peerCredentialsFromSyscaller(fakeSyscallConner{
		raw: fakeRawConn{controlErr: sentinel},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("peerCredentialsFromSyscaller() error = %v, want %v", err, sentinel)
	}
}

func TestPeerCredentialsFromSyscallerLookupError(t *testing.T) {
	sentinel := errors.New("lookup failed")

	oldReadPeerXUCred := readPeerXUCred
	readPeerXUCred = func(int, *xucred) error { return sentinel }
	t.Cleanup(func() { readPeerXUCred = oldReadPeerXUCred })

	_, err := peerCredentialsFromSyscaller(fakeSyscallConner{
		raw: fakeRawConn{fd: 1},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("peerCredentialsFromSyscaller() error = %v, want %v", err, sentinel)
	}
}

func TestPeerCredentialsFromFDSyscallError(t *testing.T) {
	sentinel := errors.New("getsockopt xucred failed")

	oldReadPeerXUCred := readPeerXUCred
	readPeerXUCred = func(int, *xucred) error { return sentinel }
	t.Cleanup(func() { readPeerXUCred = oldReadPeerXUCred })

	_, err := peerCredentialsFromFD(1)
	if !errors.Is(err, sentinel) {
		t.Fatalf("peerCredentialsFromFD() error = %v, want %v", err, sentinel)
	}
}

func TestReadPeerXUCredReturnsErrno(t *testing.T) {
	var raw xucred

	err := readPeerXUCred(-1, &raw)
	if err == nil {
		t.Fatal("readPeerXUCred() error = nil, want errno for an invalid fd")
	}
}

func TestPeerCredentialsFromFDBadVersion(t *testing.T) {
	oldReadPeerXUCred := readPeerXUCred
	readPeerXUCred = func(_ int, raw *xucred) error {
		raw.Version = xucredVersion + 1
		return nil
	}
	t.Cleanup(func() { readPeerXUCred = oldReadPeerXUCred })

	_, err := peerCredentialsFromFD(1)
	if err == nil || !strings.Contains(err.Error(), "unexpected xucred version") {
		t.Fatalf("peerCredentialsFromFD() error = %v, want unexpected xucred version", err)
	}
}

func TestPeerCredentialsFromFDPIDError(t *testing.T) {
	sentinel := errors.New("peer pid failed")

	oldReadPeerXUCred := readPeerXUCred
	oldReadPeerPID := readPeerPID
	readPeerXUCred = func(_ int, raw *xucred) error {
		raw.Version = xucredVersion
		raw.UID = 1000
		raw.NGroups = 1
		raw.Groups[0] = 1001
		return nil
	}
	readPeerPID = func(int) (int, error) { return 0, sentinel }
	t.Cleanup(func() {
		readPeerXUCred = oldReadPeerXUCred
		readPeerPID = oldReadPeerPID
	})

	_, err := peerCredentialsFromFD(1)
	if !errors.Is(err, sentinel) {
		t.Fatalf("peerCredentialsFromFD() error = %v, want %v", err, sentinel)
	}
}

func TestConnContextStoresUnixPeerError(t *testing.T) {
	socketPath := filepath.Join("/tmp", "sockguard-peercred-connctx-"+strconvTimeDarwin()+".sock")
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
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	sentinel := errors.New("peer lookup failed")
	oldReadPeerXUCred := readPeerXUCred
	readPeerXUCred = func(int, *xucred) error { return sentinel }
	t.Cleanup(func() { readPeerXUCred = oldReadPeerXUCred })

	ctx := ConnContext(context.Background(), serverConn)
	identity, _ := ctx.Value(contextKeyConnectionIdentity).(connectionIdentity)
	if !errors.Is(identity.unixPeerErr, sentinel) {
		t.Fatalf("unixPeerErr = %v, want %v", identity.unixPeerErr, sentinel)
	}
}
