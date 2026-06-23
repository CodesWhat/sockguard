package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/testcert"
)

// startTLSEchoServer starts a TLS listener using the bundle's server cert and
// returns its address. Each accepted connection completes the handshake and
// echoes a single read back before closing. The listener is closed on cleanup.
func startTLSEchoServer(t *testing.T, bundle testcert.Bundle) string {
	t.Helper()
	serverCert, err := tls.LoadX509KeyPair(bundle.ServerCertFile, bundle.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestEndpointDial_TLSHandshakeSucceeds exercises Endpoint.dial end-to-end over a
// real TLS server: the handshake must complete inside dial and the returned conn
// must be a *tls.Conn carrying an already-encrypted, working pipe.
func TestEndpointDial_TLSHandshakeSucceeds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	addr := startTLSEchoServer(t, bundle)

	ep, err := BuildEndpoint(EndpointSpec{
		Address:    "tcp://" + addr,
		CAFile:     bundle.CAFile,
		CertFile:   bundle.ClientCertFile,
		KeyFile:    bundle.ClientKeyFile,
		ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := ep.dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tconn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dial returned %T, want *tls.Conn", conn)
	}
	if !tconn.ConnectionState().HandshakeComplete {
		t.Fatal("handshake not complete on returned conn")
	}

	// Round-trip a byte to confirm the encrypted pipe actually carries data.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 'x' {
		t.Fatalf("echo = %q, want x", buf)
	}
}

// TestEndpointDial_TLSHandshakeFailureReturnsNoConn verifies the negative path:
// a verification failure (server cert valid for 127.0.0.1 but the client expects
// a different name) returns an error and no connection. dial closes the raw conn
// it dialed before returning, so a failed handshake leaks no socket.
func TestEndpointDial_TLSHandshakeFailureReturnsNoConn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	addr := startTLSEchoServer(t, bundle)

	ep, err := BuildEndpoint(EndpointSpec{
		Address:    "tcp://" + addr,
		CAFile:     bundle.CAFile,
		CertFile:   bundle.ClientCertFile,
		KeyFile:    bundle.ClientKeyFile,
		ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	// Force a verification mismatch: the server cert is for 127.0.0.1.
	ep.TLSConfig.ServerName = "wrong.example.invalid"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := ep.dial(ctx)
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded, want a TLS verification failure")
	}
	if conn != nil {
		t.Fatalf("dial returned a non-nil conn alongside its error: %T", conn)
	}
}
