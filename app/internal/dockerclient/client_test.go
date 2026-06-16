package dockerclient_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerclient"
	"github.com/codeswhat/sockguard/internal/upstream"
)

// TestNew_UsesResolverTransport pins the contract that dockerclient.New wires
// the client to the shared upstream resolver. Pool tunings now live on the
// resolver's per-endpoint transport (see internal/upstream); this package only
// guarantees the side-channel client routes through that resolver so its
// inspect calls follow the same active endpoint as the proxy under failover.
func TestNew_UsesResolverTransport(t *testing.T) {
	t.Parallel()
	client := dockerclient.New("/var/run/docker.sock")

	if _, ok := client.Transport.(*upstream.Resolver); !ok {
		t.Fatalf("Transport is %T, want *upstream.Resolver", client.Transport)
	}
}

// TestNewWithRoundTripper_UsesGivenTransport verifies the explicit-RoundTripper
// constructor installs exactly the transport it is handed, so the serve wiring
// can share one resolver across the proxy and every side channel.
func TestNewWithRoundTripper_UsesGivenTransport(t *testing.T) {
	t.Parallel()
	rt := upstream.NewSingleSocket("/var/run/docker.sock")
	client := dockerclient.NewWithRoundTripper(rt)

	if client.Transport != rt {
		t.Fatalf("Transport = %p, want the supplied resolver %p", client.Transport, rt)
	}
}

// TestNew_ActualUnixDial exercises the configured dialer end-to-end: it stands
// up a unix-socket listener, asks the resolver-backed client to dial it, and
// verifies the listener actually accepted a connection. This guards against
// regressions where the dialer is misconfigured (wrong network family, wrong
// path source) but the transport shape still looks right.
func TestNew_ActualUnixDial(t *testing.T) {
	t.Parallel()
	sockPath := filepath.Join(t.TempDir(), "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen(unix, %q): %v", sockPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	// The resolver ignores the network/address arguments and dials its active
	// endpoint (the configured unix socket).
	resolver := dockerclient.New(sockPath).Transport.(*upstream.Resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := resolver.DialContext(ctx, "tcp", "docker:0")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never accepted a connection from the dockerclient transport")
	}
}
