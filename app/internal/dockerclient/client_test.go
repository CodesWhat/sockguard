package dockerclient_test

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerclient"
)

func TestNew_TransportValues(t *testing.T) {
	client := dockerclient.New("/var/run/docker.sock")

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}

	if got, want := tr.MaxIdleConnsPerHost, 10; got != want {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", got, want)
	}

	if got, want := tr.IdleConnTimeout, 90*time.Second; got != want {
		t.Errorf("IdleConnTimeout = %v, want %v", got, want)
	}
}

func TestNew_DialContextSet(t *testing.T) {
	client := dockerclient.New("/var/run/docker.sock")

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}

	if tr.DialContext == nil {
		t.Error("DialContext is nil, want a unix-socket dialer")
	}
}

// TestNew_ActualUnixDial exercises the configured DialContext end-to-end:
// it stands up a unix-socket listener, asks the client to dial it, and
// verifies the listener actually accepted a connection. This guards against
// regressions where the dialer is misconfigured (wrong network family,
// wrong path source) but the transport shape still looks right.
func TestNew_ActualUnixDial(t *testing.T) {
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

	tr := dockerclient.New(sockPath).Transport.(*http.Transport)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := tr.DialContext(ctx, "tcp", "docker:0")
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
