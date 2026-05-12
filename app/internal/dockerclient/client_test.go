package dockerclient_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/dockerclient"
)

// tempSocketPath returns a temp file path for a unix socket, removing any
// stale file first. The caller is responsible for cleanup.
func tempSocketPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(os.TempDir(), fmt.Sprintf("dockerclient-test-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(p)
	return p
}

// startUnixServer listens on socketPath, serves handler, and registers cleanup.
func startUnixServer(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})
}

func TestNewHappyPath(t *testing.T) {
	socketPath := tempSocketPath(t)
	startUnixServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	client, err := dockerclient.New(socketPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://docker/_ping", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestNewDialTimeout(t *testing.T) {
	// Point at a non-existent socket so the dial fails fast.
	socketPath := tempSocketPath(t)

	client, err := dockerclient.New(socketPath, dockerclient.WithDialTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://docker/_ping", nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected dial error for missing socket")
	}
}

func TestNewResponseHeaderTimeout(t *testing.T) {
	socketPath := tempSocketPath(t)
	// Handler that never writes headers — triggers ResponseHeaderTimeout.
	startUnixServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))

	client, err := dockerclient.New(socketPath, dockerclient.WithResponseHeaderTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://docker/_ping", nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected response header timeout error")
	}
}

func TestNewConcurrentFanOut(t *testing.T) {
	const workers = 20
	socketPath := tempSocketPath(t)
	startUnixServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	client, err := dockerclient.New(socketPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://docker/_ping", nil)
			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				errs <- fmt.Errorf("status = %d, want 204", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}
}

func TestNewTransportValues(t *testing.T) {
	socketPath := tempSocketPath(t)

	client, err := dockerclient.New(socketPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}
	if tr.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 10", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
}

func TestNewReturnsIndependentClients(t *testing.T) {
	socketPath := tempSocketPath(t)
	startUnixServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	c1, err1 := dockerclient.New(socketPath)
	c2, err2 := dockerclient.New(socketPath)
	if err1 != nil || err2 != nil {
		t.Fatalf("New() errors: %v, %v", err1, err2)
	}
	if c1 == c2 {
		t.Fatal("expected New() to return independent client instances")
	}
}
