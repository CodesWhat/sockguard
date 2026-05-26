package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunBenchmarkLetsInflightRequestsFinish(t *testing.T) {
	t.Parallel()

	dir, err := os.MkdirTemp("/tmp", "sg-loadgen-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	socket := filepath.Join(dir, "mock.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Millisecond)
			_, _ = w.Write([]byte("OK"))
		}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server.Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
		_ = os.Remove(socket)
	})

	got := runBenchmark(benchmarkOptions{
		Socket:      socket,
		Method:      http.MethodGet,
		Path:        "/_ping",
		Concurrency: 8,
		Duration:    20 * time.Millisecond,
		Scenario:    "test",
	})

	if got.TotalRequests == 0 {
		t.Fatal("TotalRequests = 0, want at least one completed request")
	}
	if got.ErrorRequests != 0 {
		t.Fatalf("ErrorRequests = %d, want 0", got.ErrorRequests)
	}
	if len(got.ErrorCounts) != 0 {
		t.Fatalf("ErrorCounts = %#v, want empty", got.ErrorCounts)
	}
	if got.StatusCodeCounts[http.StatusOK] != got.TotalRequests {
		t.Fatalf("200 responses = %d, total requests = %d", got.StatusCodeCounts[http.StatusOK], got.TotalRequests)
	}
}
