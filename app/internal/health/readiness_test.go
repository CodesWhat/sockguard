package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/dockerclient"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

func startUnixUpstream(t *testing.T, handler http.Handler) string {
	t.Helper()
	// macOS caps sun_path at 104 bytes; t.TempDir() under /var/folders
	// overflows it, so anchor the socket in a short os.MkdirTemp dir.
	dir, err := os.MkdirTemp("/tmp", "sg-health")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	return sock
}

func TestProbeUpstreamAPI(t *testing.T) {
	t.Parallel()

	t.Run("2xx is ready", func(t *testing.T) {
		t.Parallel()
		sock := startUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/containers/json" {
				t.Errorf("unexpected probe path %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
		}))
		status, err := probeUpstreamAPI(context.Background(), dockerclient.New(sock))
		if err != nil || status != "ready" {
			t.Fatalf("got (%q, %v), want (ready, nil)", status, err)
		}
	})

	t.Run("non-2xx is unreachable", func(t *testing.T) {
		t.Parallel()
		sock := startUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		status, err := probeUpstreamAPI(context.Background(), dockerclient.New(sock))
		if err == nil || status != "unreachable" {
			t.Fatalf("got (%q, %v), want (unreachable, non-nil err)", status, err)
		}
	})

	t.Run("dial failure is unreachable", func(t *testing.T) {
		t.Parallel()
		sock := filepath.Join(t.TempDir(), "absent.sock")
		status, err := probeUpstreamAPI(context.Background(), dockerclient.New(sock))
		if err == nil || status != "unreachable" {
			t.Fatalf("got (%q, %v), want (unreachable, non-nil err)", status, err)
		}
	})

	t.Run("300 boundary is unreachable", func(t *testing.T) {
		t.Parallel()
		// 300 is the first non-2xx status; the range check is "< 200 || >=
		// 300", so this must fail closed. A mutant turning ">= 300" into
		// "> 300" would treat exactly 300 as ready.
		sock := startUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusMultipleChoices)
		}))
		status, err := probeUpstreamAPI(context.Background(), dockerclient.New(sock))
		if err == nil || status != "unreachable" {
			t.Fatalf("got (%q, %v), want (unreachable, non-nil err) for status 300", status, err)
		}
	})
}

func TestNewReadinessMonitorTimeoutFallback(t *testing.T) {
	t.Parallel()

	t.Run("non-positive timeout falls back to the default dial timeout", func(t *testing.T) {
		t.Parallel()
		m := NewReadinessMonitor("/tmp/upstream.sock", time.Now(), testLogger(), 0)
		if got := m.checker.timeout; got != healthDialTimeout {
			t.Fatalf("checker timeout = %v, want fallback %v", got, healthDialTimeout)
		}
	})

	t.Run("positive timeout passes through unchanged", func(t *testing.T) {
		t.Parallel()
		want := 5 * time.Second
		m := NewReadinessMonitor("/tmp/upstream.sock", time.Now(), testLogger(), want)
		if got := m.checker.timeout; got != want {
			t.Fatalf("checker timeout = %v, want %v (no fallback)", got, want)
		}
	})
}

func TestNewReadinessMonitorWithRoundTripperTimeoutFallback(t *testing.T) {
	t.Parallel()

	t.Run("non-positive timeout falls back to the default dial timeout", func(t *testing.T) {
		t.Parallel()
		m := NewReadinessMonitorWithRoundTripper("label", http.DefaultTransport, time.Now(), testLogger(), 0)
		if got := m.checker.timeout; got != healthDialTimeout {
			t.Fatalf("checker timeout = %v, want fallback %v", got, healthDialTimeout)
		}
	})

	t.Run("positive timeout passes through unchanged", func(t *testing.T) {
		t.Parallel()
		want := 5 * time.Second
		m := NewReadinessMonitorWithRoundTripper("label", http.DefaultTransport, time.Now(), testLogger(), want)
		if got := m.checker.timeout; got != want {
			t.Fatalf("checker timeout = %v, want %v (no fallback)", got, want)
		}
	})
}

func TestReadinessMonitorHandler(t *testing.T) {
	t.Parallel()

	t.Run("ready probe returns 200", func(t *testing.T) {
		t.Parallel()
		checker := newReadinessChecker(time.Second, time.Now, func(context.Context) (string, error) {
			return "ready", nil
		})
		m := newMonitorWithChecker("/unused.sock", time.Now(), testLogger(), checker)
		rec := httptest.NewRecorder()
		m.Handler()(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("failing probe returns 503", func(t *testing.T) {
		t.Parallel()
		checker := newReadinessChecker(time.Second, time.Now, func(context.Context) (string, error) {
			return "unreachable", errors.New("api wedged")
		})
		m := newMonitorWithChecker("/unused.sock", time.Now(), testLogger(), checker)
		rec := httptest.NewRecorder()
		m.Handler()(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}
	})
}

func TestNewReadinessMonitorProbesAPIEndToEnd(t *testing.T) {
	t.Parallel()
	sock := startUnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	m := NewReadinessMonitor(sock, time.Now(), testLogger(), time.Second)
	rec := httptest.NewRecorder()
	m.Handler()(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadinessMonitorPreservesUpstreamBasePath(t *testing.T) {
	t.Parallel()
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/gateway%2Fdocker/containers/json?limit=1" {
			t.Errorf("RequestURI = %q, want prefixed readiness path", r.RequestURI)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(daemon.Close)
	ep, err := upstream.BuildEndpoint(upstream.EndpointSpec{
		Address:               "tcp://" + strings.TrimPrefix(daemon.URL, "http://") + "/gateway%2Fdocker",
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	resolver, err := upstream.New([]upstream.Endpoint{ep}, upstream.Options{Interval: -1})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	m := NewReadinessMonitorWithRoundTripper(ep.String(), resolver, time.Now(), testLogger(), time.Second)
	rec := httptest.NewRecorder()
	m.Handler()(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
