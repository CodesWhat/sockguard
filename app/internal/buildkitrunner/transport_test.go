package buildkitrunner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"github.com/codeswhat/sockguard/v2/app/internal/h2conn"
)

func TestUpgradeAndUnaryTrailers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/grpc" || r.Header.Get("Upgrade") != "h2c" {
			t.Error("invalid upgrade request")
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Error(err)
			return
		}
		h2conn.Serve(context.Background(), &bufferedConn{Conn: conn, reader: rw.Reader}, h2conn.ServerConfig{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(buildHeader) != "build" {
				t.Error("missing build metadata")
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Grpc-Status", "7")
			w.Header().Set("Grpc-Message", "operation%20denied")
		})})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := dialUpgrade(ctx, Options{Host: server.URL}, "/grpc", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc, err := h2conn.NewClientConn(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	_, err = unary(ctx, cc, "/"+gatewayService+"/Ping", "build", &gateway.PingRequest{})
	if err == nil || err.Error() != "gateway RPC failed (7): operation denied" {
		t.Fatalf("trailers lost: %v", err)
	}
}

func TestUpgradeCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if conn, err := dialUpgrade(ctx, Options{Host: server.URL}, "/grpc", nil); err == nil {
		conn.Close()
		t.Fatal("stalled upgrade succeeded")
	}
	if time.Since(started) > time.Second {
		t.Fatal("upgrade ignored cancellation")
	}
}

func TestInvalidTargetsFailBeforeDial(t *testing.T) {
	// A live listener stands in for the daemon. Every host below that points
	// at it would connect if validation let it through, so a connection
	// count above zero proves a dial happened. Errors are compared whole:
	// a dial failure arrives wrapped as "connect to proxy: ...", which none
	// of the expected validation messages are.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	live := ln.Addr().String()

	const (
		errScheme = "proxy host must use unix://, http://, or https://"
		errUserQF = "proxy host cannot contain credentials, query, or fragment"
		errHTTP   = "HTTP proxy host must contain only scheme and authority"
		errUnix   = "unix proxy host requires an absolute socket path"
		errTLS    = "TLS files require an https proxy host"
	)
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{"empty host", Options{Host: ""}, errScheme},
		{"unsupported scheme", Options{Host: "ftp://daemon"}, errScheme},
		{"credentials", Options{Host: "http://user:secret@" + live}, errUserQF},
		{"query", Options{Host: "http://" + live + "?x=1"}, errUserQF},
		{"fragment", Options{Host: "http://" + live + "#frag"}, errUserQF},
		{"path", Options{Host: "http://" + live + "/path"}, errHTTP},
		{"missing hostname", Options{Host: "http://"}, errHTTP},
		{"relative unix socket", Options{Host: "unix://relative"}, errUnix},
		{"unix host with path", Options{Host: "unix://host/var/run/x.sock"}, errUnix},
		{"CA file on http", Options{Host: "http://" + live, CAFile: "ca.pem"}, errTLS},
		{"client cert on http", Options{Host: "http://" + live, CertFile: "c.pem"}, errTLS},
		{"client key on http", Options{Host: "http://" + live, KeyFile: "k.pem"}, errTLS},
		{"TLS files on unix", Options{Host: "unix:///var/run/x.sock", CAFile: "ca.pem"}, errTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := dialUpgrade(t.Context(), tt.opts, "/grpc", nil)
			if err == nil {
				conn.Close()
				t.Fatalf("invalid target accepted: %+v", tt.opts)
			}
			if err.Error() != tt.want {
				t.Fatalf("error = %q, want %q", err.Error(), tt.want)
			}
		})
	}

	t.Run("unparseable host", func(t *testing.T) {
		_, err := dialUpgrade(t.Context(), Options{Host: "http://%zz"}, "/grpc", nil)
		var urlErr *url.Error
		if !errors.As(err, &urlErr) || !strings.HasPrefix(err.Error(), "parse proxy host: ") {
			t.Fatalf("error = %v, want a wrapped *url.Error from parse proxy host", err)
		}
	})

	// Close the listener and wait for the accept loop to drain before
	// reading the counter, so a late accept cannot slip past the check.
	ln.Close()
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connection(s) reached the listener, want 0: validation must fail before dialing", n)
	}
}
