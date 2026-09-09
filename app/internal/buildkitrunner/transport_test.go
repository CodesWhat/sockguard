package buildkitrunner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	"golang.org/x/net/http2"
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
		(&http2.Server{}).ServeConn(&bufferedConn{Conn: conn, reader: rw.Reader}, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	cc, err := (&http2.Transport{}).NewClientConn(conn)
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
	for _, host := range []string{"", "ftp://daemon", "http://user:secret@daemon", "http://daemon/path", "http://daemon?x=1", "unix://relative"} {
		if c, err := dialUpgrade(t.Context(), Options{Host: host}, "/grpc", nil); err == nil {
			c.Close()
			t.Fatalf("invalid host accepted: %s", host)
		}
	}
}
