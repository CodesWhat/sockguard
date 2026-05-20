package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// BenchmarkHijackUpgrade measures the full hijack path: upstream dial,
// HTTP upgrade negotiation (101 Switching Protocols), takeover of the client
// connection, and a small bidirectional copy through the hijack proxy.
//
// Each iteration opens a fresh TCP client and unix-socket upstream connection.
// The bench therefore includes the cost of two dials per iteration, which is
// the realistic per-attach/per-exec-start startup cost.
func BenchmarkHijackUpgrade(b *testing.B) {
	dir, err := os.MkdirTemp("", "sockguard-hijack-bench-*")
	if err != nil {
		b.Fatalf("mktmp: %v", err)
	}
	defer os.RemoveAll(dir)
	upstreamSock := filepath.Join(dir, "docker.sock")
	upstream, err := net.Listen("unix", upstreamSock)
	if err != nil {
		b.Fatalf("upstream listen: %v", err)
	}
	defer upstream.Close()

	const echoPayload = "ok"
	var stopped atomic.Bool
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				if stopped.Load() {
					return
				}
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				req.Body.Close()

				resp := &http.Response{
					StatusCode: http.StatusSwitchingProtocols,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     http.Header{},
				}
				resp.Header.Set("Connection", "Upgrade")
				resp.Header.Set("Upgrade", "tcp")
				resp.Header.Set("Content-Type", "application/vnd.docker.raw-stream")
				if err := resp.Write(c); err != nil {
					return
				}

				buf := make([]byte, 64)
				n, _ := br.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
				_, _ = c.Write([]byte(echoPayload))
			}(conn)
		}
	}()
	defer func() {
		stopped.Store(true)
		upstream.Close()
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.Errorf("next handler should not be called for hijack endpoint")
	})
	handler := HijackHandler(upstreamSock, logger, next)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("client listen: %v", err)
	}
	defer clientLn.Close()
	srv := &http.Server{Handler: handler}
	go srv.Serve(clientLn)
	defer srv.Close()

	clientAddr := clientLn.Addr().String()
	reqBytes := []byte("POST /containers/abc/attach?stream=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
	clientMsg := []byte("ping")
	expected := make([]byte, len(clientMsg)+len(echoPayload))

	if err := doOneHijack(clientAddr, reqBytes, clientMsg, expected); err != nil {
		b.Fatalf("warmup: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := doOneHijack(clientAddr, reqBytes, clientMsg, expected); err != nil {
			b.Fatalf("iter: %v", err)
		}
	}
}

func doOneHijack(addr string, req, msg, scratch []byte) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(req); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return io.EOF
	}
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	if _, err := io.ReadFull(br, scratch); err != nil {
		return err
	}
	return nil
}
