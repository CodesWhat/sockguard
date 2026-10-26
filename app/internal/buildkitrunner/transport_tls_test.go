package buildkitrunner

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/testcert"
)

func TestUpgradeMutualTLSAndBufferedReply(t *testing.T) {
	bundle, err := testcert.WriteMutualTLSBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(bundle.ServerCertFile, bundle.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 || r.Header.Get("X-Test-Session") != "session" {
			t.Error("upgrade lost verified identity or session advertisement")
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nreply"); err != nil {
			t.Error(err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Error(err)
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	valid := Options{Host: server.URL, CAFile: bundle.CAFile, CertFile: bundle.ClientCertFile, KeyFile: bundle.ClientKeyFile}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"untrusted server", Options{Host: server.URL, CertFile: valid.CertFile, KeyFile: valid.KeyFile}},
		{"missing client identity", Options{Host: server.URL, CAFile: valid.CAFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := dialUpgrade(t.Context(), tc.opts, "/grpc", nil)
			if err == nil {
				conn.Close()
				t.Fatal("unverified connection accepted")
			}
		})
	}
	headers := http.Header{"X-Test-Session": {"session"}}
	conn, err := dialUpgrade(t.Context(), valid, "/session", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "reply" {
		t.Fatalf("buffered upgrade data = %q, %v", got, err)
	}
	if headers.Get("Connection") != "" || headers.Get("Upgrade") != "" {
		t.Fatal("upgrade mutated caller headers")
	}
}

func TestTLSConfigurationRejectsIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"certificate only", Options{CertFile: invalid}, "supplied together"},
		{"key only", Options{KeyFile: invalid}, "supplied together"},
		{"missing CA", Options{CAFile: filepath.Join(dir, "missing.pem")}, "no such file"},
		{"invalid CA", Options{CAFile: invalid}, "no certificates"},
		{"invalid key pair", Options{CertFile: invalid, KeyFile: invalid}, "failed to find"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := clientTLSConfig(tc.opts, "localhost"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := dialUpgrade(t.Context(), Options{Host: "http://localhost", CAFile: invalid}, "/grpc", nil); err == nil {
		t.Fatal("TLS options silently ignored for plaintext")
	}
}

func TestUnaryFrameRejectsAmbiguousAndOversizedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"compressed", []byte{1, 0, 0, 0, 0}},
		{"oversized declaration", []byte{0, 4, 0, 0, 0}},
		{"truncated payload", []byte{0, 0, 0, 0, 2, 1}},
		{"two frames", append(frameMessage(nil), frameMessage(nil)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readMessage(bytes.NewReader(tc.wire)); err == nil {
				t.Fatal("invalid unary input accepted")
			}
		})
	}
}
