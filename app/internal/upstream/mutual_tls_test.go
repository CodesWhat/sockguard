package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/testcert"
)

// startMutualTLSDaemon starts an httptest server that stands in for a
// `dockerd --tlsverify` daemon: it serves TLS with the bundle's server
// certificate AND requires a client certificate issued by the bundle CA. The
// handler reports how many verified peer certificates the daemon saw, so a
// caller can assert that sockguard actually presented its client certificate
// rather than merely holding one in its tls.Config.
func startMutualTLSDaemon(t *testing.T, bundle testcert.Bundle) *httptest.Server {
	t.Helper()
	serverCert, err := tls.LoadX509KeyPair(bundle.ServerCertFile, bundle.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	caPEM, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA file contains no PEM certificates")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers := 0
		if r.TLS != nil {
			peers = len(r.TLS.PeerCertificates)
		}
		fmt.Fprintf(w, "peer_certs=%d", peers)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestUpstreamMutualTLS_RoundTripThroughResolver pins the upstream half of
// sockguard's "TLS in both directions" claim: a full HTTP request traveling
// through Resolver.RoundTrip must reach a daemon that requires and verifies a
// client certificate.
//
// It covers two things the endpoint-level tests cannot:
//
//   - The daemon here demands a client certificate, so the success case fails
//     unless buildClientTLS actually loads and presents cert_file/key_file.
//     Asserting len(TLSConfig.Certificates) == 1 only proves the material was
//     parsed, not that the handshake offers it.
//   - The request is routed through the resolver's pooled transport rather than
//     Endpoint.dial directly, which pins the wiring in newTransport. The request
//     scheme is deliberately "http" because the reverse proxy rewrites it that
//     way; TLS is supplied by the endpoint dialer, not Transport.TLSClientConfig,
//     and a transport that dialed plaintext would fail here while every
//     unix-socket resolver test kept passing.
func TestUpstreamMutualTLS_RoundTripThroughResolver(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	srv := startMutualTLSDaemon(t, bundle)
	host := strings.TrimPrefix(srv.URL, "https://")

	tests := []struct {
		name    string
		spec    EndpointSpec
		wantErr bool
	}{
		{
			name: "full mutual TLS reaches the daemon",
			spec: EndpointSpec{
				Address:  "tcp://" + host,
				CAFile:   bundle.CAFile,
				CertFile: bundle.ClientCertFile,
				KeyFile:  bundle.ClientKeyFile,
			},
		},
		{
			name: "no client certificate is refused by the daemon",
			spec: EndpointSpec{
				Address: "tcp://" + host,
				CAFile:  bundle.CAFile,
			},
			wantErr: true,
		},
		{
			name: "client certificate without the daemon CA fails server verification",
			spec: EndpointSpec{
				Address:  "tcp://" + host,
				CertFile: bundle.ClientCertFile,
				KeyFile:  bundle.ClientKeyFile,
			},
			wantErr: true,
		},
		{
			name: "server_name mismatch fails hostname verification",
			spec: EndpointSpec{
				Address:    "tcp://" + host,
				CAFile:     bundle.CAFile,
				CertFile:   bundle.ClientCertFile,
				KeyFile:    bundle.ClientKeyFile,
				ServerName: "wrong.example.invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ep, err := BuildEndpoint(tt.spec)
			if err != nil {
				t.Fatalf("BuildEndpoint: %v", err)
			}
			r, err := New([]Endpoint{ep}, Options{Interval: -1})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/_ping", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			resp, err := r.RoundTrip(req)
			if tt.wantErr {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatal("RoundTrip succeeded, want a TLS failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			// The daemon required and verified a client cert, so seeing exactly
			// one peer certificate proves sockguard presented its keypair.
			if got, want := string(body), "peer_certs=1"; got != want {
				t.Errorf("daemon reported %q, want %q", got, want)
			}
		})
	}
}
