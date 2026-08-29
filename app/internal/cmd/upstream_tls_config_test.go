package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testcert"
)

func TestUpstreamMutualTLSFromYAML_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	const serverName = "daemon.internal"
	bundle, err := testcert.WriteMutualTLSBundle(dir, serverName)
	if err != nil {
		t.Fatalf("write mutual TLS bundle: %v", err)
	}
	srv := startConfiguredMutualTLSDaemon(t, bundle)
	host := strings.TrimPrefix(srv.URL, "https://")

	configPath := filepath.Join(dir, "sockguard.yaml")
	yaml := fmt.Sprintf(`
upstream:
  endpoints:
    - address: %s
      tls:
        ca_file: %s
        cert_file: %s
        key_file: %s
        server_name: %s
  failover:
    health_interval: -1s
`,
		strconv.Quote("tcp://"+host),
		strconv.Quote(bundle.CAFile),
		strconv.Quote(bundle.ClientCertFile),
		strconv.Quote(bundle.ClientKeyFile),
		strconv.Quote(serverName),
	)
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	resolver, legacy, err := buildUpstreamResolver(cfg, nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("buildUpstreamResolver: %v", err)
	}
	if legacy {
		t.Fatal("buildUpstreamResolver used the legacy socket, want configured endpoint")
	}

	endpoints := resolver.Endpoints()
	if len(endpoints) != 1 {
		t.Fatalf("resolver endpoints = %d, want 1", len(endpoints))
	}
	if got := endpoints[0].TLSConfig.ServerName; got != serverName {
		t.Errorf("TLS ServerName = %q, want %q", got, serverName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/_ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := resolver.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got, want := string(body), "peer_certs=1"; got != want {
		t.Fatalf("daemon response = %q, want %q", got, want)
	}
}

func startConfiguredMutualTLSDaemon(t *testing.T, bundle testcert.Bundle) *httptest.Server {
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
		_, _ = fmt.Fprintf(w, "peer_certs=%d", peers)
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
