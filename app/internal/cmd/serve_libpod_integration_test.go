package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testcert"
)

func TestLibpodContainerUpdateSideLookupUsesMutualTLSAndBasePath(t *testing.T) {
	bundle, err := testcert.WriteMutualTLSBundle(t.TempDir(), "127.0.0.1")
	if err != nil {
		t.Fatalf("write mutual TLS bundle: %v", err)
	}
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

	var inspectCalls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("resource side lookup reached daemon without a verified client certificate")
		}
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/engine%2Fgateway/containers/demo/json" {
			t.Errorf("upstream request = %s %s, want GET /engine%%2Fgateway/containers/demo/json", r.Method, r.URL.EscapedPath())
			http.Error(w, "unexpected upstream request", http.StatusNotFound)
			return
		}
		inspectCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"HostConfig":{"Memory":0}}`)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Upstream.Endpoints = []config.UpstreamEndpoint{{
		Address: "tcp://" + strings.TrimPrefix(srv.URL, "https://") + "/engine%2Fgateway",
		TLS: config.UpstreamTLSConfig{
			CAFile:     bundle.CAFile,
			CertFile:   bundle.ClientCertFile,
			KeyFile:    bundle.ClientKeyFile,
			ServerName: "127.0.0.1",
		},
	}}
	cfg.Upstream.Failover.HealthInterval = "-1s"
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/libpod/containers/*/update"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	cfg.RequestBody.ContainerUpdate.AllowResourceUpdates = true
	cfg.RequestBody.ContainerUpdate.RequireMemoryLimit = true

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/libpod/containers/demo/update", strings.NewReader(`{}`)))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if inspectCalls.Load() != 1 {
		t.Fatalf("resource side lookups = %d, want 1", inspectCalls.Load())
	}
}

func TestLibpodShowMountedRefusalComposesInProductionChain(t *testing.T) {
	socketPath := shortSocketPath(t, "showmounted-compose-upstream")
	_ = os.Remove(socketPath)
	var upstreamCalls atomic.Int32
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.WriteString(w, `{"foreign":"/var/lib/containers/storage/foreign/merged"}`)
	}))

	cfg := config.Defaults()
	cfg.Upstream.Socket = socketPath
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.DenyVerbosity = "verbose"
	cfg.Response.VisibleResourceLabels = []string{"tier=prod"}
	cfg.Ownership.Owner = "team-a"
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodGet, Path: "/libpod/containers/showmounted"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/libpod/containers/showmounted", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
	for _, leaked := range []string{"foreign", "/var/lib/containers"} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatalf("mount inventory %q reached the client: %s", leaked, rec.Body.String())
		}
	}
}
