package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/tlsbootstrap"
)

func runBootstrapCmd(t *testing.T, dir string, clients ...string) (stdout, stderr string, err error) {
	t.Helper()
	tlsBootstrapDir = dir
	tlsBootstrapServerNames = []string{"127.0.0.1", "localhost"}
	tlsBootstrapClients = clients
	tlsBootstrapForce = false
	t.Cleanup(func() { tlsBootstrapDir, tlsBootstrapServerNames, tlsBootstrapClients = "", nil, nil })
	var out, errOut bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&out)
	c.SetErr(&errOut)
	err = runTLSBootstrap(c, nil)
	return out.String(), errOut.String(), err
}

func TestTLSBootstrapCommandSnippetLoadsAsConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	out, errOut, err := runBootstrapCmd(t, dir, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cert_file: " + filepath.Join(dir, "server-cert.pem"), "client_ca_file: " + filepath.Join(dir, "ca.pem"), "profile: alice", "common_names: [bob]", "owner: bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("snippet missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "created CA") || !strings.Contains(errOut, "created   client  alice") {
		t.Errorf("stderr = %q", errOut)
	}
	if _, errOut, err = runBootstrapCmd(t, dir, "alice", "bob"); err != nil || !strings.Contains(errOut, "reused CA") {
		t.Errorf("rerun err=%v stderr=%q", err, errOut)
	}
	if _, _, err = runBootstrapCmd(t, filepath.Join(dir, "ca.pem"), "alice"); err == nil {
		t.Error("expected error for file path")
	}
}

// TestTLSBootstrapEndToEndMutualTLS drives helper-issued certificates through
// the production mTLS server config and the real handler chain. The client
// certificate CommonName selects the profile, and the profile's ownership.owner
// scopes what the client sees.
func TestTLSBootstrapEndToEndMutualTLS(t *testing.T) {
	pki := filepath.Join(t.TempDir(), "pki")
	if _, _, err := runBootstrapCmd(t, pki, "alice", "bob"); err != nil {
		t.Fatal(err)
	}

	socketPath := shortSocketPath(t, "tls-bootstrap")
	daemon := &ownerScopesDaemon{containers: map[string]map[string]string{}}
	daemon.seed("alice-1", "alice")
	daemon.seed("bob-1", "bob")
	startUnixHTTPUpstream(t, socketPath, daemon)

	cfg := ownerScopesConfig(socketPath)
	cfg.Ownership.InsecureAllowWeakOwnerSelection = false
	cfg.Clients.SourceIPProfiles = nil
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "alice", Rules: cfg.Rules, Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("alice")}},
		{Name: "bob", Rules: cfg.Rules, Ownership: config.ClientProfileOwnershipConfig{Owner: strPtr("bob")}},
	}
	cfg.Clients.ClientCertificateProfiles = []config.ClientCertificateProfileAssignmentConfig{
		{Profile: "alice", CommonNames: []string{"alice"}},
		{Profile: "bob", CommonNames: []string{"bob"}},
	}
	cfg.Listen = config.ListenConfig{Address: "127.0.0.1:0", TLS: config.ListenTLSConfig{
		CertFile:     filepath.Join(pki, tlsbootstrap.ServerCertFileName),
		KeyFile:      filepath.Join(pki, tlsbootstrap.ServerKeyFileName),
		ClientCAFile: filepath.Join(pki, tlsbootstrap.CAFileName),
	}}
	if err := config.ValidateStructural(&cfg); err != nil {
		t.Fatalf("snippet-shaped config rejected: %v", err)
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())

	tlsCfg, err := config.BuildMutualTLSServerConfig(cfg.Listen.TLS)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(handler)
	srv.TLSConfig = tlsCfg
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	caPEM, err := os.ReadFile(filepath.Join(pki, tlsbootstrap.CAFileName))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	clientFor := func(certs []tls.Certificate, rootCAs *x509.CertPool) *http.Client {
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1", RootCAs: rootCAs, Certificates: certs,
		}}}
	}
	issued := func(name string) []tls.Certificate {
		c, err := tls.LoadX509KeyPair(filepath.Join(pki, tlsbootstrap.ClientCertFileName(name)), filepath.Join(pki, tlsbootstrap.ClientKeyFileName(name)))
		if err != nil {
			t.Fatal(err)
		}
		return []tls.Certificate{c}
	}
	list := func(c *http.Client) ([]string, error) {
		resp, err := c.Get("https://" + ln.Addr().String() + "/v1.45/containers/json?all=1")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
		var items []struct{ Id string }
		if err := json.Unmarshal(body, &items); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, i := range items {
			ids = append(ids, i.Id)
		}
		return ids, nil
	}

	for name, want := range map[string]string{"alice": "alice-1", "bob": "bob-1"} {
		ids, err := list(clientFor(issued(name), roots))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(ids) != 1 || ids[0] != want {
			t.Errorf("%s sees %v, want [%s]", name, ids, want)
		}
	}

	// No client certificate: the TLS 1.3 handshake completes client-side, the
	// server then fails it, so the request errors.
	if _, err := list(clientFor(nil, roots)); err == nil {
		t.Error("client without a certificate was accepted")
	}

	// A certificate from another CA, even with a selected CommonName.
	otherDir := filepath.Join(t.TempDir(), "other")
	if _, _, err := runBootstrapCmd(t, otherDir, "alice"); err != nil {
		t.Fatal(err)
	}
	foreign, err := tls.LoadX509KeyPair(filepath.Join(otherDir, tlsbootstrap.ClientCertFileName("alice")), filepath.Join(otherDir, tlsbootstrap.ClientKeyFileName("alice")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := list(clientFor([]tls.Certificate{foreign}, roots)); err == nil {
		t.Error("client with a foreign-CA certificate was accepted")
	}

	// The server certificate carries serverAuth only and must not work as a
	// client identity.
	srvPair, err := tls.LoadX509KeyPair(cfg.Listen.TLS.CertFile, cfg.Listen.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := list(clientFor([]tls.Certificate{srvPair}, roots)); err == nil {
		t.Error("server certificate was accepted as a client certificate")
	}

	// A valid CA-issued certificate no profile selects is not given any
	// owner's view: add carol to the CA but not to the config.
	if _, _, err := runBootstrapCmd(t, pki, "alice", "bob", "carol"); err != nil {
		t.Fatal(err)
	}
	if ids, err := list(clientFor(issued("carol"), roots)); err == nil && len(ids) != 0 {
		for _, id := range ids {
			if id == "alice-1" || id == "bob-1" {
				t.Errorf("unselected client saw %v", ids)
			}
		}
	}
}
