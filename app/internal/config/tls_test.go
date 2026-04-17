package config

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/testcert"
)

func TestBuildMutualTLSServerConfig(t *testing.T) {
	dir := t.TempDir()
	bundle, err := testcert.WriteMutualTLSBundle(dir, "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		cfg, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:     bundle.ServerCertFile,
			KeyFile:      bundle.ServerKeyFile,
			ClientCAFile: bundle.CAFile,
		})
		if err != nil {
			t.Fatalf("BuildMutualTLSServerConfig() error = %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want TLS1.3", cfg.MinVersion)
		}
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates length = %d, want 1", len(cfg.Certificates))
		}
		if cfg.ClientCAs == nil {
			t.Fatal("ClientCAs = nil, want populated pool")
		}
	})

	t.Run("missing key pair", func(t *testing.T) {
		_, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:     filepath.Join(dir, "missing-cert.pem"),
			KeyFile:      filepath.Join(dir, "missing-key.pem"),
			ClientCAFile: bundle.CAFile,
		})
		if err == nil || !strings.Contains(err.Error(), "load listen.tls cert/key pair") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		_, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:     bundle.ServerCertFile,
			KeyFile:      bundle.ServerKeyFile,
			ClientCAFile: filepath.Join(dir, "missing-ca.pem"),
		})
		if err == nil || !strings.Contains(err.Error(), "read listen.tls client_ca_file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		invalidCA := filepath.Join(dir, "invalid-ca.pem")
		if err := os.WriteFile(invalidCA, []byte("not pem"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:     bundle.ServerCertFile,
			KeyFile:      bundle.ServerKeyFile,
			ClientCAFile: invalidCA,
		})
		if err == nil || !strings.Contains(err.Error(), "no PEM certificates found") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client identity allowlists and pins", func(t *testing.T) {
		allowedLeaf := &x509.Certificate{
			Subject:                 pkix.Name{CommonName: "allowed-client"},
			DNSNames:                []string{"client.example.com"},
			IPAddresses:             []net.IP{net.ParseIP("10.0.0.7")},
			URIs:                    []*url.URL{mustParseURL(t, "spiffe://sockguard/client")},
			RawSubjectPublicKeyInfo: []byte("allowed-client-key"),
		}
		blockedLeaf := &x509.Certificate{
			Subject:                 pkix.Name{CommonName: "blocked-client"},
			DNSNames:                []string{"blocked.example.com"},
			IPAddresses:             []net.IP{net.ParseIP("10.0.0.9")},
			URIs:                    []*url.URL{mustParseURL(t, "spiffe://sockguard/blocked")},
			RawSubjectPublicKeyInfo: []byte("blocked-client-key"),
		}

		cfg, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:                   bundle.ServerCertFile,
			KeyFile:                    bundle.ServerKeyFile,
			ClientCAFile:               bundle.CAFile,
			AllowedCommonNames:         []string{"allowed-client"},
			AllowedDNSNames:            []string{"client.example.com"},
			AllowedIPAddresses:         []string{"10.0.0.7"},
			AllowedURISANs:             []string{"spiffe://sockguard/client"},
			AllowedPublicKeySHA256Pins: []string{subjectPublicKeySHA256Hex(allowedLeaf)},
		})
		if err != nil {
			t.Fatalf("BuildMutualTLSServerConfig() error = %v", err)
		}
		if cfg.VerifyConnection == nil {
			t.Fatal("VerifyConnection = nil, want client identity verifier")
		}

		if err := cfg.VerifyConnection(tls.ConnectionState{
			VerifiedChains:   [][]*x509.Certificate{{allowedLeaf}},
			PeerCertificates: []*x509.Certificate{allowedLeaf},
		}); err != nil {
			t.Fatalf("VerifyConnection(allowed leaf) error = %v, want nil", err)
		}

		err = cfg.VerifyConnection(tls.ConnectionState{
			VerifiedChains:   [][]*x509.Certificate{{blockedLeaf}},
			PeerCertificates: []*x509.Certificate{blockedLeaf},
		})
		if err == nil || !strings.Contains(err.Error(), "client certificate not allowed") {
			t.Fatalf("VerifyConnection(blocked leaf) error = %v, want client certificate not allowed", err)
		}
	})

	t.Run("invalid public key pin", func(t *testing.T) {
		_, err := BuildMutualTLSServerConfig(ListenTLSConfig{
			CertFile:                   bundle.ServerCertFile,
			KeyFile:                    bundle.ServerKeyFile,
			ClientCAFile:               bundle.CAFile,
			AllowedPublicKeySHA256Pins: []string{"not-a-pin"},
		})
		if err == nil || !strings.Contains(err.Error(), "allowed_public_key_sha256_pins") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return parsed
}

func TestIsLoopbackTCPAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{address: "localhost:2375", want: true},
		{address: "127.0.0.1:2375", want: true},
		{address: "[::1]:2375", want: true},
		{address: ":2375", want: false},
		{address: "0.0.0.0:2375", want: false},
		{address: "bad-address", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := IsLoopbackTCPAddress(tt.address); got != tt.want {
				t.Fatalf("IsLoopbackTCPAddress(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestValidateLogOutputAcceptsStdoutAndLocalPath(t *testing.T) {
	tests := []string{
		"stdout",
		" stderr ",
		"./sockguard.log",
	}

	for _, output := range tests {
		t.Run(output, func(t *testing.T) {
			if err := validateLogOutput(output); err != nil {
				t.Fatalf("validateLogOutput(%q) error = %v", output, err)
			}
		})
	}
}
