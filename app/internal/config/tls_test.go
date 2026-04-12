package config

import (
	"crypto/tls"
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
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %v, want TLS1.2", cfg.MinVersion)
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
