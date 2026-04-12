package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func readCertificateFromPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("Decode(%s): no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", path, err)
	}
	return cert
}

func TestWriteMutualTLSBundleWritesExpectedFilesAndDefaultHosts(t *testing.T) {
	dir := t.TempDir()

	bundle, err := WriteMutualTLSBundle(dir)
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle() error = %v", err)
	}

	for _, path := range []string{
		bundle.CAFile,
		bundle.ServerCertFile,
		bundle.ServerKeyFile,
		bundle.ClientCertFile,
		bundle.ClientKeyFile,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s perms = %o, want 600", path, info.Mode().Perm())
		}
	}

	serverCert := readCertificateFromPEM(t, bundle.ServerCertFile)
	if !serverCert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("server IP SANs = %v, want 127.0.0.1", serverCert.IPAddresses)
	}
	if len(serverCert.DNSNames) == 0 || serverCert.DNSNames[0] != "localhost" {
		t.Fatalf("server DNS SANs = %v, want localhost", serverCert.DNSNames)
	}
}

func TestWriteMutualTLSBundleReturnsWriteError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(dir, []byte("file"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := WriteMutualTLSBundle(dir, "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientTLSConfig(t *testing.T) {
	dir := t.TempDir()
	bundle, err := WriteMutualTLSBundle(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WriteMutualTLSBundle: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		cfg, err := ClientTLSConfig(bundle, "127.0.0.1")
		if err != nil {
			t.Fatalf("ClientTLSConfig() error = %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %v, want TLS1.2", cfg.MinVersion)
		}
		if cfg.ServerName != "127.0.0.1" {
			t.Fatalf("ServerName = %q, want 127.0.0.1", cfg.ServerName)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates length = %d, want 1", len(cfg.Certificates))
		}
		if cfg.RootCAs == nil {
			t.Fatal("RootCAs = nil, want populated pool")
		}
	})

	t.Run("missing client key pair", func(t *testing.T) {
		_, err := ClientTLSConfig(Bundle{
			CAFile:         bundle.CAFile,
			ClientCertFile: filepath.Join(dir, "missing-cert.pem"),
			ClientKeyFile:  filepath.Join(dir, "missing-key.pem"),
		}, "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "load client key pair") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		_, err := ClientTLSConfig(Bundle{
			CAFile:         filepath.Join(dir, "missing-ca.pem"),
			ClientCertFile: bundle.ClientCertFile,
			ClientKeyFile:  bundle.ClientKeyFile,
		}, "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "read CA file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		invalidCA := filepath.Join(dir, "invalid-ca.pem")
		if err := os.WriteFile(invalidCA, []byte("not pem"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		_, err := ClientTLSConfig(Bundle{
			CAFile:         invalidCA,
			ClientCertFile: bundle.ClientCertFile,
			ClientKeyFile:  bundle.ClientKeyFile,
		}, "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "append CA certs") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCertificateTemplate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cert, err := certificateTemplate("sockguard-test")
		if err != nil {
			t.Fatalf("certificateTemplate() error = %v", err)
		}
		if cert.Subject.CommonName != "sockguard-test" {
			t.Fatalf("CommonName = %q, want sockguard-test", cert.Subject.CommonName)
		}
		if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
			t.Fatalf("SerialNumber = %v, want positive value", cert.SerialNumber)
		}
		if got := cert.NotAfter.Sub(cert.NotBefore); got < 24*time.Hour || got > 26*time.Hour {
			t.Fatalf("validity window = %v, want about 25h", got)
		}
	})

	t.Run("serial number read failure", func(t *testing.T) {
		originalReader := rand.Reader
		rand.Reader = failingReader{err: io.ErrUnexpectedEOF}
		t.Cleanup(func() {
			rand.Reader = originalReader
		})

		_, err := certificateTemplate("sockguard-test")
		if err == nil || !strings.Contains(err.Error(), "generate serial number") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestWritePEM(t *testing.T) {
	der := []byte("payload")
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := writePEM(path, "CERTIFICATE", der); err != nil {
		t.Fatalf("writePEM() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Decode() returned nil block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("block type = %q, want CERTIFICATE", block.Type)
	}
	if string(block.Bytes) != string(der) {
		t.Fatalf("block bytes = %q, want %q", string(block.Bytes), string(der))
	}

	err = writePEM(filepath.Join(path, "nested.pem"), "CERTIFICATE", der)
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteECPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	path := filepath.Join(t.TempDir(), "client-key.pem")
	if err := writeECPrivateKey(path, key); err != nil {
		t.Fatalf("writeECPrivateKey() error = %v", err)
	}
	if _, err := tls.LoadX509KeyPair(path, path); err == nil {
		t.Fatal("expected combined cert/key load to fail for a key-only PEM file")
	}

	invalidKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
		},
		D: big.NewInt(1),
	}
	err = writeECPrivateKey(filepath.Join(t.TempDir(), "invalid-key.pem"), invalidKey)
	if err == nil || !strings.Contains(err.Error(), "marshal EC private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}
