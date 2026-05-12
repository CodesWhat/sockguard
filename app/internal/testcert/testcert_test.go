package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

type closeErrorWriteCloser struct {
	closeErr error
}

func (w *closeErrorWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *closeErrorWriteCloser) Close() error {
	return w.closeErr
}

func mustGenerateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
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
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", path, err)
	}
	return cert
}

// restoreTestcertHooks saves all 12 package-level hook vars and restores them
// via t.Cleanup, so each test starts from a known good state.
func restoreTestcertHooks(t *testing.T) {
	t.Helper()

	savedNewCA := newCertificateAuthorityHook
	savedNewServer := newServerCertificateHook
	savedNewClient := newClientCertificateHook
	savedWriteBundle := writeBundleFilesHook
	savedGenerateKey := generateKeyHook
	savedCertTemplate := certificateTemplateHook
	savedCreateCert := createCertificateHook
	savedParseCert := parseCertificateHook
	savedWritePEM := writePEMHook
	savedWriteECKey := writeECPrivateKeyHook
	savedOpenFile := openFileHook
	savedEncodePEM := encodePEMHook

	t.Cleanup(func() {
		newCertificateAuthorityHook = savedNewCA
		newServerCertificateHook = savedNewServer
		newClientCertificateHook = savedNewClient
		writeBundleFilesHook = savedWriteBundle
		generateKeyHook = savedGenerateKey
		certificateTemplateHook = savedCertTemplate
		createCertificateHook = savedCreateCert
		parseCertificateHook = savedParseCert
		writePEMHook = savedWritePEM
		writeECPrivateKeyHook = savedWriteECKey
		openFileHook = savedOpenFile
		encodePEMHook = savedEncodePEM
	})
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
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want TLS1.3", cfg.MinVersion)
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
		return
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

func TestWriteMutualTLSBundleReturnsDependencyErrors(t *testing.T) {
	caErr := errors.New("ca failed")
	serverErr := errors.New("server failed")
	clientErr := errors.New("client failed")
	writeErr := errors.New("write failed")

	validCA := issuedCertificate{cert: &x509.Certificate{}, key: mustGenerateECDSAKey(t)}
	validLeaf := issuedCertificate{key: mustGenerateECDSAKey(t)}

	tests := []struct {
		name    string
		setup   func()
		wantErr error
	}{
		{
			name: "certificate authority error",
			setup: func() {
				newCertificateAuthorityHook = func() (issuedCertificate, error) { return issuedCertificate{}, caErr }
			},
			wantErr: caErr,
		},
		{
			name: "server certificate error",
			setup: func() {
				newCertificateAuthorityHook = func() (issuedCertificate, error) { return validCA, nil }
				newServerCertificateHook = func([]string, issuedCertificate) (issuedCertificate, error) {
					return issuedCertificate{}, serverErr
				}
			},
			wantErr: serverErr,
		},
		{
			name: "client certificate error",
			setup: func() {
				newCertificateAuthorityHook = func() (issuedCertificate, error) { return validCA, nil }
				newServerCertificateHook = func([]string, issuedCertificate) (issuedCertificate, error) {
					return validLeaf, nil
				}
				newClientCertificateHook = func(issuedCertificate) (issuedCertificate, error) {
					return issuedCertificate{}, clientErr
				}
			},
			wantErr: clientErr,
		},
		{
			name: "bundle write error",
			setup: func() {
				newCertificateAuthorityHook = func() (issuedCertificate, error) { return validCA, nil }
				newServerCertificateHook = func([]string, issuedCertificate) (issuedCertificate, error) {
					return validLeaf, nil
				}
				newClientCertificateHook = func(issuedCertificate) (issuedCertificate, error) { return validLeaf, nil }
				writeBundleFilesHook = func(Bundle, issuedCertificate, issuedCertificate, issuedCertificate) error {
					return writeErr
				}
			},
			wantErr: writeErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreTestcertHooks(t)
			tt.setup()
			_, err := WriteMutualTLSBundle(t.TempDir())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewCertificateAuthorityReturnsDependencyErrors(t *testing.T) {
	keyErr := errors.New("generate key failed")
	templateErr := errors.New("template failed")
	createErr := errors.New("create cert failed")
	parseErr := errors.New("parse cert failed")

	key := mustGenerateECDSAKey(t)
	template := &x509.Certificate{}

	tests := []struct {
		name    string
		setup   func()
		wantErr error
	}{
		{
			name: "key generation error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return nil, keyErr }
			},
			wantErr: keyErr,
		},
		{
			name: "template error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return key, nil }
				certificateTemplateHook = func(string) (*x509.Certificate, error) { return nil, templateErr }
			},
			wantErr: templateErr,
		},
		{
			name: "certificate creation error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return key, nil }
				certificateTemplateHook = func(string) (*x509.Certificate, error) { return template, nil }
				createCertificateHook = func(*x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
					return nil, createErr
				}
			},
			wantErr: createErr,
		},
		{
			name: "certificate parse error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return key, nil }
				certificateTemplateHook = func(string) (*x509.Certificate, error) { return template, nil }
				createCertificateHook = func(*x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
					return []byte("bad"), nil
				}
				parseCertificateHook = func([]byte) (*x509.Certificate, error) { return nil, parseErr }
			},
			wantErr: parseErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreTestcertHooks(t)
			tt.setup()
			_, err := newCertificateAuthority()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewLeafCertificateReturnsDependencyErrors(t *testing.T) {
	keyErr := errors.New("generate key failed")
	templateErr := errors.New("template failed")
	createErr := errors.New("create cert failed")

	key := mustGenerateECDSAKey(t)
	template := &x509.Certificate{}
	ca := issuedCertificate{cert: &x509.Certificate{}, key: mustGenerateECDSAKey(t)}

	tests := []struct {
		name    string
		setup   func()
		wantErr error
	}{
		{
			name: "key generation error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return nil, keyErr }
			},
			wantErr: keyErr,
		},
		{
			name: "template error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return key, nil }
				certificateTemplateHook = func(string) (*x509.Certificate, error) { return nil, templateErr }
			},
			wantErr: templateErr,
		},
		{
			name: "certificate creation error",
			setup: func() {
				generateKeyHook = func() (*ecdsa.PrivateKey, error) { return key, nil }
				certificateTemplateHook = func(string) (*x509.Certificate, error) { return template, nil }
				createCertificateHook = func(*x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
					return nil, createErr
				}
			},
			wantErr: createErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreTestcertHooks(t)
			tt.setup()
			_, err := newLeafCertificate("sockguard-test", x509.ExtKeyUsageClientAuth, ca, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteBundleFilesReturnsDependencyErrors(t *testing.T) {
	pemErr := errors.New("write pem failed")
	keyErr := errors.New("write key failed")

	bundle := newBundle(t.TempDir())
	ca := issuedCertificate{der: []byte("ca")}
	server := issuedCertificate{der: []byte("server"), key: mustGenerateECDSAKey(t)}
	client := issuedCertificate{der: []byte("client"), key: mustGenerateECDSAKey(t)}

	t.Run("certificate write error", func(t *testing.T) {
		restoreTestcertHooks(t)
		writePEMHook = func(string, string, []byte) error { return pemErr }
		writeECPrivateKeyHook = func(string, *ecdsa.PrivateKey) error {
			t.Fatal("unexpected key write")
			return nil
		}
		err := writeBundleFiles(bundle, ca, server, client)
		if !errors.Is(err, pemErr) {
			t.Fatalf("error = %v, want %v", err, pemErr)
		}
	})

	t.Run("key write error", func(t *testing.T) {
		restoreTestcertHooks(t)
		writePEMHook = func(string, string, []byte) error { return nil }
		writeECPrivateKeyHook = func(string, *ecdsa.PrivateKey) error { return keyErr }
		err := writeBundleFiles(bundle, ca, server, client)
		if !errors.Is(err, keyErr) {
			t.Fatalf("error = %v, want %v", err, keyErr)
		}
	})
}

func TestWritePEMReturnsEncodeAndCloseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	encodeErr := errors.New("encode failed")
	closeErr := errors.New("close failed")

	t.Run("encode error", func(t *testing.T) {
		restoreTestcertHooks(t)
		openFileHook = func(string) (io.WriteCloser, error) { return &closeErrorWriteCloser{}, nil }
		encodePEMHook = func(io.Writer, *pem.Block) error { return encodeErr }
		err := writePEM(path, "CERTIFICATE", []byte("payload"))
		if !errors.Is(err, encodeErr) {
			t.Fatalf("error = %v, want %v", err, encodeErr)
		}
	})

	t.Run("close error", func(t *testing.T) {
		restoreTestcertHooks(t)
		openFileHook = func(string) (io.WriteCloser, error) {
			return &closeErrorWriteCloser{closeErr: closeErr}, nil
		}
		encodePEMHook = func(io.Writer, *pem.Block) error { return nil }
		err := writePEM(path, "CERTIFICATE", []byte("payload"))
		if !errors.Is(err, closeErr) {
			t.Fatalf("error = %v, want %v", err, closeErr)
		}
	})
}
