package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Bundle struct {
	CAFile         string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
}

type issuedCertificate struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

type bundleDeps struct {
	newCertificateAuthority func() (issuedCertificate, error)
	newServerCertificate    func([]string, issuedCertificate) (issuedCertificate, error)
	newClientCertificate    func(issuedCertificate) (issuedCertificate, error)
	writeBundleFiles        func(Bundle, issuedCertificate, issuedCertificate, issuedCertificate) error
}

func newBundleDeps() bundleDeps {
	return bundleDeps{
		newCertificateAuthority: newCertificateAuthority,
		newServerCertificate:    newServerCertificate,
		newClientCertificate:    newClientCertificate,
		writeBundleFiles:        writeBundleFiles,
	}
}

type certDeps struct {
	generateKey         func() (*ecdsa.PrivateKey, error)
	certificateTemplate func(string) (*x509.Certificate, error)
	createCertificate   func(*x509.Certificate, *x509.Certificate, any, any) ([]byte, error)
	parseCertificate    func([]byte) (*x509.Certificate, error)
}

func newCertDeps() certDeps {
	return certDeps{
		generateKey: func() (*ecdsa.PrivateKey, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		},
		certificateTemplate: certificateTemplate,
		createCertificate: func(template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
			return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
		},
		parseCertificate: x509.ParseCertificate,
	}
}

type bundleWriteDeps struct {
	writePEM          func(string, string, []byte) error
	writeECPrivateKey func(string, *ecdsa.PrivateKey) error
}

func newBundleWriteDeps() bundleWriteDeps {
	return bundleWriteDeps{
		writePEM:          writePEM,
		writeECPrivateKey: writeECPrivateKey,
	}
}

type writePEMDeps struct {
	openFile  func(string) (io.WriteCloser, error)
	encodePEM func(io.Writer, *pem.Block) error
}

func newWritePEMDeps() writePEMDeps {
	return writePEMDeps{
		openFile: func(path string) (io.WriteCloser, error) {
			return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		},
		encodePEM: pem.Encode,
	}
}

func WriteMutualTLSBundle(dir string, serverHosts ...string) (Bundle, error) {
	return writeMutualTLSBundleWithDeps(dir, newBundleDeps(), serverHosts...)
}

func writeMutualTLSBundleWithDeps(dir string, deps bundleDeps, serverHosts ...string) (Bundle, error) {
	ca, err := deps.newCertificateAuthority()
	if err != nil {
		return Bundle{}, err
	}

	server, err := deps.newServerCertificate(defaultServerHosts(serverHosts), ca)
	if err != nil {
		return Bundle{}, err
	}

	client, err := deps.newClientCertificate(ca)
	if err != nil {
		return Bundle{}, err
	}

	bundle := newBundle(dir)
	if err := deps.writeBundleFiles(bundle, ca, server, client); err != nil {
		return Bundle{}, err
	}

	return bundle, nil
}

func ClientTLSConfig(bundle Bundle, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(bundle.ClientCertFile, bundle.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}
	caPEM, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("append CA certs")
	}

	return &tls.Config{
		// Match the production mutual-TLS server config, which requires
		// TLS 1.3 (see config.BuildMutualTLSServerConfig). Keeping the test
		// client pinned to 1.2 would let tests pass while hiding the fact
		// that a real 1.2-only client is rejected in production.
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}, nil
}

func certificateTemplate(commonName string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, nil
}

func defaultServerHosts(serverHosts []string) []string {
	if len(serverHosts) == 0 {
		return []string{"127.0.0.1", "localhost"}
	}
	return serverHosts
}

func newBundle(dir string) Bundle {
	return Bundle{
		CAFile:         filepath.Join(dir, "ca.pem"),
		ServerCertFile: filepath.Join(dir, "server-cert.pem"),
		ServerKeyFile:  filepath.Join(dir, "server-key.pem"),
		ClientCertFile: filepath.Join(dir, "client-cert.pem"),
		ClientKeyFile:  filepath.Join(dir, "client-key.pem"),
	}
}

func newCertificateAuthority() (issuedCertificate, error) {
	return newCertificateAuthorityWithDeps(newCertDeps())
}

func newCertificateAuthorityWithDeps(deps certDeps) (issuedCertificate, error) {
	key, err := deps.generateKey()
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("generate CA key: %w", err)
	}

	template, err := deps.certificateTemplate("sockguard-test-ca")
	if err != nil {
		return issuedCertificate{}, err
	}
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.BasicConstraintsValid = true

	der, err := deps.createCertificate(template, template, key.Public(), key)
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := deps.parseCertificate(der)
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	return issuedCertificate{cert: cert, der: der, key: key}, nil
}

func newServerCertificate(serverHosts []string, ca issuedCertificate) (issuedCertificate, error) {
	return newLeafCertificate("sockguard-test-server", x509.ExtKeyUsageServerAuth, ca, func(template *x509.Certificate) {
		for _, host := range serverHosts {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
				continue
			}
			template.DNSNames = append(template.DNSNames, host)
		}
	})
}

func newClientCertificate(ca issuedCertificate) (issuedCertificate, error) {
	return newLeafCertificate("sockguard-test-client", x509.ExtKeyUsageClientAuth, ca, nil)
}

func newLeafCertificate(
	commonName string,
	extKeyUsage x509.ExtKeyUsage,
	ca issuedCertificate,
	configure func(*x509.Certificate),
) (issuedCertificate, error) {
	return newLeafCertificateWithDeps(commonName, extKeyUsage, ca, configure, newCertDeps())
}

func newLeafCertificateWithDeps(
	commonName string,
	extKeyUsage x509.ExtKeyUsage,
	ca issuedCertificate,
	configure func(*x509.Certificate),
	deps certDeps,
) (issuedCertificate, error) {
	key, err := deps.generateKey()
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("generate %s key: %w", commonName, err)
	}

	template, err := deps.certificateTemplate(commonName)
	if err != nil {
		return issuedCertificate{}, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{extKeyUsage}
	if configure != nil {
		configure(template)
	}

	der, err := deps.createCertificate(template, ca.cert, key.Public(), ca.key)
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("create %s certificate: %w", commonName, err)
	}

	return issuedCertificate{der: der, key: key}, nil
}

func writeBundleFiles(bundle Bundle, ca issuedCertificate, server issuedCertificate, client issuedCertificate) error {
	return writeBundleFilesWithDeps(bundle, ca, server, client, newBundleWriteDeps())
}

func writeBundleFilesWithDeps(bundle Bundle, ca issuedCertificate, server issuedCertificate, client issuedCertificate, deps bundleWriteDeps) error {
	files := []struct {
		path      string
		blockType string
		der       []byte
	}{
		{path: bundle.CAFile, blockType: "CERTIFICATE", der: ca.der},
		{path: bundle.ServerCertFile, blockType: "CERTIFICATE", der: server.der},
		{path: bundle.ClientCertFile, blockType: "CERTIFICATE", der: client.der},
	}

	for _, file := range files {
		if err := deps.writePEM(file.path, file.blockType, file.der); err != nil {
			return err
		}
	}

	keys := []struct {
		path string
		key  *ecdsa.PrivateKey
	}{
		{path: bundle.ServerKeyFile, key: server.key},
		{path: bundle.ClientKeyFile, key: client.key},
	}

	for _, file := range keys {
		if err := deps.writeECPrivateKey(file.path, file.key); err != nil {
			return err
		}
	}

	return nil
}

func writePEM(path, blockType string, der []byte) (err error) {
	return writePEMWithDeps(path, blockType, der, newWritePEMDeps())
}

func writePEMWithDeps(path, blockType string, der []byte, deps writePEMDeps) (err error) {
	file, err := deps.openFile(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	if err := deps.encodePEM(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return nil
}

func writeECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	return writePEM(path, "EC PRIVATE KEY", der)
}
