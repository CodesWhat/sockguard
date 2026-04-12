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

func WriteMutualTLSBundle(dir string, serverHosts ...string) (Bundle, error) {
	if len(serverHosts) == 0 {
		serverHosts = []string{"127.0.0.1", "localhost"}
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate, err := certificateTemplate("sockguard-test-ca")
	if err != nil {
		return Bundle{}, err
	}
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	caTemplate.BasicConstraintsValid = true

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Bundle{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate server key: %w", err)
	}
	serverTemplate, err := certificateTemplate("sockguard-test-server")
	if err != nil {
		return Bundle{}, err
	}
	serverTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, host := range serverHosts {
		if ip := net.ParseIP(host); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
			continue
		}
		serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverKey.Public(), caKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("create server certificate: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate client key: %w", err)
	}
	clientTemplate, err := certificateTemplate("sockguard-test-client")
	if err != nil {
		return Bundle{}, err
	}
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientKey.Public(), caKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("create client certificate: %w", err)
	}

	bundle := Bundle{
		CAFile:         filepath.Join(dir, "ca.pem"),
		ServerCertFile: filepath.Join(dir, "server-cert.pem"),
		ServerKeyFile:  filepath.Join(dir, "server-key.pem"),
		ClientCertFile: filepath.Join(dir, "client-cert.pem"),
		ClientKeyFile:  filepath.Join(dir, "client-key.pem"),
	}

	if err := writePEM(bundle.CAFile, "CERTIFICATE", caDER); err != nil {
		return Bundle{}, err
	}
	if err := writePEM(bundle.ServerCertFile, "CERTIFICATE", serverDER); err != nil {
		return Bundle{}, err
	}
	if err := writeECPrivateKey(bundle.ServerKeyFile, serverKey); err != nil {
		return Bundle{}, err
	}
	if err := writePEM(bundle.ClientCertFile, "CERTIFICATE", clientDER); err != nil {
		return Bundle{}, err
	}
	if err := writeECPrivateKey(bundle.ClientKeyFile, clientKey); err != nil {
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
		MinVersion:   tls.VersionTLS12,
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

func writePEM(path, blockType string, der []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
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
