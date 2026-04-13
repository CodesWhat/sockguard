package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// Enabled reports whether any listen.tls setting has been configured.
func (cfg ListenTLSConfig) Enabled() bool {
	return cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ClientCAFile != ""
}

// Complete reports whether listen.tls has the full certificate, key, and
// client CA configuration required to enable mutual TLS.
func (cfg ListenTLSConfig) Complete() bool {
	return cfg.CertFile != "" && cfg.KeyFile != "" && cfg.ClientCAFile != ""
}

// BuildMutualTLSServerConfig builds a TLS server config that requires and
// verifies client certificates for TCP listeners.
func BuildMutualTLSServerConfig(cfg ListenTLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load listen.tls cert/key pair: %w", err)
	}

	clientCAPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read listen.tls client_ca_file: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("parse listen.tls client_ca_file: no PEM certificates found")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

// IsLoopbackTCPAddress reports whether address resolves to a loopback TCP host.
func IsLoopbackTCPAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsNonLoopbackTCPAddress reports whether address is a valid non-loopback TCP
// host:port pair.
func IsNonLoopbackTCPAddress(address string) bool {
	return !IsLoopbackTCPAddress(address)
}
