package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

func (cfg ListenTLSConfig) Enabled() bool {
	return cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ClientCAFile != ""
}

func (cfg ListenTLSConfig) Complete() bool {
	return cfg.CertFile != "" && cfg.KeyFile != "" && cfg.ClientCAFile != ""
}

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
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

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

func IsNonLoopbackTCPAddress(address string) bool {
	return !IsLoopbackTCPAddress(address)
}
