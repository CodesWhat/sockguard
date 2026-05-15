package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/codeswhat/sockguard/internal/certmatch"
	"github.com/codeswhat/sockguard/internal/pkipin"
)

// Enabled reports whether any listen.tls setting has been configured.
func (cfg ListenTLSConfig) Enabled() bool {
	return cfg.CertFile != "" ||
		cfg.KeyFile != "" ||
		cfg.ClientCAFile != "" ||
		len(cfg.CommonNames) > 0 ||
		len(cfg.DNSNames) > 0 ||
		len(cfg.IPAddresses) > 0 ||
		len(cfg.URISANs) > 0 ||
		len(cfg.PublicKeySHA256Pins) > 0
}

// Complete reports whether listen.tls has the full certificate, key, and
// client CA configuration required to enable mutual TLS.
func (cfg ListenTLSConfig) Complete() bool {
	return cfg.CertFile != "" && cfg.KeyFile != "" && cfg.ClientCAFile != ""
}

// BuildMutualTLSServerConfig builds a TLS server config that requires and
// verifies client certificates for TCP listeners. Error messages reference
// the "listen.tls" config field path. To produce errors keyed to a different
// field (e.g. "admin.listen.tls"), use BuildMutualTLSServerConfigForField.
func BuildMutualTLSServerConfig(cfg ListenTLSConfig) (*tls.Config, error) {
	return BuildMutualTLSServerConfigForField("listen.tls", cfg)
}

// BuildMutualTLSServerConfigForField is BuildMutualTLSServerConfig with an
// explicit field prefix used in error messages. Validation paths use this to
// produce errors that reference the operator's actual config field path
// (e.g. "admin.listen.tls") without post-hoc string substitution.
func BuildMutualTLSServerConfigForField(fieldPrefix string, cfg ListenTLSConfig) (*tls.Config, error) {
	clientIdentity, err := compileClientCertificateIdentityConstraints(fieldPrefix, cfg)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load %s cert/key pair: %w", fieldPrefix, err)
	}

	clientCAPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read %s client_ca_file: %w", fieldPrefix, err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("parse %s client_ca_file: no PEM certificates found", fieldPrefix)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	if clientIdentity.hasSelectors() {
		tlsConfig.VerifyConnection = clientIdentity.verifyConnection
	}

	return tlsConfig, nil
}

type compiledClientCertificateIdentityConstraints struct {
	fieldPrefix         string
	commonNames         []string
	dnsNames            []string
	ipAddresses         []netip.Addr
	uriSANs             []string
	publicKeySHA256Pins []string
}

func compileClientCertificateIdentityConstraints(fieldPrefix string, cfg ListenTLSConfig) (compiledClientCertificateIdentityConstraints, error) {
	compiled := compiledClientCertificateIdentityConstraints{
		fieldPrefix:         fieldPrefix,
		commonNames:         make([]string, 0, len(cfg.CommonNames)),
		dnsNames:            make([]string, 0, len(cfg.DNSNames)),
		ipAddresses:         make([]netip.Addr, 0, len(cfg.IPAddresses)),
		uriSANs:             make([]string, 0, len(cfg.URISANs)),
		publicKeySHA256Pins: make([]string, 0, len(cfg.PublicKeySHA256Pins)),
	}

	values, err := normalizeNonEmptyStrings(fieldPrefix+".common_names", cfg.CommonNames)
	if err != nil {
		return compiled, err
	}
	compiled.commonNames = append(compiled.commonNames, values...)

	values, err = normalizeNonEmptyStrings(fieldPrefix+".dns_names", cfg.DNSNames)
	if err != nil {
		return compiled, err
	}
	compiled.dnsNames = append(compiled.dnsNames, values...)

	for _, raw := range cfg.IPAddresses {
		trimmed := strings.TrimSpace(raw)
		addr, err := netip.ParseAddr(trimmed)
		if err != nil || !addr.IsValid() {
			return compiled, fmt.Errorf("%s.ip_addresses entries must be valid IP addresses, got %q", fieldPrefix, raw)
		}
		compiled.ipAddresses = append(compiled.ipAddresses, addr.Unmap())
	}

	for _, raw := range cfg.URISANs {
		trimmed := strings.TrimSpace(raw)
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.String() == "" {
			return compiled, fmt.Errorf("%s.uri_sans entries must be valid URIs, got %q", fieldPrefix, raw)
		}
		compiled.uriSANs = append(compiled.uriSANs, parsed.String())
	}

	for _, raw := range cfg.PublicKeySHA256Pins {
		pin, err := normalizeSubjectPublicKeySHA256Pin(raw)
		if err != nil {
			return compiled, fmt.Errorf("%s.public_key_sha256_pins entries must be lowercase or uppercase hex SHA-256 digests, got %q", fieldPrefix, raw)
		}
		compiled.publicKeySHA256Pins = append(compiled.publicKeySHA256Pins, pin)
	}

	return compiled, nil
}

func (c compiledClientCertificateIdentityConstraints) hasSelectors() bool {
	return len(c.commonNames) > 0 ||
		len(c.dnsNames) > 0 ||
		len(c.ipAddresses) > 0 ||
		len(c.uriSANs) > 0 ||
		len(c.publicKeySHA256Pins) > 0
}

func (c compiledClientCertificateIdentityConstraints) verifyConnection(state tls.ConnectionState) error {
	prefix := c.fieldPrefix
	if prefix == "" {
		prefix = "listen.tls"
	}
	leaf, err := verifiedClientCertificateLeaf(state)
	if err != nil {
		return fmt.Errorf("verify %s client certificate identity: %w", prefix, err)
	}
	if !c.matches(leaf) {
		return fmt.Errorf("verify %s client certificate identity: client certificate not allowed", prefix)
	}
	return nil
}

func (c compiledClientCertificateIdentityConstraints) matches(cert *x509.Certificate) bool {
	if cert == nil || !c.hasSelectors() {
		return false
	}
	if len(c.commonNames) > 0 && !containsExactString(c.commonNames, strings.TrimSpace(cert.Subject.CommonName)) {
		return false
	}
	if len(c.dnsNames) > 0 && !intersectsStrings(c.dnsNames, cert.DNSNames) {
		return false
	}
	if len(c.ipAddresses) > 0 && !certmatch.IntersectsIPAddrs(c.ipAddresses, cert.IPAddresses) {
		return false
	}
	if len(c.uriSANs) > 0 && !intersectsStrings(c.uriSANs, certmatch.CertificateURIStrings(cert)) {
		return false
	}
	if len(c.publicKeySHA256Pins) > 0 && !containsExactString(c.publicKeySHA256Pins, subjectPublicKeySHA256Hex(cert)) {
		return false
	}
	return true
}

func verifiedClientCertificateLeaf(state tls.ConnectionState) (*x509.Certificate, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("no verified client certificate")
	}
	return state.VerifiedChains[0][0], nil
}

func normalizeNonEmptyStrings(field string, values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, fmt.Errorf("%s entries must be non-empty", field)
		}
		normalized = append(normalized, trimmed)
	}
	return normalized, nil
}

func normalizeSubjectPublicKeySHA256Pin(raw string) (string, error) {
	return pkipin.NormalizeSubjectPublicKeySHA256Pin(raw)
}

func containsExactString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func intersectsStrings(allowed []string, actual []string) bool {
	for _, candidate := range actual {
		if containsExactString(allowed, candidate) {
			return true
		}
	}
	return false
}

func subjectPublicKeySHA256Hex(cert *x509.Certificate) string {
	return pkipin.SubjectPublicKeySHA256Hex(cert)
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
