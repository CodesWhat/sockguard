package config

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
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
			CertFile:            bundle.ServerCertFile,
			KeyFile:             bundle.ServerKeyFile,
			ClientCAFile:        bundle.CAFile,
			CommonNames:         []string{"allowed-client"},
			DNSNames:            []string{"client.example.com"},
			IPAddresses:         []string{"10.0.0.7"},
			URISANs:             []string{"spiffe://sockguard/client"},
			PublicKeySHA256Pins: []string{subjectPublicKeySHA256Hex(allowedLeaf)},
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
			CertFile:            bundle.ServerCertFile,
			KeyFile:             bundle.ServerKeyFile,
			ClientCAFile:        bundle.CAFile,
			PublicKeySHA256Pins: []string{"not-a-pin"},
		})
		if err == nil || !strings.Contains(err.Error(), "public_key_sha256_pins") {
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

// TestCompiledConstraintsMatchesMutantKills exercises each boundary check in
// compiledClientCertificateIdentityConstraints.matches to kill surviving
// CONDITIONALS_BOUNDARY and CONDITIONALS_NEGATION mutants on lines 151-163.
//
// Each sub-test uses a constraint with exactly one populated selector field and
// verifies that:
//
//	(a) a matching cert is accepted (CONDITIONALS_NEGATION kill), and
//	(b) a cert that only differs in that field is rejected.
//
// CONDITIONALS_BOUNDARY (`len(x) > 0` → `len(x) >= 0`):
// When a slice is empty (len==0) the guard must be skipped. If mutated to >=
// the empty slice would always enter the check and reject everything because
// containsExactString([], ...) == false. The sub-tests named
// *_empty_slice_does_not_reject verify this by building constraints where
// that particular slice is empty but another is populated — the matching cert
// must still be allowed.
func TestCompiledConstraintsMatchesMutantKills(t *testing.T) {
	// Shared certs used across sub-tests.
	allowedLeaf := &x509.Certificate{
		Subject:                 pkix.Name{CommonName: "allowed-cn"},
		DNSNames:                []string{"allowed.example.com"},
		IPAddresses:             []net.IP{net.ParseIP("10.0.0.1")},
		URIs:                    []*url.URL{mustParseURL(t, "spiffe://sockguard/allowed")},
		RawSubjectPublicKeyInfo: []byte("allowed-key"),
	}
	blockedLeaf := &x509.Certificate{
		Subject:                 pkix.Name{CommonName: "blocked-cn"},
		DNSNames:                []string{"blocked.example.com"},
		IPAddresses:             []net.IP{net.ParseIP("10.0.0.2")},
		URIs:                    []*url.URL{mustParseURL(t, "spiffe://sockguard/blocked")},
		RawSubjectPublicKeyInfo: []byte("blocked-key"),
	}

	// ── CONDITIONALS_BOUNDARY + NEGATION tls.go:151 (commonNames) ─────────────
	t.Run("common_name_match_allows", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			commonNames: []string{"allowed-cn"},
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false for cert with matching common name, want true")
		}
	})
	t.Run("common_name_mismatch_rejects", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			commonNames: []string{"allowed-cn"},
		}
		if c.matches(blockedLeaf) {
			t.Error("matches() = true for cert with non-matching common name, want false")
		}
	})
	// Empty commonNames must NOT filter — the cert is allowed by the other
	// populated selector (dnsNames). Tests CONDITIONALS_BOUNDARY: len > 0 must
	// not become len >= 0 (always-true).
	t.Run("empty_common_names_slice_does_not_reject", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			commonNames: []string{},                      // empty — skip CN check
			dnsNames:    []string{"allowed.example.com"}, // populated — use this
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false when commonNames is empty and dnsNames matches, want true")
		}
	})

	// ── CONDITIONALS_BOUNDARY tls.go:154 (dnsNames) ───────────────────────────
	t.Run("dns_name_match_allows", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			dnsNames: []string{"allowed.example.com"},
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false for cert with matching DNS SAN, want true")
		}
	})
	t.Run("dns_name_mismatch_rejects", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			dnsNames: []string{"allowed.example.com"},
		}
		if c.matches(blockedLeaf) {
			t.Error("matches() = true for cert without matching DNS SAN, want false")
		}
	})
	t.Run("empty_dns_names_slice_does_not_reject", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			dnsNames:    []string{},             // empty — skip DNS check
			commonNames: []string{"allowed-cn"}, // populated — use this
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false when dnsNames is empty and commonNames matches, want true")
		}
	})

	// ── CONDITIONALS_BOUNDARY tls.go:157 (ipAddresses) ────────────────────────
	t.Run("ip_address_match_allows", func(t *testing.T) {
		addr, _ := netip.ParseAddr("10.0.0.1")
		c := compiledClientCertificateIdentityConstraints{
			ipAddresses: []netip.Addr{addr},
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false for cert with matching IP SAN, want true")
		}
	})
	t.Run("ip_address_mismatch_rejects", func(t *testing.T) {
		addr, _ := netip.ParseAddr("10.0.0.1")
		c := compiledClientCertificateIdentityConstraints{
			ipAddresses: []netip.Addr{addr},
		}
		if c.matches(blockedLeaf) {
			t.Error("matches() = true for cert without matching IP SAN, want false")
		}
	})
	t.Run("empty_ip_addresses_slice_does_not_reject", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			ipAddresses: []netip.Addr{},         // empty — skip IP check
			commonNames: []string{"allowed-cn"}, // populated — use this
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false when ipAddresses is empty and commonNames matches, want true")
		}
	})

	// ── CONDITIONALS_BOUNDARY tls.go:160 (uriSANs) ────────────────────────────
	t.Run("uri_san_match_allows", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			uriSANs: []string{"spiffe://sockguard/allowed"},
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false for cert with matching URI SAN, want true")
		}
	})
	t.Run("uri_san_mismatch_rejects", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			uriSANs: []string{"spiffe://sockguard/allowed"},
		}
		if c.matches(blockedLeaf) {
			t.Error("matches() = true for cert without matching URI SAN, want false")
		}
	})
	t.Run("empty_uri_sans_slice_does_not_reject", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			uriSANs:     []string{},             // empty — skip URI check
			commonNames: []string{"allowed-cn"}, // populated — use this
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false when uriSANs is empty and commonNames matches, want true")
		}
	})

	// ── CONDITIONALS_BOUNDARY tls.go:163 (publicKeySHA256Pins) ───────────────
	t.Run("public_key_pin_match_allows", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			publicKeySHA256Pins: []string{subjectPublicKeySHA256Hex(allowedLeaf)},
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false for cert with matching public key pin, want true")
		}
	})
	t.Run("public_key_pin_mismatch_rejects", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			publicKeySHA256Pins: []string{subjectPublicKeySHA256Hex(allowedLeaf)},
		}
		if c.matches(blockedLeaf) {
			t.Error("matches() = true for cert with non-matching public key pin, want false")
		}
	})
	t.Run("empty_public_key_pins_slice_does_not_reject", func(t *testing.T) {
		c := compiledClientCertificateIdentityConstraints{
			publicKeySHA256Pins: []string{},             // empty — skip pin check
			commonNames:         []string{"allowed-cn"}, // populated — use this
		}
		if !c.matches(allowedLeaf) {
			t.Error("matches() = false when publicKeySHA256Pins is empty and commonNames matches, want true")
		}
	})
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
