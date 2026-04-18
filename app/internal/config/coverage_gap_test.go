package config

// coverage_gap_test.go covers branches not exercised by the existing test suite.

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// compat.go: normalizeCompatLogLevel
// ---------------------------------------------------------------------------

func TestNormalizeCompatLogLevel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"debug", "debug"},
		{"DEBUG", "debug"},
		{"info", "info"},
		{"INFO", "info"},
		{"notice", "info"},
		{"NOTICE", "info"},
		{"warn", "warn"},
		{"warning", "warn"},
		{"WARNING", "warn"},
		{"error", "error"},
		{"err", "error"},
		{"crit", "error"},
		{"alert", "error"},
		{"emerg", "error"},
		{"trace", "trace"},     // unknown → lower-trimmed passthrough
		{"  TRACE  ", "trace"}, // trims whitespace
		{"", ""},               // empty passthrough
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeCompatLogLevel(tt.in); got != tt.want {
				t.Fatalf("normalizeCompatLogLevel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validate.go: requiredFieldError (0%)
// ---------------------------------------------------------------------------

func TestRequiredFieldError(t *testing.T) {
	got := requiredFieldError("some.field")
	if got != "some.field is required" {
		t.Fatalf("requiredFieldError() = %q, want %q", got, "some.field is required")
	}
}

// ---------------------------------------------------------------------------
// validate.go: formatAllowedValues — 0-item and 1-item branches
// ---------------------------------------------------------------------------

func TestFormatAllowedValues(t *testing.T) {
	if got := formatAllowedValues(); got != "" {
		t.Fatalf("formatAllowedValues() = %q, want empty", got)
	}
	if got := formatAllowedValues("only"); got != "only" {
		t.Fatalf("formatAllowedValues(one) = %q, want %q", got, "only")
	}
	if got := formatAllowedValues("a", "b"); got != "a or b" {
		t.Fatalf("formatAllowedValues(two) = %q, want %q", got, "a or b")
	}
	if got := formatAllowedValues("a", "b", "c"); got != "a, b, or c" {
		t.Fatalf("formatAllowedValues(three) = %q, want %q", got, "a, b, or c")
	}
}

// ---------------------------------------------------------------------------
// validate.go: validateRuleConfigs — invalid action branch
// ---------------------------------------------------------------------------

func TestValidateRuleConfigsInvalidAction(t *testing.T) {
	rules := []RuleConfig{
		{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "pass"},
	}
	errs := validateRuleConfigs(rules, "test")
	if len(errs) == 0 {
		t.Fatal("expected error for invalid action in validateRuleConfigs")
	}
	if !strings.Contains(errs[0], "action") {
		t.Fatalf("error should mention action, got: %v", errs[0])
	}
}

func TestValidateRuleConfigsMissingFields(t *testing.T) {
	rules := []RuleConfig{
		{Match: MatchConfig{Method: "", Path: ""}, Action: "allow"},
	}
	errs := validateRuleConfigs(rules, "profile.rules")
	found := false
	for _, e := range errs {
		if strings.Contains(e, "match.method") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected match.method error, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// validate.go: validateClientProfile — empty name branch
// ---------------------------------------------------------------------------

func TestValidateClientProfileEmptyName(t *testing.T) {
	errs := validateClientProfile(0, ClientProfileConfig{
		Name:  "  ",
		Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
	}, map[string]struct{}{})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "name") && strings.Contains(e, "required") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected name required error, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// validate.go: validateRequestBody — unix_peer_profiles branches
// ---------------------------------------------------------------------------

// validateRequestBody: source_ip_profiles with empty profile name (hits requiredFieldError)
func TestValidateRequestBodySourceIPProfileEmptyName(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{
		{Profile: "", CIDRs: []string{"10.0.0.0/8"}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty source_ip_profiles profile name")
	}
	if !strings.Contains(err.Error(), "source_ip_profiles") {
		t.Fatalf("error should mention source_ip_profiles, got: %v", err)
	}
}

// validateRequestBody: source_ip_profiles with invalid CIDR
func TestValidateRequestBodySourceIPProfileInvalidCIDR(t *testing.T) {
	cfg := Defaults()
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{
		{Profile: "ro", CIDRs: []string{"not-a-cidr"}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid source_ip_profiles CIDR")
	}
	if !strings.Contains(err.Error(), "source_ip_profiles") {
		t.Fatalf("error should mention source_ip_profiles, got: %v", err)
	}
}

// validateRequestBody: client_certificate_profiles with empty common name entry
func TestValidateRequestBodyClientCertProfileEmptyCommonName(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Address = "127.0.0.1:2376"
	cfg.Listen.Socket = ""
	cfg.Listen.TLS.CertFile = "/tmp/server.pem"
	cfg.Listen.TLS.KeyFile = "/tmp/server-key.pem"
	cfg.Listen.TLS.ClientCAFile = "/tmp/ca.pem"
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
		{Profile: "ro", CommonNames: []string{"  "}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for empty common_names entry")
	}
	if !strings.Contains(err.Error(), "common_names") {
		t.Fatalf("error should mention common_names, got: %v", err)
	}
}

func TestValidateRequestBodyUnixPeerProfileMissingProfile(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
		{Profile: ""},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for missing unix_peer_profiles profile name")
	}
	if !strings.Contains(err.Error(), "unix_peer_profiles") {
		t.Fatalf("error should mention unix_peer_profiles, got: %v", err)
	}
}

func TestValidateRequestBodyUnixPeerProfileRequiresSocket(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = ""
	cfg.Listen.Address = "127.0.0.1:2376"
	cfg.Listen.InsecureAllowPlainTCP = true
	cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
		{Profile: "ro", UIDs: []uint32{1000}},
	}
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for unix_peer_profiles on TCP listener")
	}
	if !strings.Contains(err.Error(), "unix_peer_profiles") {
		t.Fatalf("error should mention unix_peer_profiles, got: %v", err)
	}
}

func TestValidateRequestBodyUnixPeerProfileNonPositivePID(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.UnixPeerProfiles = []ClientUnixPeerProfileAssignmentConfig{
		{Profile: "ro", PIDs: []int32{0}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for zero PID")
	}
	if !strings.Contains(err.Error(), "pids") {
		t.Fatalf("error should mention pids, got: %v", err)
	}
}

func TestValidateRequestBodyClientCertProfilesOnUnixSocket(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.ClientCertificateProfiles = []ClientCertificateProfileAssignmentConfig{
		{Profile: "ro", CommonNames: []string{"client"}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for client_certificate_profiles on unix socket")
	}
	if !strings.Contains(err.Error(), "client_certificate_profiles") {
		t.Fatalf("error should mention client_certificate_profiles, got: %v", err)
	}
}

func TestValidateRequestBodySourceIPProfilesOnUnixSocket(t *testing.T) {
	cfg := Defaults()
	cfg.Listen.Socket = "/tmp/sockguard.sock"
	cfg.Listen.Address = ""
	cfg.Clients.Profiles = []ClientProfileConfig{
		{Name: "ro", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}}},
	}
	cfg.Clients.SourceIPProfiles = []ClientSourceIPProfileAssignmentConfig{
		{Profile: "ro", CIDRs: []string{"10.0.0.0/8"}},
	}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected error for source_ip_profiles on unix socket")
	}
	if !strings.Contains(err.Error(), "source_ip_profiles") {
		t.Fatalf("error should mention source_ip_profiles, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validate.go: validateVisibleResourceLabels — missing branches
// ---------------------------------------------------------------------------

func TestValidateVisibleResourceLabelsKeyWithEmptyValue(t *testing.T) {
	errs := validateVisibleResourceLabels("test", []string{"key="})
	if len(errs) == 0 {
		t.Fatal("expected error for key= with empty value")
	}
	if !strings.Contains(errs[0], "non-empty value") {
		t.Fatalf("error should mention non-empty value, got: %v", errs[0])
	}
}

func TestValidateVisibleResourceLabelsEmptyKey(t *testing.T) {
	errs := validateVisibleResourceLabels("test", []string{"  =value"})
	if len(errs) == 0 {
		t.Fatal("expected error for empty key")
	}
	if !strings.Contains(errs[0], "label key") {
		t.Fatalf("error should mention label key, got: %v", errs[0])
	}
}

// ---------------------------------------------------------------------------
// validate.go: validExecCommand — empty slice and blank token branches
// ---------------------------------------------------------------------------

func TestValidExecCommandEmptySlice(t *testing.T) {
	if validExecCommand([]string{}) {
		t.Fatal("expected false for empty command slice")
	}
}

func TestValidExecCommandBlankToken(t *testing.T) {
	if validExecCommand([]string{"cmd", "  "}) {
		t.Fatal("expected false for command with blank token")
	}
}

// ---------------------------------------------------------------------------
// validate.go: normalizeAllowedRegistryHost — index.docker.io alias
// ---------------------------------------------------------------------------

func TestNormalizeAllowedRegistryHostDockerAlias(t *testing.T) {
	got, ok := normalizeAllowedRegistryHost("index.docker.io")
	if !ok || got != "docker.io" {
		t.Fatalf("normalizeAllowedRegistryHost(index.docker.io) = (%q, %v), want (docker.io, true)", got, ok)
	}
}

// ---------------------------------------------------------------------------
// tls.go: compileClientCertificateIdentityConstraints — error paths
// ---------------------------------------------------------------------------

func TestCompileClientCertIDConstraintsEmptyCommonName(t *testing.T) {
	_, err := compileClientCertificateIdentityConstraints(ListenTLSConfig{
		AllowedCommonNames: []string{""},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_common_names") {
		t.Fatalf("expected allowed_common_names error, got: %v", err)
	}
}

func TestCompileClientCertIDConstraintsEmptyDNSName(t *testing.T) {
	_, err := compileClientCertificateIdentityConstraints(ListenTLSConfig{
		AllowedDNSNames: []string{""},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_dns_names") {
		t.Fatalf("expected allowed_dns_names error, got: %v", err)
	}
}

func TestCompileClientCertIDConstraintsInvalidIP(t *testing.T) {
	_, err := compileClientCertificateIdentityConstraints(ListenTLSConfig{
		AllowedIPAddresses: []string{"not-an-ip"},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_ip_addresses") {
		t.Fatalf("expected allowed_ip_addresses error, got: %v", err)
	}
}

func TestCompileClientCertIDConstraintsEmptyURISAN(t *testing.T) {
	_, err := compileClientCertificateIdentityConstraints(ListenTLSConfig{
		AllowedURISANs: []string{""},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_uri_sans") {
		t.Fatalf("expected allowed_uri_sans error, got: %v", err)
	}
}

func TestCompileClientCertIDConstraintsInvalidPin(t *testing.T) {
	_, err := compileClientCertificateIdentityConstraints(ListenTLSConfig{
		AllowedPublicKeySHA256Pins: []string{"abc"},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed_public_key_sha256_pins") {
		t.Fatalf("expected allowed_public_key_sha256_pins error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tls.go: normalizeSubjectPublicKeySHA256Pin — prefix and non-hex branches
// ---------------------------------------------------------------------------

func TestNormalizeSubjectPublicKeySHA256PinWithPrefix(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	got, err := normalizeSubjectPublicKeySHA256Pin("sha256:" + validHex)
	if err != nil {
		t.Fatalf("normalizeSubjectPublicKeySHA256Pin() error = %v", err)
	}
	if got != validHex {
		t.Fatalf("normalizeSubjectPublicKeySHA256Pin() = %q, want %q", got, validHex)
	}
}

func TestNormalizeSubjectPublicKeySHA256PinNonHex(t *testing.T) {
	invalid := strings.Repeat("z", 64) // 'z' is not hex
	_, err := normalizeSubjectPublicKeySHA256Pin(invalid)
	if err == nil {
		t.Fatal("expected error for non-hex pin")
	}
}

func TestNormalizeSubjectPublicKeySHA256PinEmpty(t *testing.T) {
	_, err := normalizeSubjectPublicKeySHA256Pin("   ")
	if err == nil {
		t.Fatal("expected error for empty pin")
	}
}

// ---------------------------------------------------------------------------
// tls.go: verifiedClientCertificateLeaf — error branches
// ---------------------------------------------------------------------------

func TestVerifiedClientCertificateLeafNoChains(t *testing.T) {
	_, err := verifiedClientCertificateLeaf(tls.ConnectionState{})
	if err == nil || !strings.Contains(err.Error(), "no verified client certificate") {
		t.Fatalf("expected no verified client certificate error, got: %v", err)
	}
}

func TestVerifiedClientCertificateLeafEmptyChain(t *testing.T) {
	_, err := verifiedClientCertificateLeaf(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{}},
	})
	if err == nil || !strings.Contains(err.Error(), "no verified client certificate") {
		t.Fatalf("expected no verified client certificate error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tls.go: matches — uncovered branches
// ---------------------------------------------------------------------------

func TestMatchesNilCert(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{
		commonNames: []string{"test"},
	}
	if c.matches(nil) {
		t.Fatal("matches(nil) should return false")
	}
}

func TestMatchesNoSelectors(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{}
	if c.matches(&x509.Certificate{}) {
		t.Fatal("matches with no selectors should return false")
	}
}

func TestMatchesDNSNameMismatch(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{
		dnsNames: []string{"allowed.example.com"},
	}
	if c.matches(&x509.Certificate{DNSNames: []string{"other.example.com"}}) {
		t.Fatal("matches should return false for dns name mismatch")
	}
}

func TestMatchesIPAddressMismatch(t *testing.T) {
	addr, _ := netip.ParseAddr("10.0.0.1")
	c := compiledClientCertificateIdentityConstraints{
		ipAddresses: []netip.Addr{addr},
	}
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "client"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.2")},
	}
	if c.matches(cert) {
		t.Fatal("matches should return false for IP address mismatch")
	}
}

func TestMatchesURISANMismatch(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{
		uriSANs: []string{"spiffe://example/allowed"},
	}
	// cert has no URIs
	if c.matches(&x509.Certificate{}) {
		t.Fatal("matches should return false for uri san mismatch")
	}
}

func TestMatchesPublicKeyPinMismatch(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{
		publicKeySHA256Pins: []string{strings.Repeat("a", 64)},
	}
	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: []byte("some-key-bytes"),
	}
	// The pin won't match since RawSubjectPublicKeyInfo is arbitrary bytes
	if c.matches(cert) {
		t.Fatal("matches should return false when pin doesn't match")
	}
}

// tls.go: verifyConnection — no verified chains (exercises the error path through verifiedClientCertificateLeaf)
func TestVerifyConnectionNoChains(t *testing.T) {
	c := compiledClientCertificateIdentityConstraints{
		commonNames: []string{"test"},
	}
	err := c.verifyConnection(tls.ConnectionState{})
	if err == nil || !strings.Contains(err.Error(), "verify listen.tls client certificate identity") {
		t.Fatalf("expected identity verification error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tls.go: intersectsStrings — empty actual list
// ---------------------------------------------------------------------------

func TestIntersectsStringsNoMatch(t *testing.T) {
	if intersectsStrings([]string{"a", "b"}, []string{"c", "d"}) {
		t.Fatal("intersectsStrings should return false when no match")
	}
}

// ---------------------------------------------------------------------------
// tls.go: intersectsIPAddrs — un-parseable IP (3-byte slice)
// ---------------------------------------------------------------------------

func TestIntersectsIPAddrsUnparseableIP(t *testing.T) {
	addr, _ := netip.ParseAddr("10.0.0.1")
	bad := net.IP([]byte{1, 2, 3}) // 3-byte IP is invalid for netip
	if intersectsIPAddrs([]netip.Addr{addr}, []net.IP{bad}) {
		t.Fatal("intersectsIPAddrs should return false for un-parseable IP")
	}
}

// ---------------------------------------------------------------------------
// tls.go: certificateURIStrings — nil cert and nil URI entry
// ---------------------------------------------------------------------------

func TestCertificateURIStringsNilCert(t *testing.T) {
	if got := certificateURIStrings(nil); got != nil {
		t.Fatalf("certificateURIStrings(nil) = %v, want nil", got)
	}
}

func TestCertificateURIStringsNilEntry(t *testing.T) {
	validURL, _ := url.Parse("https://example.com")
	cert := &x509.Certificate{URIs: []*url.URL{nil, validURL}}
	got := certificateURIStrings(cert)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Fatalf("certificateURIStrings() = %v, want [https://example.com]", got)
	}
}

// ---------------------------------------------------------------------------
// tls.go: subjectPublicKeySHA256Hex — nil cert
// ---------------------------------------------------------------------------

func TestSubjectPublicKeySHA256HexNilCert(t *testing.T) {
	if got := subjectPublicKeySHA256Hex(nil); got != "" {
		t.Fatalf("subjectPublicKeySHA256Hex(nil) = %q, want empty", got)
	}
}
