package certmatch

import (
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"testing"
)

func TestIntersectsIPAddrs_InvalidSlice(t *testing.T) {
	t.Parallel()
	// net.IP with 3 bytes is invalid; netip.AddrFromSlice returns ok=false.
	bad := net.IP{1, 2, 3}
	if IntersectsIPAddrs([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, []net.IP{bad}) {
		t.Fatal("expected IntersectsIPAddrs=false for unparseable IP slice")
	}
}

func TestIntersectsIPAddrs_Match(t *testing.T) {
	t.Parallel()
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if !IntersectsIPAddrs(allowed, []net.IP{net.ParseIP("10.0.0.1")}) {
		t.Fatal("expected IntersectsIPAddrs=true for matching IP")
	}
}

func TestIntersectsIPAddrs_NoMatch(t *testing.T) {
	t.Parallel()
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if IntersectsIPAddrs(allowed, []net.IP{net.ParseIP("192.168.1.1")}) {
		t.Fatal("expected IntersectsIPAddrs=false for non-matching IP")
	}
}

func TestIntersectsIPAddrs_IPv4InIPv6Match(t *testing.T) {
	t.Parallel()
	// Exercises addr.Unmap(): Linux dual-stack listeners surface IPv4 connections
	// as ::ffff:10.0.0.1; Unmap() reduces that to the plain v4 form before comparison.
	actual := []net.IP{net.ParseIP("::ffff:10.0.0.1")}
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if !IntersectsIPAddrs(allowed, actual) {
		t.Fatal("expected IntersectsIPAddrs=true for IPv4-mapped-IPv6 address matching allowed v4 addr")
	}
}

func TestIntersectsIPAddrs_IPv6NoMatch(t *testing.T) {
	t.Parallel()
	// Unmap() is a no-op for real IPv6 addresses; confirms the branch does not
	// falsely collapse unrelated IPv6 addrs into matching an allowed v4 entry.
	actual := []net.IP{net.ParseIP("2001:db8::1")}
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if IntersectsIPAddrs(allowed, actual) {
		t.Fatal("expected IntersectsIPAddrs=false for real IPv6 address against allowed v4 addr")
	}
}

func TestCertificateURIStrings_NilCert(t *testing.T) {
	t.Parallel()
	if got := CertificateURIStrings(nil); got != nil {
		t.Fatalf("CertificateURIStrings(nil) = %v, want nil", got)
	}
}

func TestCertificateURIStrings_EmptyURIs(t *testing.T) {
	t.Parallel()
	cert := &x509.Certificate{}
	if got := CertificateURIStrings(cert); got != nil {
		t.Fatalf("CertificateURIStrings(empty) = %v, want nil", got)
	}
}

func TestCertificateURIStrings_NilEntry(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("https://example.com")
	cert := &x509.Certificate{URIs: []*url.URL{nil, u}}
	got := CertificateURIStrings(cert)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Fatalf("CertificateURIStrings = %v, want [https://example.com]", got)
	}
}
