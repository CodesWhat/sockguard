package certmatch

import (
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"testing"
)

func TestIntersectsIPAddrs_InvalidSlice(t *testing.T) {
	// net.IP with 3 bytes is invalid; netip.AddrFromSlice returns ok=false.
	bad := net.IP{1, 2, 3}
	if IntersectsIPAddrs([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, []net.IP{bad}) {
		t.Fatal("expected IntersectsIPAddrs=false for unparseable IP slice")
	}
}

func TestIntersectsIPAddrs_Match(t *testing.T) {
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if !IntersectsIPAddrs(allowed, []net.IP{net.ParseIP("10.0.0.1")}) {
		t.Fatal("expected IntersectsIPAddrs=true for matching IP")
	}
}

func TestIntersectsIPAddrs_NoMatch(t *testing.T) {
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if IntersectsIPAddrs(allowed, []net.IP{net.ParseIP("192.168.1.1")}) {
		t.Fatal("expected IntersectsIPAddrs=false for non-matching IP")
	}
}

func TestCertificateURIStrings_NilCert(t *testing.T) {
	if got := CertificateURIStrings(nil); got != nil {
		t.Fatalf("CertificateURIStrings(nil) = %v, want nil", got)
	}
}

func TestCertificateURIStrings_EmptyURIs(t *testing.T) {
	cert := &x509.Certificate{}
	if got := CertificateURIStrings(cert); got != nil {
		t.Fatalf("CertificateURIStrings(empty) = %v, want nil", got)
	}
}

func TestCertificateURIStrings_NilEntry(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	cert := &x509.Certificate{URIs: []*url.URL{nil, u}}
	got := CertificateURIStrings(cert)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Fatalf("CertificateURIStrings = %v, want [https://example.com]", got)
	}
}
