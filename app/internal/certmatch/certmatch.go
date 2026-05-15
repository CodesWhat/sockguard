// Package certmatch holds small helpers used by both the TLS server-cert
// validator (internal/config/tls.go) and the per-client cert profile matcher
// (internal/clientacl/middleware.go). The two callers historically carried
// byte-identical copies of these helpers; centralizing them prevents drift.
package certmatch

import (
	"crypto/x509"
	"net"
	"net/netip"
)

// IntersectsIPAddrs reports whether any IP in actual, after unmapping IPv4-in-
// IPv6 forms, equals any IP in allowed. Returns false for an empty actual.
func IntersectsIPAddrs(allowed []netip.Addr, actual []net.IP) bool {
	for _, candidate := range actual {
		addr, ok := netip.AddrFromSlice(candidate)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		for _, allowedAddr := range allowed {
			if allowedAddr == addr {
				return true
			}
		}
	}
	return false
}

// CertificateURIStrings flattens cert.URIs into their string forms, dropping
// nil entries. Returns nil when the cert is nil or has no URIs.
func CertificateURIStrings(cert *x509.Certificate) []string {
	if cert == nil || len(cert.URIs) == 0 {
		return nil
	}
	values := make([]string, 0, len(cert.URIs))
	for _, value := range cert.URIs {
		if value == nil {
			continue
		}
		values = append(values, value.String())
	}
	return values
}
