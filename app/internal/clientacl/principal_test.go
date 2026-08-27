package clientacl

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestPrincipalDistinguishesUnixPeers(t *testing.T) {
	requestForPeer := func(creds unixPeerCredentials) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/session", nil)
		req.RemoteAddr = "@"
		return req.WithContext(withUnixPeerCredentials(req.Context(), creds))
	}

	first, err := RequestPrincipal(requestForPeer(unixPeerCredentials{UID: 1000, GID: 1000, PID: 41}))
	if err != nil {
		t.Fatalf("RequestPrincipal(first peer) error = %v", err)
	}
	second, err := RequestPrincipal(requestForPeer(unixPeerCredentials{UID: 1000, GID: 1000, PID: 42}))
	if err != nil {
		t.Fatalf("RequestPrincipal(second peer) error = %v", err)
	}
	if first == second {
		t.Fatalf("different Unix peers resolved to the same principal %q", first)
	}

	repeat, err := RequestPrincipal(requestForPeer(unixPeerCredentials{UID: 1000, GID: 1000, PID: 41}))
	if err != nil {
		t.Fatalf("RequestPrincipal(repeated peer) error = %v", err)
	}
	if repeat != first {
		t.Fatalf("same Unix peer resolved inconsistently: first %q, repeat %q", first, repeat)
	}
}

func TestRequestPrincipalCorrelatesVerifiedCertificateAcrossTCPPorts(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("verified-client-certificate")}
	requestFromPort := func(remoteAddr string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/grpc", nil)
		req.RemoteAddr = remoteAddr
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}
		return req
	}

	grpcPrincipal, err := RequestPrincipal(requestFromPort("192.0.2.10:41000"))
	if err != nil {
		t.Fatalf("RequestPrincipal(/grpc) error = %v", err)
	}
	sessionPrincipal, err := RequestPrincipal(requestFromPort("192.0.2.10:42000"))
	if err != nil {
		t.Fatalf("RequestPrincipal(/session) error = %v", err)
	}
	if grpcPrincipal != sessionPrincipal {
		t.Fatalf("same verified certificate split across TCP ports: /grpc %q, /session %q", grpcPrincipal, sessionPrincipal)
	}
}

func TestRequestPrincipalNormalizesUnauthenticatedRemoteHost(t *testing.T) {
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/grpc", nil),
		httptest.NewRequest(http.MethodPost, "/session", nil),
	}
	requests[0].RemoteAddr = "[::ffff:192.0.2.10]:41000"
	requests[1].RemoteAddr = "192.0.2.10:42000"

	first, err := RequestPrincipal(requests[0])
	if err != nil {
		t.Fatalf("RequestPrincipal(mapped IPv6) error = %v", err)
	}
	second, err := RequestPrincipal(requests[1])
	if err != nil {
		t.Fatalf("RequestPrincipal(IPv4) error = %v", err)
	}
	if first != second {
		t.Fatalf("equivalent remote IPs resolved inconsistently: mapped %q, IPv4 %q", first, second)
	}
}

func TestRequestPrincipalFailsClosedAfterUnixPeerLookupFailure(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.RemoteAddr = "@"
	peerErr := errors.New("peer credential lookup failed")
	req = req.WithContext(withConnectionIdentity(req.Context(), connectionIdentity{unixPeerErr: peerErr}))

	if _, err := RequestPrincipal(req); !errors.Is(err, peerErr) {
		t.Fatalf("RequestPrincipal() error = %v, want wrapped peer lookup error", err)
	}
}
