package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMutualTLSEdgeCases is the QA-4 end-to-end mTLS regression: every
// client-certificate failure mode the production mTLS path is supposed
// to reject, exercised by a real TLS handshake against a real listener
// configured with BuildMutualTLSServerConfig. The existing unit tests
// cover BuildMutualTLSServerConfig's loader-time errors (missing files,
// invalid PEM, bad pin format); this file fills the live-handshake gap
// — wrong CA, expired/not-yet-valid leaves, DNS SAN allowlist mismatch,
// SPKI pin mismatch, TLS 1.2 downgrade — alongside the matching success
// paths so a false-positive regression is also detected.
//
// Each subtest mints exactly the certs it needs from a per-test CA and
// stands up its own httptest-style TLS server, so cases never share
// state. The shared mtlsHarness helper builds the trusted CA, the
// server cert, and a small toolkit for issuing arbitrarily-shaped
// client certs (off-CA, expired, custom SAN, custom NotBefore/After).
func TestMutualTLSEdgeCases(t *testing.T) {
	t.Run("trusted client with no selectors handshakes", func(t *testing.T) {
		h := newMTLSHarness(t)
		client := h.issueClient(t, clientCertOptions{commonName: "trusted-client"})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
		})

		got, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(client, tls.VersionTLS13))
		if err != nil {
			t.Fatalf("trusted handshake failed: %v", err)
		}
		if got != "ok" {
			t.Fatalf("body = %q, want ok", got)
		}
	})

	t.Run("client cert from an unrelated CA is rejected", func(t *testing.T) {
		h := newMTLSHarness(t)
		otherCA := newTestCA(t)
		strangerClient := otherCA.issueClient(t, clientCertOptions{commonName: "stranger"})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
		})

		_, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(strangerClient, tls.VersionTLS13))
		if err == nil {
			t.Fatal("handshake with wrong-CA client succeeded; want a TLS error")
		}
		// The server's verifier surfaces as a tls.AlertError on the wire;
		// asserting "the handshake failed" is enough — the matcher itself
		// is unit-tested by TestBuildMutualTLSServerConfig.
	})

	t.Run("expired client certificate is rejected", func(t *testing.T) {
		h := newMTLSHarness(t)
		expiredClient := h.issueClient(t, clientCertOptions{
			commonName: "expired-client",
			notBefore:  time.Now().Add(-48 * time.Hour),
			notAfter:   time.Now().Add(-24 * time.Hour),
		})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
		})

		_, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(expiredClient, tls.VersionTLS13))
		if err == nil {
			t.Fatal("handshake with expired client cert succeeded; want a TLS error")
		}
	})

	t.Run("client certificate not yet valid is rejected", func(t *testing.T) {
		h := newMTLSHarness(t)
		futureClient := h.issueClient(t, clientCertOptions{
			commonName: "future-client",
			notBefore:  time.Now().Add(24 * time.Hour),
			notAfter:   time.Now().Add(48 * time.Hour),
		})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
		})

		_, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(futureClient, tls.VersionTLS13))
		if err == nil {
			t.Fatal("handshake with not-yet-valid client cert succeeded; want a TLS error")
		}
	})

	t.Run("DNS SAN allowlist accepts a matching client and rejects others", func(t *testing.T) {
		h := newMTLSHarness(t)
		permitted := h.issueClient(t, clientCertOptions{commonName: "permitted", dnsNames: []string{"agent.example.com"}})
		rejected := h.issueClient(t, clientCertOptions{commonName: "rejected", dnsNames: []string{"other.example.com"}})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
			DNSNames:     []string{"agent.example.com"},
		})

		body, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(permitted, tls.VersionTLS13))
		if err != nil {
			t.Fatalf("permitted SAN handshake failed: %v", err)
		}
		if body != "ok" {
			t.Fatalf("permitted body = %q, want ok", body)
		}

		_, err = mtlsRoundTrip(server.URL, h.clientTLSConfig(rejected, tls.VersionTLS13))
		if err == nil {
			t.Fatal("rejected-SAN handshake succeeded; want verifier denial")
		}
	})

	t.Run("SPKI pin accepts only the pinned subject public key", func(t *testing.T) {
		h := newMTLSHarness(t)
		// Pin the SPKI of one specific client; another client signed by
		// the same CA must be rejected even though its chain verifies.
		pinned := h.issueClient(t, clientCertOptions{commonName: "pinned"})
		other := h.issueClient(t, clientCertOptions{commonName: "other"})
		pinnedHex := subjectPublicKeySHA256Hex(pinned.cert)
		if pinnedHex == subjectPublicKeySHA256Hex(other.cert) {
			t.Fatal("two freshly generated clients produced the same SPKI hex — generator entropy bug")
		}
		server := h.startServer(t, ListenTLSConfig{
			CertFile:            h.serverCertPath,
			KeyFile:             h.serverKeyPath,
			ClientCAFile:        h.caPath,
			PublicKeySHA256Pins: []string{pinnedHex},
		})

		if _, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(pinned, tls.VersionTLS13)); err != nil {
			t.Fatalf("pinned-SPKI handshake failed: %v", err)
		}
		if _, err := mtlsRoundTrip(server.URL, h.clientTLSConfig(other, tls.VersionTLS13)); err == nil {
			t.Fatal("non-pinned-SPKI handshake succeeded; want verifier denial")
		}
	})

	t.Run("TLS 1.2 client is rejected by the TLS 1.3 floor", func(t *testing.T) {
		h := newMTLSHarness(t)
		client := h.issueClient(t, clientCertOptions{commonName: "downgrade-attempt"})
		server := h.startServer(t, ListenTLSConfig{
			CertFile:     h.serverCertPath,
			KeyFile:      h.serverKeyPath,
			ClientCAFile: h.caPath,
		})

		// Client pinned to TLS 1.2 only — production server requires 1.3.
		cfg := h.clientTLSConfig(client, tls.VersionTLS13)
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12

		_, err := mtlsRoundTrip(server.URL, cfg)
		if err == nil {
			t.Fatal("TLS 1.2-only client handshake succeeded; server should refuse the downgrade")
		}
		// Go's TLS stack reports this with text along the lines of
		// "protocol version not supported"; assert the rejection rather
		// than the exact phrasing to stay stable across stdlib updates.
	})
}

// --- mTLS harness ---------------------------------------------------------
//
// The harness mints a CA + server keypair once per top-level test (call
// sites use newMTLSHarness(t)), and exposes issueClient for adversarial
// leaves. Server certs are valid for 127.0.0.1; clients use the same
// host to dial the listener. Each helper plays the role that production
// testcert.WriteMutualTLSBundle plays for the happy-path tests — but
// with knobs the production helper deliberately does not expose, so we
// can simulate expired / wrong-CA / off-SAN client identities.

type mtlsHarness struct {
	ca             *testCA
	serverCertPath string
	serverKeyPath  string
	caPath         string
}

func newMTLSHarness(t *testing.T) *mtlsHarness {
	t.Helper()
	ca := newTestCA(t)

	dir := t.TempDir()
	server := ca.issueLeaf(t, leafCertOptions{
		commonName:  "sockguard-mtls-server",
		ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		extKeyUsage: x509.ExtKeyUsageServerAuth,
	})

	serverCertPath := writePEMFile(t, dir, "server-cert.pem", "CERTIFICATE", server.der)
	serverKeyPath := writeECKeyFile(t, dir, "server-key.pem", server.key)
	caPath := writePEMFile(t, dir, "ca.pem", "CERTIFICATE", ca.der)

	return &mtlsHarness{
		ca:             ca,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		caPath:         caPath,
	}
}

// issueClient mints a client leaf off the harness's CA with the given
// adversarial options. The result is signed by the trusted CA, so any
// verifier-side failure (expired, SAN-mismatch, SPKI-pin-mismatch)
// reflects the listener's identity policy and not the chain validation.
func (h *mtlsHarness) issueClient(t *testing.T, opts clientCertOptions) issuedLeaf {
	t.Helper()
	return h.ca.issueClient(t, opts)
}

func (h *mtlsHarness) startServer(t *testing.T, cfg ListenTLSConfig) *mtlsTestServer {
	t.Helper()
	tlsCfg, err := BuildMutualTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("BuildMutualTLSServerConfig: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}),
		// A short read header timeout keeps a stuck handshake from
		// dragging the suite past the test timeout if a regression
		// makes the verifier wedge instead of returning an error.
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return &mtlsTestServer{URL: "https://" + ln.Addr().String()}
}

// clientTLSConfig builds a client-side tls.Config that trusts the
// harness CA and presents the supplied leaf. MinVersion defaults to
// TLS 1.3 to match the production server floor; tests that exercise
// the downgrade rejection override the version explicitly.
func (h *mtlsHarness) clientTLSConfig(leaf issuedLeaf, minVersion uint16) *tls.Config {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(h.ca.cert)
	return &tls.Config{
		MinVersion: minVersion,
		ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.der},
			PrivateKey:  leaf.key,
			Leaf:        leaf.cert,
		}},
		RootCAs: rootPool,
	}
}

type mtlsTestServer struct {
	URL string
}

func mtlsRoundTrip(url string, clientCfg *tls.Config) (string, error) {
	tr := &http.Transport{
		TLSClientConfig:     clientCfg,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("unexpected status: " + resp.Status + " body: " + string(body))
	}
	return strings.TrimSpace(string(body)), nil
}

// --- cert minting toolkit ------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA GenerateKey: %v", err)
	}
	tmpl := mtlsTestTemplate(t, "sockguard-mtls-test-ca")
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.BasicConstraintsValid = true

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{cert: cert, der: der, key: key}
}

type leafCertOptions struct {
	commonName  string
	dnsNames    []string
	ipAddresses []net.IP
	notBefore   time.Time
	notAfter    time.Time
	extKeyUsage x509.ExtKeyUsage
}

type clientCertOptions = leafCertOptions

type issuedLeaf struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func (c *testCA) issueLeaf(t *testing.T, opts leafCertOptions) issuedLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf GenerateKey: %v", err)
	}
	tmpl := mtlsTestTemplate(t, opts.commonName)
	if !opts.notBefore.IsZero() {
		tmpl.NotBefore = opts.notBefore
	}
	if !opts.notAfter.IsZero() {
		tmpl.NotAfter = opts.notAfter
	}
	tmpl.DNSNames = opts.dnsNames
	tmpl.IPAddresses = opts.ipAddresses
	usage := opts.extKeyUsage
	if usage == 0 {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return issuedLeaf{cert: cert, der: der, key: key}
}

// issueClient is issueLeaf specialized for client certs; the unused
// *testing.T parameter is accepted so the signature matches the
// stranger-CA helper used in the wrong-CA subtest.
func (c *testCA) issueClient(t *testing.T, opts clientCertOptions) issuedLeaf {
	if opts.extKeyUsage == 0 {
		opts.extKeyUsage = x509.ExtKeyUsageClientAuth
	}
	return c.issueLeaf(t, opts)
}

func writePEMFile(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = file.Close()
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	return path
}

func writeECKeyFile(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}
	return writePEMFile(t, dir, name, "EC PRIVATE KEY", der)
}

func mtlsTestTemplate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("serial number: %v", err)
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
}
