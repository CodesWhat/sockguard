package clientacl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/filter"
	"github.com/codeswhat/sockguard/internal/logging"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeResolver struct {
	client resolvedClient
	found  bool
	err    error
}

func (f fakeResolver) deps() aclDeps {
	return aclDeps{
		resolveClient: func(context.Context, netip.Addr) (resolvedClient, bool, error) {
			return f.client, f.found, f.err
		},
	}
}

func verifiedClientTLS(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

func testSubjectPublicKeySHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func TestMiddlewareDeniesRemoteIPOutsideAllowedCIDRs(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		AllowedCIDRs: []string{"10.0.0.0/8"},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected request to be denied")
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestMiddlewareAllowsRemoteIPWithinAllowedCIDRs(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		AllowedCIDRs: []string{"192.0.2.0/24"},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareAssignsProfileFromSourceIP(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "watchtower", CIDRs: []string{"192.0.2.0/24"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := RequestProfile(r)
		if !ok || profile != "watchtower" {
			t.Fatalf("RequestProfile() = (%q, %v), want (watchtower, true)", profile, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareAssignsProfileFromClientCertificate(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "portainer", CommonNames: []string{"portainer-admin"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := RequestProfile(r)
		if !ok || profile != "portainer" {
			t.Fatalf("RequestProfile() = (%q, %v), want (portainer, true)", profile, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.TLS = verifiedClientTLS(&x509.Certificate{Subject: pkix.Name{CommonName: "portainer-admin"}})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareIgnoresUnverifiedPeerCertificateForProfileSelection(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "portainer", CommonNames: []string{"portainer-admin"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if profile, ok := RequestProfile(r); ok {
			t.Fatalf("RequestProfile() = (%q, true), want no profile from unverified peer certificate", profile)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "portainer-admin"}},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareLogsMatchedProfileStrategyAtDebugLevel(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	handler := middlewareWithDeps(logger, Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "watchtower", CIDRs: []string{"192.0.2.0/24"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "client ACL profile matched") {
		t.Fatalf("expected profile match log, got %q", logOutput)
	}
	if !strings.Contains(logOutput, "strategy=source_ip") {
		t.Fatalf("expected source_ip strategy in log, got %q", logOutput)
	}
	if !strings.Contains(logOutput, "profile=watchtower") {
		t.Fatalf("expected matched profile in log, got %q", logOutput)
	}
}

func TestMiddlewarePrefersVerifiedClientCertificateChain(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "portainer", CommonNames: []string{"portainer-admin"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := RequestProfile(r)
		if !ok || profile != "portainer" {
			t.Fatalf("RequestProfile() = (%q, %v), want (portainer, true)", profile, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "unverified-client"}},
		},
		VerifiedChains: [][]*x509.Certificate{
			{
				{Subject: pkix.Name{CommonName: "portainer-admin"}},
			},
		},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareAssignsProfileFromClientCertificateExtendedSelectors(t *testing.T) {
	spiffeURI, err := url.Parse("spiffe://sockguard.test/workload/portainer")
	if err != nil {
		t.Fatalf("Parse SPIFFE URI: %v", err)
	}
	uriSAN, err := url.Parse("urn:example:sockguard:test")
	if err != nil {
		t.Fatalf("Parse URI SAN: %v", err)
	}

	tests := []struct {
		name        string
		assignments []ClientCertificateProfileAssignment
		cert        *x509.Certificate
		wantProfile string
	}{
		{
			name: "dns san",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "dashboard", DNSNames: []string{"dashboard.internal"}},
			},
			cert:        &x509.Certificate{DNSNames: []string{"dashboard.internal"}},
			wantProfile: "dashboard",
		},
		{
			name: "ip san",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "agent", IPAddresses: []string{"192.0.2.44"}},
			},
			cert:        &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.0.2.44")}},
			wantProfile: "agent",
		},
		{
			name: "uri san",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "uri-client", URISANs: []string{"urn:example:sockguard:test"}},
			},
			cert:        &x509.Certificate{URIs: []*url.URL{uriSAN}},
			wantProfile: "uri-client",
		},
		{
			name: "spiffe id",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "spiffe-client", SPIFFEIDs: []string{"spiffe://sockguard.test/workload/portainer"}},
			},
			cert:        &x509.Certificate{URIs: []*url.URL{spiffeURI}},
			wantProfile: "spiffe-client",
		},
		{
			name: "spki pin",
			assignments: []ClientCertificateProfileAssignment{
				{
					Profile: "pinned-client",
					PublicKeySHA256Pins: []string{
						"sha256:" + strings.ToUpper(testSubjectPublicKeySHA256Hex(&x509.Certificate{
							RawSubjectPublicKeyInfo: []byte("pinned-client-key"),
						})),
					},
				},
			},
			cert: &x509.Certificate{
				RawSubjectPublicKeyInfo: []byte("pinned-client-key"),
			},
			wantProfile: "pinned-client",
		},
		{
			name: "multiple selectors on one assignment are anded",
			assignments: []ClientCertificateProfileAssignment{
				{
					Profile:   "strict-client",
					DNSNames:  []string{"dashboard.internal"},
					SPIFFEIDs: []string{"spiffe://sockguard.test/workload/portainer"},
				},
			},
			cert: &x509.Certificate{
				DNSNames: []string{"dashboard.internal"},
				URIs:     []*url.URL{spiffeURI},
			},
			wantProfile: "strict-client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := middlewareWithDeps(testLogger(), Options{
				Profiles: ProfileOptions{
					ClientCertificates: tt.assignments,
				},
			}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				profile, ok := RequestProfile(r)
				if !ok || profile != tt.wantProfile {
					t.Fatalf("RequestProfile() = (%q, %v), want (%s, true)", profile, ok, tt.wantProfile)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			req.TLS = verifiedClientTLS(tt.cert)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
		})
	}
}

func TestMatchClientCertificateProfileSelectorSemantics(t *testing.T) {
	uriOne, err := url.Parse("urn:example:sockguard:first")
	if err != nil {
		t.Fatalf("Parse URI SAN: %v", err)
	}
	uriTwo, err := url.Parse("urn:example:sockguard:second")
	if err != nil {
		t.Fatalf("Parse URI SAN: %v", err)
	}
	spiffeOne, err := url.Parse("spiffe://sockguard.test/workload/one")
	if err != nil {
		t.Fatalf("Parse SPIFFE URI: %v", err)
	}
	spiffeTwo, err := url.Parse("spiffe://sockguard.test/workload/two")
	if err != nil {
		t.Fatalf("Parse SPIFFE URI: %v", err)
	}

	tests := []struct {
		name        string
		assignments []ClientCertificateProfileAssignment
		cert        *x509.Certificate
		wantProfile string
		wantOK      bool
	}{
		{
			name: "dns names are ORed within a selector field",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "dns-client", DNSNames: []string{"api.internal", "dashboard.internal"}},
			},
			cert:        &x509.Certificate{DNSNames: []string{"dashboard.internal"}},
			wantProfile: "dns-client",
			wantOK:      true,
		},
		{
			name: "ip addresses are ORed within a selector field",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "ip-client", IPAddresses: []string{"192.0.2.10", "192.0.2.44"}},
			},
			cert:        &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.0.2.44")}},
			wantProfile: "ip-client",
			wantOK:      true,
		},
		{
			name: "uri sans are ORed within a selector field",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "uri-client", URISANs: []string{"urn:example:sockguard:first", "urn:example:sockguard:second"}},
			},
			cert:        &x509.Certificate{URIs: []*url.URL{uriTwo}},
			wantProfile: "uri-client",
			wantOK:      true,
		},
		{
			name: "spiffe ids are ORed within a selector field",
			assignments: []ClientCertificateProfileAssignment{
				{Profile: "spiffe-client", SPIFFEIDs: []string{"spiffe://sockguard.test/workload/one", "spiffe://sockguard.test/workload/two"}},
			},
			cert:        &x509.Certificate{URIs: []*url.URL{spiffeTwo}},
			wantProfile: "spiffe-client",
			wantOK:      true,
		},
		{
			name: "spki pins are ORed within a selector field",
			assignments: []ClientCertificateProfileAssignment{
				{
					Profile: "pinned-client",
					PublicKeySHA256Pins: []string{
						strings.Repeat("a", 64),
						"sha256:" + strings.ToUpper(testSubjectPublicKeySHA256Hex(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("second-key")})),
					},
				},
			},
			cert: &x509.Certificate{
				RawSubjectPublicKeyInfo: []byte("second-key"),
			},
			wantProfile: "pinned-client",
			wantOK:      true,
		},
		{
			name: "different certificate selector fields are ANDed together",
			assignments: []ClientCertificateProfileAssignment{
				{
					Profile:             "strict-client",
					DNSNames:            []string{"api.internal", "dashboard.internal"},
					IPAddresses:         []string{"192.0.2.10", "192.0.2.44"},
					URISANs:             []string{"urn:example:sockguard:first", "urn:example:sockguard:second"},
					SPIFFEIDs:           []string{"spiffe://sockguard.test/workload/one", "spiffe://sockguard.test/workload/two"},
					PublicKeySHA256Pins: []string{testSubjectPublicKeySHA256Hex(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("strict-key")})},
				},
			},
			cert: &x509.Certificate{
				DNSNames:                []string{"dashboard.internal"},
				IPAddresses:             []net.IP{net.ParseIP("192.0.2.44")},
				URIs:                    []*url.URL{uriOne, spiffeTwo},
				RawSubjectPublicKeyInfo: []byte("strict-key"),
			},
			wantProfile: "strict-client",
			wantOK:      true,
		},
		{
			name: "different certificate selector fields fail when one populated field misses",
			assignments: []ClientCertificateProfileAssignment{
				{
					Profile:             "strict-client",
					DNSNames:            []string{"dashboard.internal"},
					IPAddresses:         []string{"192.0.2.44"},
					URISANs:             []string{"urn:example:sockguard:first"},
					SPIFFEIDs:           []string{"spiffe://sockguard.test/workload/two"},
					PublicKeySHA256Pins: []string{testSubjectPublicKeySHA256Hex(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("strict-key")})},
				},
			},
			cert: &x509.Certificate{
				DNSNames:                []string{"dashboard.internal"},
				IPAddresses:             []net.IP{net.ParseIP("192.0.2.44")},
				URIs:                    []*url.URL{uriOne, spiffeOne},
				RawSubjectPublicKeyInfo: []byte("strict-key"),
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileOptions(Options{
				Profiles: ProfileOptions{ClientCertificates: tt.assignments},
			})
			if err != nil {
				t.Fatalf("compileOptions() error = %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			req.TLS = verifiedClientTLS(tt.cert)

			profile, ok := matchClientCertificateProfile(req, compiled.clientCertProfiles, compiled.clientCertProfileIndex)
			if ok != tt.wantOK {
				t.Fatalf("matchClientCertificateProfile() ok = %v, want %v", ok, tt.wantOK)
			}
			if profile != tt.wantProfile {
				t.Fatalf("matchClientCertificateProfile() profile = %q, want %q", profile, tt.wantProfile)
			}
		})
	}
}

func TestProfileLookupIndexesCacheSourceIPAndClientCertificateMatches(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "watchtower", CIDRs: []string{"192.0.2.0/24"}},
			},
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "portainer", CommonNames: []string{"portainer-admin"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions() error = %v", err)
	}

	addr := netip.MustParseAddr("192.0.2.10")
	profile, ok := matchSourceIPProfile(addr, compiled.sourceIPProfiles, compiled.sourceIPProfileIndex)
	if !ok || profile != "watchtower" {
		t.Fatalf("matchSourceIPProfile() = (%q, %v), want (watchtower, true)", profile, ok)
	}
	if cached, found := compiled.sourceIPProfileIndex.lookup(addr); !found || !cached.ok || cached.profile != "watchtower" {
		t.Fatalf("source IP cache = (%#v, %v), want watchtower hit", cached, found)
	}

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.TLS = verifiedClientTLS(&x509.Certificate{
		Raw:     []byte("client-cert-raw"),
		Subject: pkix.Name{CommonName: "portainer-admin"},
	})

	profile, ok = matchClientCertificateProfile(req, compiled.clientCertProfiles, compiled.clientCertProfileIndex)
	if !ok || profile != "portainer" {
		t.Fatalf("matchClientCertificateProfile() = (%q, %v), want (portainer, true)", profile, ok)
	}

	fingerprint, fingerprintOK := clientCertificateFingerprint(req.TLS.PeerCertificates[0])
	if !fingerprintOK {
		t.Fatal("clientCertificateFingerprint() ok = false, want true")
	}
	if cached, found := compiled.clientCertProfileIndex.lookup(fingerprint); !found || !cached.ok || cached.profile != "portainer" {
		t.Fatalf("client certificate cache = (%#v, %v), want portainer hit", cached, found)
	}
}

func TestSelectProfileReturnsMatchStrategy(t *testing.T) {
	tests := []struct {
		name         string
		options      Options
		request      *http.Request
		clientIP     netip.Addr
		ipOK         bool
		wantProfile  string
		wantStrategy profileMatchStrategy
		wantOK       bool
	}{
		{
			name: "client certificate",
			options: Options{
				Profiles: ProfileOptions{
					ClientCertificates: []ClientCertificateProfileAssignment{
						{Profile: "portainer", CommonNames: []string{"portainer-admin"}},
					},
				},
			},
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
				req.TLS = verifiedClientTLS(&x509.Certificate{Subject: pkix.Name{CommonName: "portainer-admin"}})
				return req
			}(),
			wantProfile:  "portainer",
			wantStrategy: profileMatchStrategyClientCertificate,
			wantOK:       true,
		},
		{
			name: "unix peer",
			options: Options{
				Profiles: ProfileOptions{
					UnixPeers: []UnixPeerProfileAssignment{
						{Profile: "local-admin", UIDs: []uint32{1001}},
					},
				},
			},
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
				return req.WithContext(withUnixPeerCredentials(req.Context(), unixPeerCredentials{UID: 1001}))
			}(),
			wantProfile:  "local-admin",
			wantStrategy: profileMatchStrategyUnixPeer,
			wantOK:       true,
		},
		{
			name: "source ip",
			options: Options{
				Profiles: ProfileOptions{
					SourceIPs: []SourceIPProfileAssignment{
						{Profile: "watchtower", CIDRs: []string{"192.0.2.0/24"}},
					},
				},
			},
			request:      httptest.NewRequest(http.MethodGet, "/_ping", nil),
			clientIP:     netip.MustParseAddr("192.0.2.10"),
			ipOK:         true,
			wantProfile:  "watchtower",
			wantStrategy: profileMatchStrategySourceIP,
			wantOK:       true,
		},
		{
			name: "default profile",
			options: Options{
				Profiles: ProfileOptions{
					DefaultProfile: "readonly",
				},
			},
			request:      httptest.NewRequest(http.MethodGet, "/_ping", nil),
			wantProfile:  "readonly",
			wantStrategy: profileMatchStrategyDefaultProfile,
			wantOK:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileOptions(tt.options)
			if err != nil {
				t.Fatalf("compileOptions() error = %v", err)
			}

			profile, strategy, ok, err := selectProfile(tt.request, tt.clientIP, tt.ipOK, compiled)
			if err != nil {
				t.Fatalf("selectProfile() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("selectProfile() ok = %v, want %v", ok, tt.wantOK)
			}
			if profile != tt.wantProfile {
				t.Fatalf("selectProfile() profile = %q, want %q", profile, tt.wantProfile)
			}
			if strategy != tt.wantStrategy {
				t.Fatalf("selectProfile() strategy = %q, want %q", strategy, tt.wantStrategy)
			}
		})
	}
}

func TestMiddlewareAssignsProfileFromUnixPeerCredentials(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			UnixPeers: []UnixPeerProfileAssignment{
				{
					Profile: "local-admin",
					UIDs:    []uint32{1001},
					GIDs:    []uint32{1002},
					PIDs:    []int32{4242},
				},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := RequestProfile(r)
		if !ok || profile != "local-admin" {
			t.Fatalf("RequestProfile() = (%q, %v), want (local-admin, true)", profile, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req = req.WithContext(withUnixPeerCredentials(req.Context(), unixPeerCredentials{
		UID: 1001,
		GID: 1002,
		PID: 4242,
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMatchUnixPeerProfileSelectorSemantics(t *testing.T) {
	tests := []struct {
		name        string
		assignments []UnixPeerProfileAssignment
		creds       unixPeerCredentials
		wantProfile string
		wantOK      bool
	}{
		{
			name: "uids are ORed within a selector field",
			assignments: []UnixPeerProfileAssignment{
				{Profile: "uid-client", UIDs: []uint32{1001, 1002}},
			},
			creds:       unixPeerCredentials{UID: 1002, GID: 2000, PID: 3000},
			wantProfile: "uid-client",
			wantOK:      true,
		},
		{
			name: "gids are ORed within a selector field",
			assignments: []UnixPeerProfileAssignment{
				{Profile: "gid-client", GIDs: []uint32{2001, 2002}},
			},
			creds:       unixPeerCredentials{UID: 1000, GID: 2002, PID: 3000},
			wantProfile: "gid-client",
			wantOK:      true,
		},
		{
			name: "pids are ORed within a selector field",
			assignments: []UnixPeerProfileAssignment{
				{Profile: "pid-client", PIDs: []int32{3001, 3002}},
			},
			creds:       unixPeerCredentials{UID: 1000, GID: 2000, PID: 3002},
			wantProfile: "pid-client",
			wantOK:      true,
		},
		{
			name: "different unix peer selector fields are ANDed together",
			assignments: []UnixPeerProfileAssignment{
				{Profile: "strict-peer", UIDs: []uint32{1001, 1002}, GIDs: []uint32{2001, 2002}, PIDs: []int32{3001, 3002}},
			},
			creds:       unixPeerCredentials{UID: 1002, GID: 2002, PID: 3002},
			wantProfile: "strict-peer",
			wantOK:      true,
		},
		{
			name: "different unix peer selector fields fail when one populated field misses",
			assignments: []UnixPeerProfileAssignment{
				{Profile: "strict-peer", UIDs: []uint32{1001, 1002}, GIDs: []uint32{2001, 2002}, PIDs: []int32{3001, 3002}},
			},
			creds:  unixPeerCredentials{UID: 1002, GID: 2999, PID: 3002},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileOptions(Options{
				Profiles: ProfileOptions{UnixPeers: tt.assignments},
			})
			if err != nil {
				t.Fatalf("compileOptions() error = %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
			req = req.WithContext(withUnixPeerCredentials(req.Context(), tt.creds))

			profile, ok, err := matchUnixPeerProfile(req, compiled.unixPeerProfiles)
			if err != nil {
				t.Fatalf("matchUnixPeerProfile() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("matchUnixPeerProfile() ok = %v, want %v", ok, tt.wantOK)
			}
			if profile != tt.wantProfile {
				t.Fatalf("matchUnixPeerProfile() profile = %q, want %q", profile, tt.wantProfile)
			}
		})
	}
}

func TestConnContextCapturesUnixPeerCredentials(t *testing.T) {
	socketPath := filepath.Join("/tmp", "sockguard-clientacl-peer-"+strconvTime()+".sock")
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	var serverConn net.Conn
	select {
	case err := <-acceptErr:
		t.Fatalf("accept unix: %v", err)
	case serverConn = <-accepted:
	}
	defer serverConn.Close()

	ctx := ConnContext(context.Background(), serverConn)
	creds, ok := unixPeerCredentialsFromContext(ctx)
	if !ok {
		t.Fatal("expected unix peer credentials in context")
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Fatalf("UID = %d, want %d", creds.UID, os.Getuid())
	}
	if creds.GID != uint32(os.Getgid()) {
		t.Fatalf("GID = %d, want %d", creds.GID, os.Getgid())
	}
	if creds.PID <= 0 {
		t.Fatalf("PID = %d, want > 0", creds.PID)
	}
}

func TestMiddlewareNoOpWithoutConfiguredACLs(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusNoContent {
		t.Fatalf("reached=%v status=%d, want true/204", reached, rec.Code)
	}
}

func TestMiddlewareDeniesWhenRemoteAddrMissingUnderCIDRPolicy(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		AllowedCIDRs: []string{"10.0.0.0/8"},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected request to be denied")
	}))

	req := httptest.NewRequest(http.MethodGet, "/_ping", nil)
	req.RemoteAddr = ""
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareAllowsClientContainerLabelRuleMatch(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: "com.sockguard.allow.",
		},
	}, fakeResolver{
		found: true,
		client: resolvedClient{
			Labels: map[string]string{
				"com.sockguard.allow.get": "/containers/**,/events",
			},
		},
	}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestMiddlewareDeniesClientContainerLabelRuleMiss(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: "com.sockguard.allow.",
		},
	}, fakeResolver{
		found: true,
		client: resolvedClient{
			Labels: map[string]string{
				"com.sockguard.allow.get": "/events",
			},
		},
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected request to be denied")
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestMiddlewarePassesThroughWhenResolvedContainerHasNoACLLabels(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: "com.sockguard.allow.",
		},
	}, fakeResolver{
		found: true,
		client: resolvedClient{
			Labels: map[string]string{
				"com.example.other": "value",
			},
		},
	}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewarePassesThroughWhenClientCannotBeResolved(t *testing.T) {
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: DefaultLabelPrefix,
		},
	}, fakeResolver{found: false}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusNoContent {
		t.Fatalf("reached=%v status=%d, want true/204", reached, rec.Code)
	}
}

func TestMiddlewareReturnsBadGatewayWhenClientLookupFails(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: "com.sockguard.allow.",
		},
	}, fakeResolver{
		err: errors.New("dial boom"),
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected lookup failure to short-circuit request")
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}

func TestMiddlewareReturnsBadGatewayWhenResolvedClientHasInvalidACLLabel(t *testing.T) {
	handler := middlewareWithDeps(testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{
			Enabled:     true,
			LabelPrefix: DefaultLabelPrefix,
		},
	}, fakeResolver{
		found: true,
		client: resolvedClient{
			Name:   "traefik",
			ID:     "client-1",
			Labels: map[string]string{DefaultLabelPrefix + "custom": "/containers/**"},
		},
	}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected invalid ACL label to short-circuit request")
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:45678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestMiddlewareWrapperResolvesClientLabelsViaUnixSocket(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Fatalf("path = %q, want /containers/json", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Id":     "client-1",
				"Names":  []string{"/traefik"},
				"Labels": map[string]string{DefaultLabelPrefix + "get": "/containers/**"},
				"NetworkSettings": map[string]any{
					"Networks": map[string]any{
						"default": map[string]any{"IPAddress": "172.18.0.5"},
					},
				},
			},
		})
	}))

	handler := Middleware(socketPath, testLogger(), Options{
		ContainerLabels: ContainerLabelOptions{Enabled: true, LabelPrefix: DefaultLabelPrefix},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	req.RemoteAddr = "172.18.0.5:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestMiddlewareWrapperReturnsInternalServerErrorForInvalidConfig(t *testing.T) {
	meta := &logging.RequestMeta{}
	handler := Middleware("/unused.sock", testLogger(), Options{
		AllowedCIDRs: []string{"not-a-cidr"},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected misconfigured middleware to short-circuit")
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if meta.Decision != "deny" || meta.Reason != "client ACL misconfigured" {
		t.Fatalf("meta = %#v, want deny/client ACL misconfigured", meta)
	}
}

func TestCompileOptions(t *testing.T) {
	compiled, err := compileOptions(Options{
		AllowedCIDRs: []string{"192.0.2.0/24"},
		ContainerLabels: ContainerLabelOptions{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("compileOptions() error = %v", err)
	}
	if !compiled.labelsOn {
		t.Fatal("expected labelsOn=true")
	}
	if compiled.labelPrefix != DefaultLabelPrefix {
		t.Fatalf("labelPrefix = %q, want %q", compiled.labelPrefix, DefaultLabelPrefix)
	}
	if len(compiled.allowedCIDRs) != 1 || !compiled.allowedCIDRs[0].Contains(netip.MustParseAddr("192.0.2.10")) {
		t.Fatalf("allowedCIDRs = %#v, want 192.0.2.0/24", compiled.allowedCIDRs)
	}

	if _, err := compileOptions(Options{AllowedCIDRs: []string{"bad"}}); err == nil {
		t.Fatal("expected invalid CIDR error")
	}

	if _, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "bad-pin-client", PublicKeySHA256Pins: []string{"not-a-pin"}},
			},
		},
	}); err == nil || !strings.Contains(err.Error(), "public_key_sha256_pins") {
		t.Fatalf("expected invalid public_key_sha256_pins error, got: %v", err)
	}
}

func TestRemoteIP(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "empty", input: "", wantOK: false},
		{name: "ipv4 hostport", input: "192.0.2.10:12345", want: "192.0.2.10", wantOK: true},
		{name: "ipv4 bare", input: "192.0.2.11", want: "192.0.2.11", wantOK: true},
		{name: "ipv6 hostport", input: "[2001:db8::1]:2375", want: "2001:db8::1", wantOK: true},
		{name: "invalid", input: "not-an-ip", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := remoteIP(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("remoteIP(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Fatalf("remoteIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCompileContainerLabelRules(t *testing.T) {
	rules, hasACL, err := compileContainerLabelRules(nil, DefaultLabelPrefix)
	if err != nil || hasACL || rules != nil {
		t.Fatalf("compileContainerLabelRules(nil) = (%v, %v, %v), want (nil, false, nil)", rules, hasACL, err)
	}

	rules, hasACL, err = compileContainerLabelRules(map[string]string{
		DefaultLabelPrefix + "get": "/containers/**, /events ",
	}, DefaultLabelPrefix)
	if err != nil {
		t.Fatalf("compileContainerLabelRules() error = %v", err)
	}
	if !hasACL || len(rules) != 2 {
		t.Fatalf("got hasACL=%v len=%d, want true and 2 rules", hasACL, len(rules))
	}

	rules, hasACL, err = compileContainerLabelRules(map[string]string{
		"com.example.other": "/containers/**",
	}, DefaultLabelPrefix)
	if err != nil || hasACL || len(rules) != 0 {
		t.Fatalf("compileContainerLabelRules(non-prefixed) = (%v, %v, %v), want (empty, false, nil)", rules, hasACL, err)
	}

	if _, _, err := compileContainerLabelRules(map[string]string{
		DefaultLabelPrefix + "custom": "/containers/**",
	}, DefaultLabelPrefix); err == nil {
		t.Fatal("expected unsupported method label error")
	}

	if _, _, err := compileContainerLabelRules(map[string]string{
		DefaultLabelPrefix + "get": " , ",
	}, DefaultLabelPrefix); err == nil {
		t.Fatal("expected empty pattern error")
	}

	if _, _, err := compileContainerLabelRulesWith(map[string]string{
		DefaultLabelPrefix + "get": "/containers/**",
	}, DefaultLabelPrefix, func(filter.Rule) (*filter.CompiledRule, error) {
		return nil, errors.New("compile boom")
	}); err == nil {
		t.Fatal("expected compile error")
	}

	// Lock in deterministic rule ordering. Go randomizes map iteration on
	// every run, so without the explicit sort in compileContainerLabelRulesWith
	// the (index, error reporting, first-match-wins) contract would flake.
	// Keys are sorted alphabetically ahead of iteration, so `get` lands before
	// `post` and rule 0 is the GET rule regardless of the underlying map order.
	multi := map[string]string{
		DefaultLabelPrefix + "post": "/containers/*/start",
		DefaultLabelPrefix + "get":  "/containers/**",
	}
	ordered, _, err := compileContainerLabelRules(multi, DefaultLabelPrefix)
	if err != nil || len(ordered) != 2 {
		t.Fatalf("compileContainerLabelRules(multi) = (%v, %v), want 2 rules nil error", len(ordered), err)
	}
	if ordered[0].Index != 0 || ordered[1].Index != 1 {
		t.Fatalf("rule indices = (%d, %d), want (0, 1) in sorted key order", ordered[0].Index, ordered[1].Index)
	}
}

func TestLabelMethod(t *testing.T) {
	tests := []struct {
		key  string
		want string
		ok   bool
	}{
		{key: DefaultLabelPrefix + "get", want: http.MethodGet, ok: true},
		{key: DefaultLabelPrefix + "head", want: http.MethodHead, ok: true},
		{key: DefaultLabelPrefix + "post", want: http.MethodPost, ok: true},
		{key: DefaultLabelPrefix + "put", want: http.MethodPut, ok: true},
		{key: DefaultLabelPrefix + "delete", want: http.MethodDelete, ok: true},
		{key: DefaultLabelPrefix + "patch", want: http.MethodPatch, ok: true},
		{key: DefaultLabelPrefix + "options", want: http.MethodOptions, ok: true},
		{key: DefaultLabelPrefix + "connect", want: http.MethodConnect, ok: true},
		{key: DefaultLabelPrefix + "trace", want: http.MethodTrace, ok: true},
		{key: DefaultLabelPrefix + "custom", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := labelMethod(tt.key, DefaultLabelPrefix)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("labelMethod(%q) = (%q, %v), want (%q, %v)", tt.key, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSplitLabelPatterns(t *testing.T) {
	if got := splitLabelPatterns(" /events , /containers/** "); len(got) != 2 || got[0] != "/events" || got[1] != "/containers/**" {
		t.Fatalf("splitLabelPatterns() = %#v, want [/events /containers/**]", got)
	}
	if got := splitLabelPatterns(" , "); len(got) != 0 {
		t.Fatalf("splitLabelPatterns(all whitespace) = %#v, want empty", got)
	}
}

func TestResolveClient(t *testing.T) {
	socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RawQuery {
		default:
			_, _ = w.Write([]byte(`[{"Id":"client-1","Names":["/traefik"],"Labels":{"` + DefaultLabelPrefix + `get":"/events"},"NetworkSettings":{"Networks":{"default":{"IPAddress":"172.18.0.5"},"v6":{"GlobalIPv6Address":"2001:db8::5"}}}}]`))
		}
	}))

	resolver := upstreamResolver{client: newUnixHTTPClient(socketPath)}

	client, found, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("172.18.0.5"))
	if err != nil {
		t.Fatalf("resolveClient() error = %v", err)
	}
	if !found {
		t.Fatal("expected client to be found")
	}
	if client.ID != "client-1" || client.Name != "traefik" {
		t.Fatalf("client = %#v, want ID client-1 and Name traefik", client)
	}

	client, found, err = resolver.resolveClient(context.Background(), netip.MustParseAddr("2001:db8::5"))
	if err != nil || !found || client.Name != "traefik" {
		t.Fatalf("resolveClient(v6) = (%#v, %v, %v), want traefik/true/nil", client, found, err)
	}
}

func TestResolveClientNotFoundAndErrors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		}))
		resolver := upstreamResolver{client: newUnixHTTPClient(socketPath)}

		_, found, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("172.18.0.99"))
		if err != nil || found {
			t.Fatalf("resolveClient() = found %v err %v, want false nil", found, err)
		}
	})

	t.Run("bad status", func(t *testing.T) {
		socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusBadGateway)
		}))
		resolver := upstreamResolver{client: newUnixHTTPClient(socketPath)}

		_, _, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("172.18.0.5"))
		if err == nil || !strings.Contains(err.Error(), "docker container lookup status 502") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		socketPath := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		resolver := upstreamResolver{client: newUnixHTTPClient(socketPath)}

		_, _, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("172.18.0.5"))
		if err == nil {
			t.Fatal("expected invalid JSON error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		socketPath := filepath.Join("/tmp", "sockguard-clientacl-missing-"+strconvTime()+".sock")
		resolver := upstreamResolver{client: newUnixHTTPClient(socketPath)}

		_, _, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("172.18.0.5"))
		if err == nil {
			t.Fatal("expected transport error")
		}
	})
}

func TestContainerHelpers(t *testing.T) {
	container := listedContainer{
		ID:     "abc",
		Names:  []string{"/demo"},
		Labels: map[string]string{"k": "v"},
	}
	container.NetworkSettings.Networks = map[string]struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}{
		"default": {IPAddress: "192.0.2.10"},
		"v6":      {GlobalIPv6Address: "2001:db8::10"},
		"bad":     {IPAddress: "not-an-ip"},
	}

	if !containerHasIP(container, netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("expected IPv4 match")
	}
	if !containerHasIP(container, netip.MustParseAddr("2001:db8::10")) {
		t.Fatal("expected IPv6 match")
	}
	if containerHasIP(container, netip.MustParseAddr("192.0.2.99")) {
		t.Fatal("did not expect unmatched IP")
	}

	if !ipMatches("192.0.2.10", netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("expected ipMatches success")
	}
	if ipMatches("", netip.MustParseAddr("192.0.2.10")) || ipMatches("bad", netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("expected ipMatches failure for empty/invalid input")
	}

	if got := firstContainerName(container.Names); got != "demo" {
		t.Fatalf("firstContainerName() = %q, want demo", got)
	}
	if got := firstContainerName(nil); got != "" {
		t.Fatalf("firstContainerName(nil) = %q, want empty", got)
	}
	if got := clientName(resolvedClient{Name: "traefik", ID: "abc"}); got != "traefik" {
		t.Fatalf("clientName(named) = %q, want traefik", got)
	}
	if got := clientName(resolvedClient{ID: "abc"}); got != "abc" {
		t.Fatalf("clientName(fallback) = %q, want abc", got)
	}
}

func TestClientACLSetDeniedNormalizesPath(t *testing.T) {
	// clientacl fires logging.SetDenied with filter.NormalizePath so the
	// access log still carries a clean path even when clientacl runs
	// before the filter middleware stamps meta.NormPath.
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	writer := &metaCarrierWriter{meta: meta}

	logging.SetDenied(writer, req, "nope", filter.NormalizePath)
	if meta.Decision != "deny" || meta.Reason != "nope" || meta.NormPath != "/containers/json" {
		t.Fatalf("meta after SetDenied = %#v", meta)
	}

	// No panic when there is no meta to stamp.
	logging.SetDenied(httptest.NewRecorder(), req, "ignored", filter.NormalizePath)
}

type metaCarrierWriter struct {
	http.ResponseWriter
	meta *logging.RequestMeta
}

func (w *metaCarrierWriter) Header() http.Header               { return make(http.Header) }
func (w *metaCarrierWriter) Write([]byte) (int, error)         { return 0, nil }
func (w *metaCarrierWriter) WriteHeader(statusCode int)        {}
func (w *metaCarrierWriter) RequestMeta() *logging.RequestMeta { return w.meta }

func startUnixHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	socketPath := filepath.Join("/tmp", "sockguard-clientacl-"+strings.ReplaceAll(strings.ToLower(t.Name()), "/", "-")+"-"+strconvTime()+".sock")
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	})

	return socketPath
}

func newUnixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func strconvTime() string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", ""), ":", ""), "0")
}
