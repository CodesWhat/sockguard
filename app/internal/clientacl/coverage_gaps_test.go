package clientacl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/internal/logging"
)

// ---- storeLocked: TTL-scrub removes all stale entries so havingOldest stays false

func TestStoreLocked_ScrubbedAllStale(t *testing.T) {
	baseNow := time.Unix(1_700_000_000, 0)
	now := baseNow

	cache := newClientCache(
		5*time.Second,
		1,
		func() time.Time { return now },
		func(_ context.Context, _ netip.Addr) (resolvedClient, bool, error) {
			return resolvedClient{ID: "x"}, true, nil
		},
	)

	ctx := context.Background()
	a := mustAddr(t, "10.0.0.1")
	b := mustAddr(t, "10.0.0.2")

	if _, _, err := cache.Lookup(ctx, a); err != nil {
		t.Fatalf("lookup a: %v", err)
	}

	// Advance past TTL so entry for a is stale.
	now = baseNow.Add(10 * time.Second)

	// Insert b: cache at maxSize=1; TTL-scrub removes stale a, leaving len=0,
	// so havingOldest stays false and the "evict oldest" branch is skipped.
	if _, _, err := cache.Lookup(ctx, b); err != nil {
		t.Fatalf("lookup b: %v", err)
	}

	if _, found, _ := cache.Lookup(ctx, b); !found {
		t.Fatal("expected b to be cached after stale-scrub insertion")
	}
}

// ---- compileOptions: error paths for profile selector parsing

func TestCompileOptions_InvalidProfileCIDR(t *testing.T) {
	_, err := compileOptions(Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "p", CIDRs: []string{"not-a-cidr"}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected parse profile CIDR error")
	}
}

func TestCompileOptions_InvalidIPSAN(t *testing.T) {
	_, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", IPAddresses: []string{"not-an-ip"}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected IP SAN parse error")
	}
}

func TestCompileOptions_InvalidURISAN(t *testing.T) {
	// Control character forces url.Parse to return an error.
	_, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", URISANs: []string{string([]byte{0x7f})}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected URI SAN parse error")
	}
}

func TestCompileOptions_InvalidSPIFFEID(t *testing.T) {
	_, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", SPIFFEIDs: []string{string([]byte{0x7f})}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected SPIFFE ID parse error")
	}
}

func TestCompileOptions_BlankCommonNameAndDNSSkipped(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", CommonNames: []string{"  "}, DNSNames: []string{"  "}},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled.clientCertProfiles) != 1 {
		t.Fatalf("expected 1 compiled cert profile, got %d", len(compiled.clientCertProfiles))
	}
	if len(compiled.clientCertProfiles[0].commonNames) != 0 {
		t.Fatalf("expected 0 commonNames after blank skip, got %d", len(compiled.clientCertProfiles[0].commonNames))
	}
	if len(compiled.clientCertProfiles[0].dnsNames) != 0 {
		t.Fatalf("expected 0 dnsNames after blank skip, got %d", len(compiled.clientCertProfiles[0].dnsNames))
	}
}

// ---- RequestProfile: nil request and request with no profile

func TestRequestProfile_NilRequest(t *testing.T) {
	profile, ok := RequestProfile(nil)
	if ok || profile != "" {
		t.Fatalf("RequestProfile(nil) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

func TestRequestProfile_NoProfile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	profile, ok := RequestProfile(req)
	if ok || profile != "" {
		t.Fatalf("RequestProfile(no profile) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- unixPeerCredentialsFromContext: no identity in context

func TestUnixPeerCredentialsFromContext_NoIdentity(t *testing.T) {
	creds, ok := unixPeerCredentialsFromContext(context.Background())
	if ok {
		t.Fatalf("expected ok=false for empty context, got creds=%+v", creds)
	}
}

// ---- ConnContext: non-unix connection returns context unchanged

func TestConnContext_NonUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	result := ConnContext(context.Background(), serverConn)
	_, ok := unixPeerCredentialsFromContext(result)
	if ok {
		t.Fatal("expected no unix peer credentials for a TCP connection")
	}
}

// ---- matchSourceIPProfile: nil index

func TestMatchSourceIPProfile_NilIndex(t *testing.T) {
	assignments := []compiledSourceIPProfileAssignment{
		{profile: "p", cidrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	}

	profile, ok := matchSourceIPProfile(netip.MustParseAddr("10.0.0.1"), assignments, nil)
	if !ok || profile != "p" {
		t.Fatalf("matchSourceIPProfile(nil index, hit) = (%q, %v), want (p, true)", profile, ok)
	}

	profile, ok = matchSourceIPProfile(netip.MustParseAddr("192.0.2.1"), assignments, nil)
	if ok || profile != "" {
		t.Fatalf("matchSourceIPProfile(nil index, miss) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- matchClientCertificateProfile: cert with no Raw (fingerprint not available)

func TestMatchClientCertificateProfile_NilFingerprintCert(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", CommonNames: []string{"test-cn"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = verifiedClientTLS(&x509.Certificate{
		// Raw is nil so fingerprinting is skipped.
		Subject: pkix.Name{CommonName: "test-cn"},
	})

	profile, ok := matchClientCertificateProfile(req, compiled.clientCertProfiles, compiled.clientCertProfileIndex)
	if !ok || profile != "p" {
		t.Fatalf("matchClientCertificateProfile(no fingerprint) = (%q, %v), want (p, true)", profile, ok)
	}
}

// ---- clientCertificateLeaf: TLS state with empty chains and empty peer certs

func TestClientCertificateLeaf_BothEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{} // VerifiedChains=nil, PeerCertificates=nil
	if leaf := clientCertificateLeaf(req); leaf != nil {
		t.Fatalf("expected nil leaf for empty TLS state, got %+v", leaf)
	}
}

// ---- matchUnixPeerProfile: unixPeerErr in context

func TestMatchUnixPeerProfile_UnixPeerError(t *testing.T) {
	peerErr := errors.New("peer credentials lookup failed")
	assignments := []compiledUnixPeerProfileAssignment{
		{profile: "p", uids: []uint32{1001}},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(withConnectionIdentity(req.Context(), connectionIdentity{unixPeerErr: peerErr}))

	_, _, err := matchUnixPeerProfile(req, assignments)
	if !errors.Is(err, peerErr) {
		t.Fatalf("matchUnixPeerProfile() error = %v, want %v", err, peerErr)
	}
}

// ---- compiledUnixPeerProfileAssignment.matches: no selectors

func TestCompiledUnixPeerAssignment_Matches_NoSelectors(t *testing.T) {
	a := compiledUnixPeerProfileAssignment{profile: "p"}
	if a.matches(unixPeerCredentials{UID: 1000, GID: 2000, PID: 3000}) {
		t.Fatal("expected matches=false for assignment with no selectors")
	}
}

// ---- containsInt32: found and not-found cases

func TestContainsInt32(t *testing.T) {
	if !containsInt32([]int32{1, 2, 3}, 2) {
		t.Fatal("expected containsInt32 to find 2")
	}
	if containsInt32([]int32{1, 2, 3}, 99) {
		t.Fatal("expected containsInt32 not to find 99")
	}
}

// ---- compiledClientCertificateProfileAssignment.matches: edge cases

func TestCompiledCertProfileMatches_NilCert(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p", commonNames: []string{"cn"}}
	if a.matches(nil) {
		t.Fatal("expected matches=false for nil cert")
	}
}

func TestCompiledCertProfileMatches_NoSelectors(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p"}
	if a.matches(&x509.Certificate{}) {
		t.Fatal("expected matches=false for assignment with no selectors")
	}
}

func TestCompiledCertProfileMatches_CommonNameMiss(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p", commonNames: []string{"want-cn"}}
	if a.matches(&x509.Certificate{Subject: pkix.Name{CommonName: "other-cn"}}) {
		t.Fatal("expected matches=false for CN miss")
	}
}

func TestCompiledCertProfileMatches_DNSNameMiss(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p", dnsNames: []string{"allowed.internal"}}
	if a.matches(&x509.Certificate{DNSNames: []string{"other.internal"}}) {
		t.Fatal("expected matches=false for DNS name miss")
	}
}

func TestCompiledCertProfileMatches_IPAddrMiss(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{
		profile:     "p",
		ipAddresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
	}
	if a.matches(&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.0.0.2")}}) {
		t.Fatal("expected matches=false for IP address miss")
	}
}

func TestCompiledCertProfileMatches_URISANMiss(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p", uriSANs: []string{"urn:example:allowed"}}
	other, _ := url.Parse("urn:example:other")
	if a.matches(&x509.Certificate{URIs: []*url.URL{other}}) {
		t.Fatal("expected matches=false for URI SAN miss")
	}
}

func TestCompiledCertProfileMatches_SPIFFEIDMatchAndMiss(t *testing.T) {
	a := compiledClientCertificateProfileAssignment{profile: "p", spiffeIDs: []string{"spiffe://allowed/workload"}}
	other, _ := url.Parse("spiffe://other/workload")
	if a.matches(&x509.Certificate{URIs: []*url.URL{other}}) {
		t.Fatal("expected matches=false for SPIFFE ID miss")
	}
	allowed, _ := url.Parse("spiffe://allowed/workload")
	if !a.matches(&x509.Certificate{URIs: []*url.URL{allowed}}) {
		t.Fatal("expected matches=true for matching SPIFFE ID")
	}
}

// ---- intersectsIPAddrs: invalid IP slice (AddrFromSlice fails)

func TestIntersectsIPAddrs_InvalidSlice(t *testing.T) {
	// net.IP with 3 bytes is invalid; AddrFromSlice returns ok=false.
	badIP := net.IP{1, 2, 3}
	if intersectsIPAddrs([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, []net.IP{badIP}) {
		t.Fatal("expected intersectsIPAddrs=false for unparseable IP slice")
	}
}

// ---- certificateURIStrings: nil URL in list

func TestCertificateURIStrings_NilURIInList(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	cert := &x509.Certificate{URIs: []*url.URL{nil, u}}
	result := certificateURIStrings(cert)
	if len(result) != 1 || result[0] != "https://example.com" {
		t.Fatalf("certificateURIStrings = %v, want [https://example.com]", result)
	}
}

// ---- clientCertificateProfileIndex: nil receiver

func TestClientCertProfileIndex_NilReceiver(t *testing.T) {
	var idx *clientCertificateProfileIndex

	result, ok := idx.lookup([32]byte{})
	if ok || result.profile != "" {
		t.Fatalf("nil lookup = (%+v, %v), want (zero, false)", result, ok)
	}

	// Must not panic.
	idx.store([32]byte{}, profileLookupResult{profile: "p", ok: true})
}

// ---- matchSourceIPProfile: cached miss (index has result with ok=false) ----

func TestMatchSourceIPProfile_CachedMiss(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "p", CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	// First call: miss (IP outside all CIDRs) — stores ok=false in index.
	addr := netip.MustParseAddr("192.0.2.99")
	profile, ok := matchSourceIPProfile(addr, compiled.sourceIPProfiles, compiled.sourceIPProfileIndex)
	if ok || profile != "" {
		t.Fatalf("matchSourceIPProfile(miss) = (%q, %v), want (\"\", false)", profile, ok)
	}

	// Second call: same IP, should use cached miss (ok=false path in index.lookup).
	profile, ok = matchSourceIPProfile(addr, compiled.sourceIPProfiles, compiled.sourceIPProfileIndex)
	if ok || profile != "" {
		t.Fatalf("matchSourceIPProfile(cached miss) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- matchClientCertificateProfile: cached miss path ---------------------

func TestMatchClientCertificateProfile_CachedMiss(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			ClientCertificates: []ClientCertificateProfileAssignment{
				{Profile: "p", CommonNames: []string{"want-cn"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	// First call with a cert that has a fingerprint but doesn't match — stores miss in index.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = verifiedClientTLS(&x509.Certificate{
		Raw:     []byte("cert-bytes"),
		Subject: pkix.Name{CommonName: "other-cn"},
	})
	profile, ok := matchClientCertificateProfile(req, compiled.clientCertProfiles, compiled.clientCertProfileIndex)
	if ok || profile != "" {
		t.Fatalf("matchClientCertificateProfile(miss) = (%q, %v), want (\"\", false)", profile, ok)
	}

	// Second call: same cert, index should return cached miss.
	profile, ok = matchClientCertificateProfile(req, compiled.clientCertProfiles, compiled.clientCertProfileIndex)
	if ok || profile != "" {
		t.Fatalf("matchClientCertificateProfile(cached miss) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- matchUnixPeerProfile: no peer creds in context (ok=false, no error) --

func TestMatchUnixPeerProfile_NoCreds(t *testing.T) {
	assignments := []compiledUnixPeerProfileAssignment{
		{profile: "p", uids: []uint32{1001}},
	}
	// Request context has a connectionIdentity with no peer creds and no error.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(withConnectionIdentity(req.Context(), connectionIdentity{}))

	profile, ok, err := matchUnixPeerProfile(req, assignments)
	if err != nil {
		t.Fatalf("matchUnixPeerProfile() error = %v, want nil", err)
	}
	if ok || profile != "" {
		t.Fatalf("matchUnixPeerProfile(no creds) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- matchUnixPeerProfile: creds present but no assignment matches --------

func TestMatchUnixPeerProfile_NoPeerMatch(t *testing.T) {
	compiled, err := compileOptions(Options{
		Profiles: ProfileOptions{
			UnixPeers: []UnixPeerProfileAssignment{
				{Profile: "p", UIDs: []uint32{9999}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(withUnixPeerCredentials(req.Context(), unixPeerCredentials{UID: 1000, GID: 2000, PID: 3000}))

	profile, ok, err := matchUnixPeerProfile(req, compiled.unixPeerProfiles)
	if err != nil {
		t.Fatalf("matchUnixPeerProfile() error = %v", err)
	}
	if ok || profile != "" {
		t.Fatalf("matchUnixPeerProfile(no match) = (%q, %v), want (\"\", false)", profile, ok)
	}
}

// ---- compiledUnixPeerProfileAssignment.matches: GID miss and PID miss ----

func TestCompiledUnixPeerAssignment_Matches_GIDMiss(t *testing.T) {
	a := compiledUnixPeerProfileAssignment{
		profile: "p",
		uids:    []uint32{1001},
		gids:    []uint32{2001},
	}
	// UID matches but GID does not.
	if a.matches(unixPeerCredentials{UID: 1001, GID: 9999, PID: 0}) {
		t.Fatal("expected matches=false when GID misses")
	}
}

func TestCompiledUnixPeerAssignment_Matches_PIDMiss(t *testing.T) {
	a := compiledUnixPeerProfileAssignment{
		profile: "p",
		uids:    []uint32{1001},
		gids:    []uint32{2001},
		pids:    []int32{3001},
	}
	// UID and GID match but PID does not.
	if a.matches(unixPeerCredentials{UID: 1001, GID: 2001, PID: 9999}) {
		t.Fatal("expected matches=false when PID misses")
	}
}

// ---- upstreamResolver.resolveClient: non-200 and JSON-decode error paths ---

func TestResolveClient_Non200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("docker error"))
	}))
	defer srv.Close()

	resolver := upstreamResolver{client: srv.Client()}
	// Redirect the docker URL to the test server by using a custom transport.
	resolver.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req2 := req.Clone(req.Context())
			req2.URL.Scheme = "http"
			req2.URL.Host = srv.Listener.Addr().String()
			return http.DefaultTransport.RoundTrip(req2)
		}),
	}

	_, _, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestResolveClient_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	resolver := upstreamResolver{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req2 := req.Clone(req.Context())
				req2.URL.Scheme = "http"
				req2.URL.Host = srv.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req2)
			}),
		},
	}

	_, _, err := resolver.resolveClient(context.Background(), netip.MustParseAddr("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---- middlewareWithDeps: profile matched + request has logging.Meta → meta.Profile set

func TestMiddlewareWithDeps_ProfileMatchedSetsLogMeta(t *testing.T) {
	// Set up a source-IP profile that matches 10.0.0.0/8.
	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			SourceIPs: []SourceIPProfileAssignment{
				{Profile: "readonly", CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/containers/json", nil)
	req.RemoteAddr = "10.0.0.5:12345"

	// Inject logging meta into the request context so the meta.Profile branch is hit.
	meta := &logging.RequestMeta{}
	req = req.WithContext(logging.WithMeta(req.Context(), meta))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if meta.Profile != "readonly" {
		t.Fatalf("meta.Profile = %q, want %q", meta.Profile, "readonly")
	}
}

// ---- middlewareWithDeps: compileOptions error returns 500 handler

func TestMiddlewareWithDeps_CompileOptionsError(t *testing.T) {
	// An invalid CIDR in AllowedCIDRs causes compileOptions to fail.
	handler := middlewareWithDeps(testLogger(), Options{
		AllowedCIDRs: []string{"not-a-cidr"},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected middleware to deny before reaching handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// ---- middlewareWithDeps: unix peer error propagates as 502

func TestMiddlewareWithDeps_UnixPeerProfileError(t *testing.T) {
	peerErr := errors.New("peer credentials lookup failed")

	handler := middlewareWithDeps(testLogger(), Options{
		Profiles: ProfileOptions{
			UnixPeers: []UnixPeerProfileAssignment{
				{Profile: "local", UIDs: []uint32{1001}},
			},
		},
	}, fakeResolver{}.deps())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected middleware to deny before reaching handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(withConnectionIdentity(req.Context(), connectionIdentity{unixPeerErr: peerErr}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadGateway, rec.Body.String())
	}
}
