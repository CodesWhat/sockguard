package proxy

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/responsefilter"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// newDaemonResolverForTest points an upstream.Resolver at handler over plain
// TCP, so the request reaches it through the same pooled net/http Transport
// production uses. That matters here specifically: Transport is what would
// re-add Accept-Encoding: gzip to a request that carries none, which is why
// the strip is a Set to identity rather than a Del.
func newDaemonResolverForTest(t *testing.T, handler http.Handler) *upstream.Resolver {
	t.Helper()

	daemon := httptest.NewServer(handler)
	t.Cleanup(daemon.Close)

	ep, err := upstream.BuildEndpoint(upstream.EndpointSpec{
		Address:               "tcp://" + strings.TrimPrefix(daemon.URL, "http://"),
		InsecureAllowPlainTCP: true,
	})
	if err != nil {
		t.Fatalf("BuildEndpoint: %v", err)
	}
	resolver, err := upstream.New([]upstream.Endpoint{ep}, upstream.Options{Interval: -1})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return resolver
}

// TestProxyPinsIdentityAcceptEncodingAtTheDaemon asserts the header the
// daemon actually receives, not the one the Rewrite wrote. Asserting the
// clone would pass just as well for a Del, which net/http would then turn
// back into gzip on the wire.
func TestProxyPinsIdentityAcceptEncodingAtTheDaemon(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	resolver := newDaemonResolverForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	rp := NewWithTransport(resolver, testLogger(), Options{})

	req := httptest.NewRequest(http.MethodGet, "http://client/v1.53/containers/json", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := <-seen; got != "identity" {
		t.Fatalf("daemon saw Accept-Encoding = %q, want identity", got)
	}
	// The strip happens on ReverseProxy's outbound clone, so the inbound
	// request still has to say what the client sent for the access log.
	if got := req.Header.Get("Accept-Encoding"); got != "gzip, br" {
		t.Fatalf("inbound Accept-Encoding = %q, want the client's request left intact for the logs", got)
	}
}

// TestProxyDecodesGzipResponseFromDaemonIgnoringIdentity is the end-to-end
// backstop. The daemon here compresses despite being asked for identity,
// which is what a TLS-terminating proxy in front of a remote daemon does, and
// the client still gets a redacted, uncompressed body instead of a 502.
func TestProxyDecodesGzipResponseFromDaemonIgnoringIdentity(t *testing.T) {
	t.Parallel()

	resolver := newDaemonResolverForTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(`{"Id":"abc123","Config":{"Env":["SECRET=shh"]}}`))
		_ = gz.Close()
	}))

	responsePolicy := responsefilter.New(responsefilter.Options{RedactContainerEnv: true})
	rp := NewWithTransport(resolver, testLogger(), Options{ModifyResponse: responsePolicy.ModifyResponse})

	req := httptest.NewRequest(http.MethodGet, "http://client/v1.53/containers/abc123/json", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("client saw Content-Encoding = %q, want it dropped with the decoded body", got)
	}

	var payload struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("client body is not JSON: %v\nbody: %q", err, rec.Body.String())
	}
	if len(payload.Config.Env) != 0 {
		t.Fatalf("Config.Env = %v, want it redacted", payload.Config.Env)
	}
}

// TestProxyForwardsGzipResponseOnUnfilteredRoute is the other side of that:
// the filter claims no handler for GET /images/json, so the daemon's
// compressed body reaches the client as-is and stays decodable by it.
func TestProxyForwardsGzipResponseOnUnfilteredRoute(t *testing.T) {
	t.Parallel()

	const upstreamBody = `[{"Id":"sha256:aa"}]`
	resolver := newDaemonResolverForTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(upstreamBody))
		_ = gz.Close()
	}))

	responsePolicy := responsefilter.New(responsefilter.Options{
		RedactContainerEnv:    true,
		RedactMountPaths:      true,
		RedactNetworkTopology: true,
		RedactSensitiveData:   true,
		RedactHostTopology:    true,
	})
	rp := NewWithTransport(resolver, testLogger(), Options{ModifyResponse: responsePolicy.ModifyResponse})

	req := httptest.NewRequest(http.MethodGet, "http://client/v1.53/images/json", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("client saw Content-Encoding = %q, want gzip forwarded with the untouched body", got)
	}

	gzr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("client body is not gzip: %v", err)
	}
	body, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != upstreamBody {
		t.Fatalf("body = %q, want %q", body, upstreamBody)
	}
}
