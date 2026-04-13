package clientacl

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestSetDeniedMeta(t *testing.T) {
	meta := &logging.RequestMeta{}
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	writer := &metaCarrierWriter{meta: meta}

	setDeniedMeta(writer, req, "nope")
	if meta.Decision != "deny" || meta.Reason != "nope" || meta.NormPath != "/containers/json" {
		t.Fatalf("meta after setDeniedMeta = %#v", meta)
	}

	setDeniedMeta(httptest.NewRecorder(), req, "ignored")
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
