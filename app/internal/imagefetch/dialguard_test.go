package imagefetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialGuard(t *testing.T) {
	t.Parallel()
	resolve := map[string][]netip.Addr{
		"public.example":   {netip.MustParseAddr("93.184.216.34")},
		"internal.example": {netip.MustParseAddr("10.0.0.5")},
		"mixed.example":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("192.168.1.1")},
		"v6ula.example":    {netip.MustParseAddr("fd00::1")},
		"mapped.example":   {netip.MustParseAddr("::ffff:127.0.0.1")},
	}
	tests := []struct {
		name    string
		allowed []string
		addr    string
		blocked bool
	}{
		{"public name", nil, "public.example:443", false},
		{"private name", nil, "internal.example:443", true},
		{"mixed answers", nil, "mixed.example:443", true},
		{"ula", nil, "v6ula.example:443", true},
		{"mapped loopback", nil, "mapped.example:443", true},
		{"loopback literal", nil, "127.0.0.1:5000", true},
		{"rfc1918 literal", nil, "10.0.0.5:8080", true},
		{"link-local metadata", nil, "169.254.169.254:80", true},
		{"unspecified", nil, "0.0.0.0:80", true},
		{"public literal", nil, "93.184.216.34:443", false},
		{"shared metadata", nil, "100.100.100.200:80", true},
		{"shared lower boundary", nil, "100.64.0.0:443", true},
		{"shared upper boundary", nil, "100.127.255.255:443", true},
		{"before shared", nil, "100.63.255.255:443", false},
		{"after shared", nil, "100.128.0.0:443", false},
		{"benchmark", nil, "198.18.0.1:443", true},
		{"benchmark upper boundary", nil, "198.19.255.255:443", true},
		{"after benchmark", nil, "198.20.0.0:443", false},
		{"this network", nil, "0.1.2.3:443", true},
		{"protocol assignment", nil, "192.0.0.8:443", true},
		{"public PCP anycast", nil, "192.0.0.9:443", false},
		{"public TURN anycast", nil, "192.0.0.10:443", false},
		{"documentation one", nil, "192.0.2.1:443", true},
		{"documentation two", nil, "198.51.100.1:443", true},
		{"beside documentation", nil, "198.51.101.1:443", false},
		{"documentation three", nil, "203.0.113.1:443", true},
		{"reserved", nil, "240.0.0.1:443", true},
		{"broadcast", nil, "255.255.255.255:443", true},
		{"translated private", nil, "[64:ff9b::a00:1]:443", true},
		{"translated shared metadata", nil, "[64:ff9b::6464:64c8]:443", true},
		{"translated public", nil, "[64:ff9b::808:808]:443", false},
		{"zoned local NAT64", nil, "[64:ff9b:1::a00:1%eth0]:443", true},
		{"zoned translated private", nil, "[64:ff9b::a00:1%eth0]:443", true},
		{"zoned translated public", nil, "[64:ff9b::808:808%eth0]:443", false},
		{"listed zoned local NAT64", []string{"64:ff9b:1::a00:1%eth0"}, "[64:ff9b:1::a00:1%eth0]:443", false},
		{"local NAT64 lower boundary", nil, "[64:ff9b:1::]:443", true},
		{"local NAT64 private destination", nil, "[64:ff9b:1::a00:1]:443", true},
		{"local NAT64 upper boundary", nil, "[64:ff9b:1:ffff:ffff:ffff:ffff:ffff]:443", true},
		{"listed local NAT64 destination", []string{"64:ff9b:1::a00:1"}, "[64:ff9b:1::a00:1]:443", false},
		{"listed shared metadata", []string{"100.100.100.200"}, "100.100.100.200:80", false},
		{"listed host", []string{"internal.example"}, "internal.example:443", false},
		{"listed host:port", []string{"10.0.0.5:8080"}, "10.0.0.5:8080", false},
		{"listed host other port", []string{"10.0.0.5:8080"}, "10.0.0.5:9090", true},
		{"listing one host does not open another", []string{"internal.example"}, "10.0.0.5:443", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := newDialGuard(tt.allowed)
			g.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
				if ips, ok := resolve[host]; ok {
					return ips, nil
				}
				return nil, errors.New("nxdomain")
			}
			dialed := ""
			g.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
				dialed = addr
				c, _ := net.Pipe()
				return c, nil
			}
			conn, err := g.DialContext(context.Background(), "tcp", tt.addr)
			if conn != nil {
				_ = conn.Close()
			}
			if tt.blocked {
				if err == nil || dialed != "" {
					t.Fatalf("err=%v dialed=%q, want blocked before dialing", err, dialed)
				}
				return
			}
			if err != nil || dialed == "" {
				t.Fatalf("err=%v dialed=%q, want a dial", err, dialed)
			}
		})
	}
}

func TestDialGuardDialsResolvedIPNotName(t *testing.T) {
	t.Parallel()
	g := newDialGuard(nil)
	g.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	var dialed string
	g.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		c, _ := net.Pipe()
		return c, nil
	}
	conn, err := g.DialContext(context.Background(), "tcp", "public.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want the resolved IP", dialed)
	}
}

func TestNewGuardedFetcherUsesGuardTransport(t *testing.T) {
	t.Parallel()
	if NewGuardedFetcher([]string{"10.0.0.5:8080"}).transport == nil || NewFetcher().transport == nil {
		t.Fatal("fetcher has no transport")
	}
}

func TestDialGuardTransportBypassesEnvironmentProxy(t *testing.T) {
	t.Parallel()
	transport, ok := newDialGuard(nil).transport().(*http.Transport)
	if !ok {
		t.Fatal("guarded transport must retain HTTP transport")
	}
	if transport.Proxy != nil {
		t.Fatal("proxy can resolve registry redirects outside the dial guard")
	}
}

func TestDialGuardBlocksZonedNAT64Redirect(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://[64:ff9b:1::a00:1%25eth0]/private", http.StatusFound)
	}))
	defer server.Close()
	initial := server.Listener.Addr().String()
	guard := newDialGuard([]string{initial})
	var redirectedDials atomic.Int32
	guard.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != initial {
			redirectedDials.Add(1)
			return nil, errors.New("redirect reached the dialer")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport := guard.transport().(*http.Transport)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, errBlockedAddress) || redirectedDials.Load() != 0 {
		t.Fatalf("redirect err=%v, private dials=%d; want address refusal before dial", err, redirectedDials.Load())
	}
}
