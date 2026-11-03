package imagefetch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
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
