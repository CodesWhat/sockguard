package imagefetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// errBlockedAddress is returned by the dial guard for a destination that
// resolves to a loopback, private, link-local, multicast or unspecified
// address and was not explicitly listed by the operator.
var errBlockedAddress = errors.New("registry address is not publicly routable and not listed in allowed_registries")

// dialGuard refuses connections to non-public addresses after DNS resolution.
// It sits at dial time, so it also covers token realms and blob redirects that
// a registry response points at, not only the host named in the image reference.
type dialGuard struct {
	// allowed holds operator-listed hosts, either "host" or "host:port",
	// lower-cased. A listed host is dialed without the address check.
	allowed map[string]struct{}
	// lookup and dial are seams for tests.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newDialGuard(allowedHosts []string) *dialGuard {
	g := &dialGuard{
		allowed: make(map[string]struct{}, len(allowedHosts)),
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	for _, h := range allowedHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			g.allowed[h] = struct{}{}
		}
	}
	return g
}

func (g *dialGuard) isAllowed(host, port string) bool {
	host = strings.ToLower(host)
	if _, ok := g.allowed[host]; ok {
		return true
	}
	_, ok := g.allowed[net.JoinHostPort(host, port)]
	return ok
}

var blockedRegistryRanges = [...]netip.Prefix{
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var registryNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// blockedAddr reports whether a is not a publicly routable unicast address.
func blockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if registryNAT64Prefix.Contains(a) {
		raw := a.As16()
		a = netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	}
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	// IANA marks these two anycast assignments globally reachable inside the
	// otherwise non-public 192.0.0.0/24 protocol-assignment block.
	if a == netip.AddrFrom4([4]byte{192, 0, 0, 9}) || a == netip.AddrFrom4([4]byte{192, 0, 0, 10}) {
		return false
	}
	for _, prefix := range blockedRegistryRanges {
		if prefix.Contains(a) {
			return true
		}
	}
	return false
}

// DialContext resolves addr, refuses it if any resolved address is blocked
// (unless the host is operator-listed), and dials the resolved IP directly so
// a second DNS answer cannot swap in a different address.
func (g *dialGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if g.isAllowed(host, port) {
		return g.dial(ctx, network, addr)
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = g.lookup(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	for _, ip := range ips {
		if blockedAddr(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s", errBlockedAddress, host, ip)
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := g.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func (g *dialGuard) transport() http.RoundTripper {
	base, ok := remote.DefaultTransport.(*http.Transport)
	if !ok {
		return remote.DefaultTransport
	}
	t := base.Clone()
	t.DialContext = g.DialContext
	t.Proxy = nil
	return t
}

// NewGuardedFetcher is NewFetcher with a dial-time address guard. Hosts in
// allowedHosts ("host" or "host:port", the allowed_registries spelling) may
// resolve to private addresses; every other destination, including token
// realms and blob redirects, must resolve to public addresses only. Environment
// proxies are disabled so the guard checks each actual destination.
func NewGuardedFetcher(allowedHosts []string) *Fetcher {
	f := NewFetcher()
	f.transport = newDialGuard(allowedHosts).transport()
	return f
}
