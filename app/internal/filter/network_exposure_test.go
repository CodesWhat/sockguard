package filter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

const (
	proxyNetworkID    = "aa11bb22cc33dd44ee55ff6600112233"
	backendNetworkID  = "bb22cc33dd44ee55ff66001122334455"
	exposureHostNetID = "cc33dd44ee55ff660011223344556677"
)

// exposureNetworks is a fake daemon: it resolves a reference by ID, ID prefix
// or name like the real one, and counts lookups.
type exposureNetworks struct {
	lookups []string
}

func (f *exposureNetworks) inspect(_ context.Context, ref string) (NetworkInspectResult, bool, error) {
	f.lookups = append(f.lookups, ref)
	switch ref {
	case "proxy", proxyNetworkID, proxyNetworkID[:8], "abc123":
		// "abc123" is an ID prefix of the proxy network. It is also a name an
		// operator could have listed, and must still resolve by what it is.
		if ref == "abc123" {
			return NetworkInspectResult{ID: "dd44ee55ff66", Name: "other", Driver: "bridge"}, true, nil
		}
		return NetworkInspectResult{ID: proxyNetworkID, Name: "proxy", Driver: "bridge"}, true, nil
	case "backend", backendNetworkID:
		return NetworkInspectResult{ID: backendNetworkID, Name: "backend", Driver: "bridge"}, true, nil
	case "bridge":
		return NetworkInspectResult{Name: "bridge", Driver: "bridge"}, true, nil
	case "podman":
		return NetworkInspectResult{Name: "podman", Driver: "bridge"}, true, nil
	case exposureHostNetID:
		return NetworkInspectResult{Name: "host", Driver: "host"}, true, nil
	case "missing":
		return NetworkInspectResult{}, false, nil
	case "boom":
		return NetworkInspectResult{}, false, errors.New("daemon down")
	}
	return NetworkInspectResult{}, false, nil
}

type exposureCase struct {
	name         string
	path         string
	body         string
	opts         NetworkExposureOptions
	allowHost    bool
	noInspector  bool
	wantStatus   int
	wantLookups  []string
	skipLookupCk bool
}

func runExposureCase(t *testing.T, tt exposureCase, mode string, apply func(*ResourceLimitGuardOptions, NetworkExposureOptions, bool)) (resourceGuardOutcome, *exposureNetworks) {
	t.Helper()
	fake := &exposureNetworks{}
	opts := ResourceLimitGuardOptions{}
	if !tt.noInspector {
		opts.InspectNetwork = fake.inspect
	}
	apply(&opts, tt.opts, tt.allowHost)
	return runResourceGuardRequest(t, opts, http.MethodPost, tt.path, tt.body, mode), fake
}

func applyDocker(o *ResourceLimitGuardOptions, e NetworkExposureOptions, allowHost bool) {
	o.ContainerCreate.NetworkExposure = e
	o.ContainerCreate.AllowHostNetwork = allowHost
}

func applyLibpod(o *ResourceLimitGuardOptions, e NetworkExposureOptions, allowHost bool) {
	o.LibpodContainerCreate.NetworkExposure = e
	o.LibpodContainerCreate.AllowHostNetwork = allowHost
}

func applyService(o *ResourceLimitGuardOptions, e NetworkExposureOptions, allowHost bool) {
	o.Service.NetworkExposure = e
	o.Service.AllowHostNetwork = allowHost
}

func checkExposureCases(t *testing.T, cases []exposureCase, apply func(*ResourceLimitGuardOptions, NetworkExposureOptions, bool)) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out, fake := runExposureCase(t, tt, "", apply)
			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			wantForwards := 0
			if tt.wantStatus == guardedRequestAllowedStatus {
				wantForwards = 1
				if out.forwardedBody != tt.body {
					t.Fatalf("forwarded body = %q, want it unchanged", out.forwardedBody)
				}
			}
			if out.forwarded != wantForwards {
				t.Fatalf("forwarded = %d, want %d", out.forwarded, wantForwards)
			}
			if !tt.skipLookupCk && !slices.Equal(fake.lookups, tt.wantLookups) {
				t.Fatalf("lookups = %v, want %v", fake.lookups, tt.wantLookups)
			}
		})
	}
}

const (
	ok   = guardedRequestAllowedStatus
	deny = http.StatusForbidden
	bad  = http.StatusBadGateway
)

func ports(opts ...string) NetworkExposureOptions {
	return NetworkExposureOptions{AllowedPortHostIPs: opts}
}

func nets(names ...string) NetworkExposureOptions {
	return NetworkExposureOptions{AllowedNetworks: names}
}

func TestNetworkExposureDockerCreatePorts(t *testing.T) {
	const p = "/containers/create"
	binding := func(hostIP string) string {
		return `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"` + hostIP + `","HostPort":"8080"}]}}}`
	}
	deny1 := NetworkExposureOptions{DenyPublishedPorts: true}
	loopback := ports("127.0.0.1", "::1")
	checkExposureCases(t, []exposureCase{
		{name: "deny: no ports passes", path: p, body: `{"Image":"x","HostConfig":{}}`, opts: deny1, wantStatus: ok},
		{name: "deny: exposed port alone is not published", path: p, body: `{"Config":{"ExposedPorts":{"80/tcp":{}}},"HostConfig":{}}`, opts: deny1, wantStatus: ok},
		{name: "deny: binding refused", path: p, body: binding("127.0.0.1"), opts: deny1, wantStatus: deny},
		{name: "deny: binding without host IP refused", path: p, body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"80"}]}}}`, opts: deny1, wantStatus: deny},
		{name: "deny: entry with an empty binding list is not published", path: p, body: `{"HostConfig":{"PortBindings":{"80/tcp":[]}}}`, opts: deny1, wantStatus: ok},
		{name: "deny: entry with null bindings is not published", path: p, body: `{"HostConfig":{"PortBindings":{"80/tcp":null}}}`, opts: deny1, wantStatus: ok},
		{name: "deny: second entry with a binding refused", path: p, body: `{"HostConfig":{"PortBindings":{"80/tcp":[],"443/tcp":[{"HostPort":"443"}]}}}`, opts: deny1, wantStatus: deny},
		{name: "deny: PublishAllPorts refused", path: p, body: `{"HostConfig":{"PublishAllPorts":true}}`, opts: deny1, wantStatus: deny},
		{name: "deny: PublishAllPorts false passes", path: p, body: `{"HostConfig":{"PublishAllPorts":false}}`, opts: deny1, wantStatus: ok},
		{name: "deny: key case is folded like the daemon does", path: p, body: `{"hostconfig":{"publishallports":true}}`, opts: deny1, wantStatus: deny},
		{name: "deny: versioned path", path: "/v1.45" + p, body: binding(""), opts: deny1, wantStatus: deny},
		{name: "off by default", path: p, body: binding(""), opts: NetworkExposureOptions{}, wantStatus: ok},

		{name: "host ips: loopback v4", path: p, body: binding("127.0.0.1"), opts: loopback, wantStatus: ok},
		{name: "host ips: loopback v6", path: p, body: binding("::1"), opts: loopback, wantStatus: ok},
		{name: "host ips: 4in6 mapped loopback", path: p, body: binding("::ffff:127.0.0.1"), opts: loopback, wantStatus: ok},
		{name: "host ips: empty means all interfaces", path: p, body: binding(""), opts: loopback, wantStatus: deny},
		{name: "host ips: 0.0.0.0", path: p, body: binding("0.0.0.0"), opts: loopback, wantStatus: deny},
		{name: "host ips: unspecified v6", path: p, body: binding("::"), opts: loopback, wantStatus: deny},
		{name: "host ips: another address", path: p, body: binding("127.0.0.2"), opts: loopback, wantStatus: deny},
		{name: "host ips: garbage", path: p, body: binding("localhost"), opts: loopback, wantStatus: deny},
		{name: "host ips: padded", path: p, body: binding(" 127.0.0.1"), opts: loopback, wantStatus: deny},
		{name: "host ips: one bad binding among good ones", path: p, body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1"}],"81/tcp":[{"HostIp":"10.0.0.1"}]}}}`, opts: loopback, wantStatus: deny},
		{name: "host ips: PublishAllPorts binds all interfaces", path: p, body: `{"HostConfig":{"PublishAllPorts":true}}`, opts: loopback, wantStatus: deny},
		{name: "host ips: no ports needs no list", path: p, body: `{"HostConfig":{}}`, opts: loopback, wantStatus: ok},
		{name: "host ips: 0.0.0.0 listed admits an empty host IP", path: p, body: binding(""), opts: ports("0.0.0.0"), wantStatus: ok},
		{name: "host ips: 0.0.0.0 listed admits PublishAllPorts", path: p, body: `{"HostConfig":{"PublishAllPorts":true}}`, opts: ports("0.0.0.0"), wantStatus: ok},
		{name: "host ips: mapped entry in the list matches the plain request", path: p, body: binding("127.0.0.1"), opts: ports("::ffff:127.0.0.1"), wantStatus: ok},
		{name: "host ips: deny wins over the list", path: p, body: binding("127.0.0.1"), opts: NetworkExposureOptions{DenyPublishedPorts: true, AllowedPortHostIPs: []string{"127.0.0.1"}}, wantStatus: deny},
	}, applyDocker)
}

func TestNetworkExposureDockerCreateNetworks(t *testing.T) {
	const p = "/containers/create"
	mode := func(m string) string { return `{"HostConfig":{"NetworkMode":"` + m + `"}}` }
	endpoints := func(m string, keys ...string) string {
		var sb strings.Builder
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"` + k + `":{}`)
		}
		return `{"HostConfig":{"NetworkMode":"` + m + `"},"NetworkingConfig":{"EndpointsConfig":{` + sb.String() + `}}}`
	}
	only := nets("proxy")
	checkExposureCases(t, []exposureCase{
		{name: "by name", path: p, body: mode("proxy"), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "by full ID", path: p, body: mode(proxyNetworkID), opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID}},
		{name: "by ID prefix", path: p, body: mode(proxyNetworkID[:8]), opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID[:8]}},
		{name: "unlisted network by ID", path: p, body: mode(backendNetworkID), opts: only, wantStatus: deny, wantLookups: []string{backendNetworkID}},
		{name: "unlisted network by name", path: p, body: mode("backend"), opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "a listed string that resolves to another network is refused", path: p, body: mode("abc123"), opts: nets("abc123"), wantStatus: deny, wantLookups: []string{"abc123"}},
		{name: "empty mode is the default bridge", path: p, body: `{"HostConfig":{}}`, opts: only, wantStatus: deny, wantLookups: []string{"bridge"}},
		{name: "default mode is the default bridge", path: p, body: mode("default"), opts: only, wantStatus: deny, wantLookups: []string{"bridge"}},
		{name: "default bridge listed", path: p, body: mode("default"), opts: nets("bridge"), wantStatus: ok, wantLookups: []string{"bridge"}},
		{name: "no HostConfig at all is the default bridge", path: p, body: `{"Image":"x"}`, opts: only, wantStatus: deny, wantLookups: []string{"bridge"}},
		{name: "none joins nothing and needs no lookup", path: p, body: mode("none"), opts: only, noInspector: true, wantStatus: ok},
		{name: "endpoint key by name", path: p, body: endpoints("proxy", "proxy"), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "endpoint key by ID", path: p, body: endpoints("proxy", proxyNetworkID), opts: only, wantStatus: ok, wantLookups: []string{"proxy", proxyNetworkID}},
		{name: "second endpoint key unlisted", path: p, body: endpoints("proxy", "backend", "proxy"), opts: only, wantStatus: deny, wantLookups: []string{"proxy", "backend"}},
		{name: "endpoint key alone, default mode, also needs the default bridge", path: p, body: endpoints("", "proxy"), opts: only, wantStatus: deny, wantLookups: []string{"bridge"}},
		{name: "container: mode refused without a lookup", path: p, body: mode("container:abc"), opts: only, wantStatus: deny, wantLookups: nil},
		{name: "Container: mode refused case-insensitively", path: p, body: mode("Container:abc"), opts: only, wantStatus: deny, wantLookups: nil},
		{name: "ns: mode refused", path: p, body: mode("ns:/var/run/netns/x"), opts: only, wantStatus: deny, wantLookups: nil},
		{name: "pasta refused", path: p, body: mode("pasta"), opts: only, wantStatus: deny, wantLookups: nil},
		{name: "slirp4netns refused", path: p, body: mode("slirp4netns"), opts: only, wantStatus: deny, wantLookups: nil},
		{name: "host refused while allow_host_network is off", path: p, body: mode("host"), opts: nets("host"), wantStatus: deny, wantLookups: nil},
		{name: "host stays with allow_host_network when it is on", path: p, body: mode("host"), opts: only, allowHost: true, wantStatus: ok, wantLookups: nil},
		{name: "host network named by ID refused while allow_host_network is off", path: p, body: mode(exposureHostNetID), opts: only, wantStatus: deny, wantLookups: []string{exposureHostNetID}},
		{name: "host network named by ID with the host gate on", path: p, body: mode(exposureHostNetID), opts: only, allowHost: true, wantStatus: ok, wantLookups: []string{exposureHostNetID}},
		{name: "unknown network is refused", path: p, body: mode("missing"), opts: only, wantStatus: deny, wantLookups: []string{"missing"}},
		{name: "lookup failure fails closed", path: p, body: mode("boom"), opts: only, wantStatus: bad, wantLookups: []string{"boom"}},
		{name: "no inspector fails closed", path: p, body: mode("proxy"), opts: only, noInspector: true, wantStatus: bad},
		{name: "off by default needs no lookup", path: p, body: mode("anything"), opts: NetworkExposureOptions{}, noInspector: true, wantStatus: ok},
		{name: "a repeated network is looked up once", path: p, body: endpoints("proxy", "proxy"), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "ports and networks both checked", path: p, body: `{"HostConfig":{"NetworkMode":"proxy","PublishAllPorts":true}}`, opts: NetworkExposureOptions{DenyPublishedPorts: true, AllowedNetworks: []string{"proxy"}}, wantStatus: deny, wantLookups: nil},
	}, applyDocker)
}

func TestNetworkExposureLibpodCreate(t *testing.T) {
	const p = "/libpod/containers/create"
	only := nets("proxy")
	mapping := func(hostIP string) string {
		return `{"portmappings":[{"host_ip":"` + hostIP + `","container_port":80,"host_port":8080,"protocol":"tcp"}]}`
	}
	checkExposureCases(t, []exposureCase{
		{name: "deny: no ports", path: p, body: `{"image":"x"}`, opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: ok},
		{name: "deny: empty portmappings", path: p, body: `{"portmappings":[]}`, opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: ok},
		{name: "deny: portmapping", path: p, body: mapping("127.0.0.1"), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "deny: publish_image_ports", path: p, body: `{"publish_image_ports":true}`, opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "deny: publish_image_ports false", path: p, body: `{"publish_image_ports":false}`, opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: ok},
		{name: "deny: versioned path", path: "/v6.1.3" + p, body: mapping(""), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "host ips: loopback", path: p, body: mapping("127.0.0.1"), opts: ports("127.0.0.1"), wantStatus: ok},
		{name: "host ips: mapped loopback", path: p, body: mapping("::ffff:127.0.0.1"), opts: ports("127.0.0.1"), wantStatus: ok},
		{name: "host ips: ::1", path: p, body: mapping("::1"), opts: ports("::1"), wantStatus: ok},
		{name: "host ips: empty", path: p, body: mapping(""), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: 0.0.0.0", path: p, body: mapping("0.0.0.0"), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: garbage", path: p, body: mapping("nope"), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: publish_image_ports binds all interfaces", path: p, body: `{"publish_image_ports":true}`, opts: ports("127.0.0.1"), wantStatus: deny},

		{name: "net: bridge with a listed network", path: p, body: `{"netns":{"nsmode":"bridge"},"networks":{"proxy":{}}}`, opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "net: by ID", path: p, body: `{"networks":{"` + proxyNetworkID + `":{}}}`, opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID}},
		{name: "net: by ID prefix", path: p, body: `{"networks":{"` + proxyNetworkID[:8] + `":{}}}`, opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID[:8]}},
		{name: "net: unlisted", path: p, body: `{"networks":{"proxy":{},"backend":{}}}`, opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "net: ID of unlisted network", path: p, body: `{"networks":{"` + backendNetworkID + `":{}}}`, opts: only, wantStatus: deny, wantLookups: []string{backendNetworkID}},
		{name: "net: listed string resolving elsewhere", path: p, body: `{"networks":{"abc123":{}}}`, opts: nets("abc123"), wantStatus: deny, wantLookups: []string{"abc123"}},
		{name: "net: cni_networks", path: p, body: `{"cni_networks":["backend"]}`, opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "net: no networks is the default network", path: p, body: `{"image":"x"}`, opts: only, wantStatus: deny, wantLookups: []string{"podman"}},
		{name: "net: default network listed", path: p, body: `{"image":"x"}`, opts: nets("podman"), wantStatus: ok, wantLookups: []string{"podman"}},
		{name: "net: none", path: p, body: `{"netns":{"nsmode":"none"}}`, opts: only, noInspector: true, wantStatus: ok},
		{name: "net: container ns refused", path: p, body: `{"netns":{"nsmode":"container","value":"abc"}}`, opts: only, wantStatus: deny},
		{name: "net: path ns refused", path: p, body: `{"netns":{"nsmode":"path","value":"/run/netns/x"}}`, opts: only, wantStatus: deny},
		{name: "net: pasta refused", path: p, body: `{"netns":{"nsmode":"pasta"}}`, opts: only, wantStatus: deny},
		{name: "net: slirp4netns refused", path: p, body: `{"netns":{"nsmode":"slirp4netns"}}`, opts: only, wantStatus: deny},
		{name: "net: joining a pod refused", path: p, body: `{"pod":"p1","networks":{"proxy":{}}}`, opts: only, wantStatus: deny},
		{name: "net: host refused while the host gate is off", path: p, body: `{"netns":{"nsmode":"host"}}`, opts: only, wantStatus: deny},
		{name: "net: host with the host gate on", path: p, body: `{"netns":{"nsmode":"host"}}`, opts: only, allowHost: true, wantStatus: ok},
		{name: "net: unknown network", path: p, body: `{"networks":{"missing":{}}}`, opts: only, wantStatus: deny, wantLookups: []string{"missing"}},
		{name: "net: lookup failure", path: p, body: `{"networks":{"boom":{}}}`, opts: only, wantStatus: bad, wantLookups: []string{"boom"}},
		{name: "net: no inspector", path: p, body: `{"networks":{"proxy":{}}}`, opts: only, noInspector: true, wantStatus: bad},
		{name: "net: the Docker create list does not apply", path: p, body: `{"networks":{"backend":{}}}`, opts: NetworkExposureOptions{}, wantStatus: ok},
	}, applyLibpod)
}

func TestNetworkExposureServiceCreateAndUpdate(t *testing.T) {
	const create = "/services/create"
	only := nets("proxy")
	spec := func(network, endpoint string) string {
		body := `{"TaskTemplate":{"ContainerSpec":{"Image":"x"}`
		if network != "" {
			body += `,"Networks":[{"Target":"` + network + `"}]`
		}
		body += `}`
		if endpoint != "" {
			body += `,"EndpointSpec":` + endpoint
		}
		return body + `}`
	}
	ingress := `{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":80}]}`
	hostMode := `{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":80,"PublishMode":"host"}]}`
	cases := []exposureCase{
		{name: "deny: no ports", path: create, body: spec("", `{"Mode":"vip"}`), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: ok},
		{name: "deny: ingress port", path: create, body: spec("", ingress), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "deny: host mode port", path: create, body: spec("", hostMode), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "deny: update body", path: "/services/s1/update?version=3", body: spec("", ingress), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "host ips: ports refused unless 0.0.0.0 is listed", path: create, body: spec("", ingress), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: host mode port refused too", path: create, body: spec("", hostMode), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: 0.0.0.0 listed", path: create, body: spec("", ingress), opts: ports("0.0.0.0"), wantStatus: ok},
		{name: "host ips: no ports passes", path: create, body: spec("", ""), opts: ports("127.0.0.1"), wantStatus: ok},

		{name: "net: by name", path: create, body: spec("proxy", ""), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "net: by ID", path: create, body: spec(proxyNetworkID, ""), opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID}},
		{name: "net: by ID prefix", path: create, body: spec(proxyNetworkID[:8], ""), opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID[:8]}},
		{name: "net: unlisted", path: create, body: spec("backend", ""), opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "net: listed string resolving elsewhere", path: create, body: spec("abc123", ""), opts: nets("abc123"), wantStatus: deny, wantLookups: []string{"abc123"}},
		{name: "net: top-level Networks", path: create, body: `{"Networks":[{"Target":"backend"}]}`, opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "net: no networks passes", path: create, body: spec("", ""), opts: only, noInspector: true, wantStatus: ok},
		{name: "net: literal host refused", path: create, body: spec("host", ""), opts: only, wantStatus: deny},
		{name: "net: host ID refused", path: create, body: spec(exposureHostNetID, ""), opts: only, wantStatus: deny, skipLookupCk: true},
		{name: "net: host ID with the host gate on is the host gate's call", path: create, body: spec(exposureHostNetID, ""), opts: only, allowHost: true, wantStatus: ok, skipLookupCk: true},
		{name: "net: unknown", path: create, body: spec("missing", ""), opts: only, wantStatus: deny, wantLookups: []string{"missing"}},
		{name: "net: lookup failure", path: create, body: spec("boom", ""), opts: only, wantStatus: bad, skipLookupCk: true},
		{name: "net: no inspector", path: create, body: spec("proxy", ""), opts: only, noInspector: true, wantStatus: bad},
		{name: "net: update body", path: "/services/s1/update?version=3", body: spec("backend", ""), opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
	}
	// The host-network guard that runs ahead of this one resolves the same
	// targets while allow_host_network is off, so each shows up twice.
	for i := range cases {
		if cases[i].wantLookups != nil {
			cases[i].wantLookups = slices.Concat(cases[i].wantLookups, cases[i].wantLookups)
		}
	}
	checkExposureCases(t, cases, applyService)
}

func TestNetworkExposureServiceRollbackPaths(t *testing.T) {
	only := NetworkExposureOptions{AllowedNetworks: []string{"proxy"}, DenyPublishedPorts: true}
	type svc = ServiceInspectResult
	tests := []struct {
		name       string
		path       string
		body       string
		current    *svc
		inspectErr bool
		wantStatus int
	}{
		{name: "manual rollback to a disallowed network", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"backend"}}, wantStatus: deny},
		{name: "manual rollback to a disallowed network named by ID", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{backendNetworkID}}, wantStatus: deny},
		{name: "manual rollback to published ports", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true, PreviousSpecPublishedPorts: 1}, wantStatus: deny},
		{name: "manual rollback to a compliant previous spec", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"proxy"}}, wantStatus: ok},
		{name: "manual rollback ignores a disallowed body", path: "/services/s1/update?version=3&rollback=previous", body: `{"TaskTemplate":{"Networks":[{"Target":"backend"}]}}`, current: &svc{Version: 3, HasPreviousSpec: true, PreviousSpecNetworkTargets: []string{"proxy"}}, wantStatus: ok},
		{name: "manual rollback with no previous spec", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, current: &svc{Version: 3}, wantStatus: ok},
		{name: "manual rollback stale version", path: "/services/s1/update?version=2&rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true}, wantStatus: http.StatusConflict},
		{name: "manual rollback needs a version", path: "/services/s1/update?rollback=previous", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true}, wantStatus: http.StatusBadRequest},
		{name: "manual rollback needs one rollback value", path: "/services/s1/update?version=3&rollback=previous&rollback=x", body: `{}`, current: &svc{Version: 3, HasPreviousSpec: true}, wantStatus: http.StatusBadRequest},
		{name: "manual rollback inspect failure", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, inspectErr: true, wantStatus: bad},
		{name: "manual rollback without an inspector", path: "/services/s1/update?version=3&rollback=previous", body: `{}`, wantStatus: bad},
		{name: "automatic rollback to a disallowed current spec network", path: "/services/s1/update?version=3", body: `{"UpdateConfig":{"FailureAction":"rollback"},"TaskTemplate":{"Networks":[{"Target":"proxy"}]}}`, current: &svc{Version: 3, SpecNetworkTargets: []string{"backend"}}, wantStatus: deny},
		{name: "automatic rollback to published ports", path: "/services/s1/update?version=3", body: `{"UpdateConfig":{"FailureAction":"rollback"}}`, current: &svc{Version: 3, SpecPublishedPorts: 2}, wantStatus: deny},
		{name: "automatic rollback to a compliant current spec", path: "/services/s1/update?version=3", body: `{"UpdateConfig":{"FailureAction":"rollback"},"TaskTemplate":{"Networks":[{"Target":"proxy"}]}}`, current: &svc{Version: 3, SpecNetworkTargets: []string{"proxy"}}, wantStatus: ok},
		{name: "automatic rollback stale version", path: "/services/s1/update?version=2", body: `{"UpdateConfig":{"FailureAction":"rollback"}}`, current: &svc{Version: 3}, wantStatus: http.StatusConflict},
		{name: "automatic rollback needs a version", path: "/services/s1/update", body: `{"UpdateConfig":{"FailureAction":"rollback"}}`, current: &svc{Version: 3}, wantStatus: http.StatusBadRequest},
		{name: "pause never inspects the current spec", path: "/services/s1/update?version=3", body: `{"UpdateConfig":{"FailureAction":"pause"}}`, current: &svc{Version: 3, SpecNetworkTargets: []string{"backend"}}, wantStatus: ok},
		{name: "create never inspects a stored spec", path: "/services/create", body: `{"UpdateConfig":{"FailureAction":"rollback"}}`, wantStatus: ok},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &exposureNetworks{}
			opts := ResourceLimitGuardOptions{InspectNetwork: fake.inspect}
			opts.Service.NetworkExposure = only
			switch {
			case tt.current != nil:
				result := *tt.current
				opts.InspectService = func(context.Context, string) (ServiceInspectResult, bool, error) { return result, true, nil }
			case tt.inspectErr:
				opts.InspectService = func(context.Context, string) (ServiceInspectResult, bool, error) {
					return ServiceInspectResult{}, false, errors.New("daemon down")
				}
			}
			out := runResourceGuardRequest(t, opts, http.MethodPost, tt.path, tt.body, "")
			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
		})
	}
}

func TestNetworkExposureNetworkConnect(t *testing.T) {
	only := nets("proxy")
	const body = `{"Container":"c1"}`
	tests := exposureConnectCases(only)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &exposureNetworks{}
			opts := ResourceLimitGuardOptions{}
			if !tt.noInspector {
				opts.InspectNetwork = fake.inspect
			}
			opts.ContainerCreate.NetworkExposure = tt.docker
			opts.ContainerCreate.AllowHostNetwork = tt.allowHost
			opts.LibpodContainerCreate.NetworkExposure = tt.libpod
			out := runResourceGuardRequest(t, opts, http.MethodPost, tt.path, body, "")
			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if !tt.skipLookupCk && !slices.Equal(fake.lookups, tt.wantLookups) {
				t.Fatalf("lookups = %v, want %v", fake.lookups, tt.wantLookups)
			}
		})
	}
}

type connectCase struct {
	name         string
	path         string
	docker       NetworkExposureOptions
	libpod       NetworkExposureOptions
	allowHost    bool
	noInspector  bool
	wantStatus   int
	wantLookups  []string
	skipLookupCk bool
}

func exposureConnectCases(only NetworkExposureOptions) []connectCase {
	return []connectCase{
		{name: "docker connect to a listed network", path: "/networks/proxy/connect", docker: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "docker connect by ID", path: "/networks/" + proxyNetworkID + "/connect", docker: only, wantStatus: ok, wantLookups: []string{proxyNetworkID}},
		{name: "docker connect by ID prefix", path: "/v1.45/networks/" + proxyNetworkID[:8] + "/connect", docker: only, wantStatus: ok, wantLookups: []string{proxyNetworkID[:8]}},
		{name: "docker connect to an unlisted network", path: "/networks/backend/connect", docker: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "docker connect to an unlisted network by ID", path: "/networks/" + backendNetworkID + "/connect", docker: only, wantStatus: deny, wantLookups: []string{backendNetworkID}},
		{name: "docker connect, listed string resolving elsewhere", path: "/networks/abc123/connect", docker: nets("abc123"), wantStatus: deny, wantLookups: []string{"abc123"}},
		{name: "docker connect to the host network by ID", path: "/networks/" + exposureHostNetID + "/connect", docker: only, wantStatus: deny, wantLookups: []string{exposureHostNetID}},
		{name: "docker connect, unknown network", path: "/networks/missing/connect", docker: only, wantStatus: deny, wantLookups: []string{"missing"}},
		{name: "docker connect, lookup failure", path: "/networks/boom/connect", docker: only, wantStatus: bad, wantLookups: []string{"boom"}},
		{name: "docker connect, no inspector", path: "/networks/proxy/connect", docker: only, noInspector: true, wantStatus: bad},
		{name: "docker connect, list off", path: "/networks/backend/connect", wantStatus: ok, wantLookups: nil},
		{name: "docker connect uses the Docker list, not the libpod one", path: "/networks/backend/connect", libpod: only, wantStatus: ok, wantLookups: nil},
		{name: "docker connect with a slash in the name", path: "/networks/a/b/connect", docker: only, wantStatus: deny, wantLookups: []string{"a/b"}},
		{name: "libpod connect to a listed network", path: "/libpod/networks/proxy/connect", libpod: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "libpod connect to an unlisted network", path: "/v6.1.3/libpod/networks/backend/connect", libpod: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "libpod connect uses the libpod list, not the Docker one", path: "/libpod/networks/backend/connect", docker: only, wantStatus: ok, wantLookups: nil},
		{name: "disconnect is untouched", path: "/networks/backend/disconnect", docker: only, wantStatus: ok, wantLookups: nil},
	}
}

func TestNetworkExposureWarnAndAuditModes(t *testing.T) {
	deny1 := NetworkExposureOptions{DenyPublishedPorts: true, AllowedNetworks: []string{"proxy"}}
	tests := []struct {
		name       string
		apply      func(*ResourceLimitGuardOptions, NetworkExposureOptions, bool)
		path       string
		body       string
		wantStatus int
		wantReason string
	}{
		{name: "docker port", apply: applyDocker, path: "/containers/create", body: `{"HostConfig":{"NetworkMode":"proxy","PublishAllPorts":true}}`, wantStatus: ok, wantReason: "published ports"},
		{name: "docker network", apply: applyDocker, path: "/containers/create", body: `{"HostConfig":{"NetworkMode":"backend"}}`, wantStatus: ok, wantReason: "not in allowed_networks"},
		{name: "docker lookup failure still fails closed", apply: applyDocker, path: "/containers/create", body: `{"HostConfig":{"NetworkMode":"boom"}}`, wantStatus: bad},
		{name: "docker unknown network is a would-deny", apply: applyDocker, path: "/containers/create", body: `{"HostConfig":{"NetworkMode":"missing"}}`, wantStatus: ok, wantReason: "does not exist"},
		{name: "libpod port", apply: applyLibpod, path: "/libpod/containers/create", body: `{"portmappings":[{"container_port":80}],"networks":{"proxy":{}}}`, wantStatus: ok, wantReason: "published ports"},
		{name: "libpod mode", apply: applyLibpod, path: "/libpod/containers/create", body: `{"netns":{"nsmode":"pasta"}}`, wantStatus: ok, wantReason: "can't verify"},
		{name: "service port", apply: applyService, path: "/services/create", body: `{"EndpointSpec":{"Ports":[{"TargetPort":80}]}}`, wantStatus: ok, wantReason: "published ports"},
		{name: "service network", apply: applyService, path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"backend"}]}}`, wantStatus: ok, wantReason: "not in allowed_networks"},
		{name: "service lookup failure still fails closed", apply: applyService, path: "/services/create", body: `{"TaskTemplate":{"Networks":[{"Target":"boom"}]}}`, wantStatus: bad},
		{name: "connect", apply: func(o *ResourceLimitGuardOptions, e NetworkExposureOptions, h bool) { applyDocker(o, e, h) }, path: "/networks/backend/connect", body: `{"Container":"c"}`, wantStatus: ok, wantReason: "not in allowed_networks"},
	}
	for _, mode := range []string{"warn", "audit"} {
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				fake := &exposureNetworks{}
				opts := ResourceLimitGuardOptions{InspectNetwork: fake.inspect}
				tt.apply(&opts, deny1, false)
				out := runResourceGuardRequest(t, opts, http.MethodPost, tt.path, tt.body, mode)
				if out.status != tt.wantStatus {
					t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
				}
				if tt.wantStatus != ok {
					return
				}
				if out.forwarded != 1 || out.forwardedBody != tt.body {
					t.Fatalf("forwarded = %d body %q, want one untouched pass-through", out.forwarded, out.forwardedBody)
				}
				if out.meta.Decision != logging.DecisionWouldDeny || out.meta.ReasonCode != reasonCodeRequestBodyPolicyDenied {
					t.Fatalf("decision/reason code = %q/%q, want would_deny/%q", out.meta.Decision, out.meta.ReasonCode, reasonCodeRequestBodyPolicyDenied)
				}
				if !strings.Contains(out.meta.Reason, tt.wantReason) {
					t.Fatalf("reason = %q, want it to contain %q", out.meta.Reason, tt.wantReason)
				}
			})
		}
	}
}

func TestNetworkExposureEnforceRecordsDenial(t *testing.T) {
	opts := ResourceLimitGuardOptions{}
	applyDocker(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
	out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/create", `{"HostConfig":{"PublishAllPorts":true}}`, "")
	if out.status != http.StatusForbidden || out.meta.Decision != logging.DecisionDeny || out.meta.ReasonCode != reasonCodeRequestBodyPolicyDenied {
		t.Fatalf("status/decision/reason code = %d/%q/%q", out.status, out.meta.Decision, out.meta.ReasonCode)
	}
	if !strings.Contains(out.body, "published ports are not allowed") {
		t.Fatalf("body = %s", out.body)
	}
}

func TestNetworkExposureUnreadableAndOversizedBodies(t *testing.T) {
	opts := ResourceLimitGuardOptions{}
	applyDocker(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
	// Undecodable bodies get no verdict from this guard: the inspectors and the
	// daemon refuse them.
	if out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/create", `{`, ""); out.status != ok {
		t.Fatalf("undecodable body status = %d, want it forwarded", out.status)
	}
	big := `{"HostConfig":{"PublishAllPorts":true},"Pad":"` + strings.Repeat("a", maxContainerCreateBodyBytes) + `"}`
	if out := runResourceGuardRequest(t, opts, http.MethodPost, "/containers/create", big, ""); out.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", out.status)
	}
	svc := ResourceLimitGuardOptions{}
	applyService(&svc, NetworkExposureOptions{DenyPublishedPorts: true}, false)
	bigSvc := `{"Pad":"` + strings.Repeat("a", maxServiceBodyBytes) + `"}`
	if out := runResourceGuardRequest(t, svc, http.MethodPost, "/services/create", bigSvc, ""); out.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized service body status = %d, want 413", out.status)
	}
}

func TestNormalizeHostIP(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "0.0.0.0", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"::ffff:127.0.0.1", "127.0.0.1", true},
		{"::1", "::1", true},
		{"fe80::1%eth0", "", false},
		{"[::1]", "", false},
		{"127.0.0.1:80", "", false},
		{" 127.0.0.1", "", false},
		{"localhost", "", false},
		{"256.0.0.1", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeHostIP(tt.in)
		if ok != tt.ok || (ok && got.String() != tt.want) {
			t.Errorf("normalizeHostIP(%q) = %v, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNetworkConnectTarget(t *testing.T) {
	tests := []struct {
		path       string
		target     string
		libpod, ok bool
	}{
		{"/networks/proxy/connect", "proxy", false, true},
		{"/networks/a/b/connect", "a/b", false, true},
		{"/libpod/networks/proxy/connect", "proxy", true, true},
		{"/libpod/networks/a/b/connect", "", false, false},
		{"/networks/proxy/disconnect", "", false, false},
		{"/containers/create", "", false, false},
	}
	for _, tt := range tests {
		target, libpod, ok := networkConnectTarget(tt.path)
		if target != tt.target || libpod != tt.libpod || ok != tt.ok {
			t.Errorf("networkConnectTarget(%q) = %q, %v, %v; want %q, %v, %v", tt.path, target, libpod, ok, tt.target, tt.libpod, tt.ok)
		}
	}
}

// FuzzNetworkExposure builds a Docker create body from fuzzed pieces, so it is
// always valid JSON, and checks the port and host IP gates against net.ParseIP
// as an independent oracle: a published port is always denied under
// deny_published_ports, and under allowed_port_host_ips it is admitted exactly
// when its host IP is the one listed.
func FuzzNetworkExposure(f *testing.F) {
	f.Add("127.0.0.1", "8080", false)
	f.Add("", "80", false)
	f.Add("::ffff:127.0.0.1", "", false)
	f.Add("0.0.0.0", "80", true)
	f.Add("127.0.0.1%eth0", "80", false)
	f.Add(" 127.0.0.1", "80", false)
	f.Add("127.1", "80", false)
	f.Add("::1", "80", true)

	f.Fuzz(func(t *testing.T, hostIP, hostPort string, publishAll bool) {
		hostConfig := map[string]any{
			"PublishAllPorts": publishAll,
			"PortBindings": map[string]any{
				"80/tcp": []map[string]string{{"HostIp": hostIP, "HostPort": hostPort}},
			},
		}
		raw, err := json.Marshal(map[string]any{"HostConfig": hostConfig})
		if err != nil {
			t.Skip()
		}
		body := string(raw)

		run := func(e NetworkExposureOptions) resourceGuardOutcome {
			opts := ResourceLimitGuardOptions{}
			applyDocker(&opts, e, false)
			return runResourceGuardRequest(t, opts, http.MethodPost, "/containers/create", body, "")
		}

		if out := run(NetworkExposureOptions{DenyPublishedPorts: true}); out.status != http.StatusForbidden || out.forwarded != 0 {
			t.Fatalf("deny_published_ports forwarded a published port: status %d body %q", out.status, body)
		}

		// A host IP is allowed when it parses as 127.0.0.1. PublishAllPorts adds
		// an all-interfaces binding, which is never 127.0.0.1.
		ip := net.ParseIP(hostIP)
		want := !publishAll && ip != nil && ip.Equal(net.IPv4(127, 0, 0, 1))
		out := run(NetworkExposureOptions{AllowedPortHostIPs: []string{"127.0.0.1"}})
		if got := out.status == guardedRequestAllowedStatus; got != want {
			t.Fatalf("host IP %q publishAll=%v admitted=%v, want %v", hostIP, publishAll, got, want)
		}
		if out.status != guardedRequestAllowedStatus && (out.status != http.StatusForbidden || out.forwarded != 0) {
			t.Fatalf("refusal status %d forwarded %d", out.status, out.forwarded)
		}
	})
}

func TestNetworkExposurePodCreate(t *testing.T) {
	const p = "/libpod/pods/create"
	only := nets("proxy")
	mapping := func(hostIP string) string {
		return `{"name":"p1","portmappings":[{"host_ip":"` + hostIP + `","container_port":80,"host_port":8080}]}`
	}
	checkExposureCases(t, []exposureCase{
		{name: "deny: no ports", path: p, body: `{"name":"p1"}`, opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: ok},
		{name: "deny: portmapping", path: p, body: mapping("127.0.0.1"), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "deny: versioned path", path: "/v6.1.3" + p, body: mapping(""), opts: NetworkExposureOptions{DenyPublishedPorts: true}, wantStatus: deny},
		{name: "host ips: loopback", path: p, body: mapping("127.0.0.1"), opts: ports("127.0.0.1"), wantStatus: ok},
		{name: "host ips: mapped loopback", path: p, body: mapping("::ffff:127.0.0.1"), opts: ports("127.0.0.1"), wantStatus: ok},
		{name: "host ips: empty", path: p, body: mapping(""), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "host ips: garbage", path: p, body: mapping("nope"), opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "net: listed", path: p, body: `{"networks":{"proxy":{}}}`, opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "net: by ID prefix", path: p, body: `{"networks":{"` + proxyNetworkID[:8] + `":{}}}`, opts: only, wantStatus: ok, wantLookups: []string{proxyNetworkID[:8]}},
		{name: "net: unlisted", path: p, body: `{"networks":{"backend":{}}}`, opts: only, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "net: no networks is the default network", path: p, body: `{"name":"p1"}`, opts: only, wantStatus: deny, wantLookups: []string{"podman"}},
		{name: "net: none", path: p, body: `{"netns":{"nsmode":"none"}}`, opts: only, noInspector: true, wantStatus: ok},
		{name: "net: pasta refused", path: p, body: `{"netns":{"nsmode":"pasta"}}`, opts: only, wantStatus: deny},
		{name: "net: path ns refused", path: p, body: `{"netns":{"nsmode":"path","value":"/run/netns/x"}}`, opts: only, wantStatus: deny},
		{name: "net: host refused while the pod host gate is off", path: p, body: `{"netns":{"nsmode":"host"}}`, opts: only, wantStatus: deny},
		{name: "net: lookup failure", path: p, body: `{"networks":{"boom":{}}}`, opts: only, wantStatus: bad, wantLookups: []string{"boom"}},
		{name: "off by default", path: p, body: mapping(""), opts: NetworkExposureOptions{}, wantStatus: ok},
	}, applyLibpod)

	// The pod's own allow_host_network answers for host.
	opts := ResourceLimitGuardOptions{}
	applyLibpod(&opts, only, false)
	opts.LibpodPodCreate.AllowHostNetwork = true
	if out := runResourceGuardRequest(t, opts, http.MethodPost, p, `{"netns":{"nsmode":"host"}}`, ""); out.status != ok {
		t.Fatalf("host with the pod host gate on: status %d, want it forwarded", out.status)
	}
	// Only the libpod container list applies; the Docker one doesn't.
	dockerOnly := ResourceLimitGuardOptions{}
	applyDocker(&dockerOnly, NetworkExposureOptions{DenyPublishedPorts: true}, false)
	if out := runResourceGuardRequest(t, dockerOnly, http.MethodPost, p, mapping("127.0.0.1"), ""); out.status != ok {
		t.Fatalf("docker-only gates refused a pod create: status %d", out.status)
	}
}

func TestNetworkExposurePlayKube(t *testing.T) {
	const yaml = "apiVersion: v1\nkind: Pod\n"
	for _, path := range []string{"/libpod/play/kube", "/v6.1.3/libpod/kube/play", "/libpod/play/kube?start=true"} {
		for name, e := range map[string]NetworkExposureOptions{
			"deny_published_ports":  {DenyPublishedPorts: true},
			"allowed_port_host_ips": ports("127.0.0.1"),
			"allowed_networks":      nets("proxy"),
		} {
			t.Run(path+"/"+name, func(t *testing.T) {
				opts := ResourceLimitGuardOptions{}
				applyLibpod(&opts, e, false)
				out := runResourceGuardRequest(t, opts, http.MethodPost, path, yaml, "")
				if out.status != deny || out.forwarded != 0 || !strings.Contains(out.body, "play kube denied") {
					t.Fatalf("status %d forwarded %d body %s", out.status, out.forwarded, out.body)
				}
			})
		}
		t.Run(path+"/gates off", func(t *testing.T) {
			if out := runResourceGuardRequest(t, ResourceLimitGuardOptions{}, http.MethodPost, path, yaml, ""); out.status != ok {
				t.Fatalf("status %d, want it forwarded", out.status)
			}
		})
		t.Run(path+"/docker gates only", func(t *testing.T) {
			opts := ResourceLimitGuardOptions{}
			applyDocker(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
			if out := runResourceGuardRequest(t, opts, http.MethodPost, path, yaml, ""); out.status != ok {
				t.Fatalf("status %d, want it forwarded", out.status)
			}
		})
	}
	for _, mode := range []string{"warn", "audit"} {
		for _, path := range []string{"/libpod/play/kube", "/libpod/pods/create"} {
			t.Run(mode+path, func(t *testing.T) {
				opts := ResourceLimitGuardOptions{}
				applyLibpod(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
				body := `{"portmappings":[{"container_port":80}]}`
				out := runResourceGuardRequest(t, opts, http.MethodPost, path, body, mode)
				if out.status != ok || out.forwarded != 1 || out.forwardedBody != body {
					t.Fatalf("status %d forwarded %d", out.status, out.forwarded)
				}
				if out.meta.Decision != logging.DecisionWouldDeny || out.meta.ReasonCode != reasonCodeRequestBodyPolicyDenied {
					t.Fatalf("decision/reason code = %q/%q", out.meta.Decision, out.meta.ReasonCode)
				}
			})
		}
	}
}

func TestNetworkExposureHostStackOptions(t *testing.T) {
	const libpod = "/libpod/containers/create"
	const pod = "/libpod/pods/create"
	const docker = "/containers/create"
	deny1 := NetworkExposureOptions{DenyPublishedPorts: true}
	cases := []exposureCase{
		{name: "libpod: pasta network_options", path: libpod, body: `{"image":"alpine","netns":{"nsmode":"pasta"},"network_options":{"pasta":["-t","0.0.0.0/8080:80"]}}`, opts: deny1, wantStatus: deny},
		{name: "libpod: slirp4netns network_options", path: libpod, body: `{"network_options":{"slirp4netns":["port_handler=slirp4netns"]}}`, opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "libpod: network_options key case", path: libpod, body: `{"network_options":{"Pasta":["-t","8080"]}}`, opts: deny1, wantStatus: deny},
		{name: "libpod: pasta netns value", path: libpod, body: `{"netns":{"nsmode":"pasta","value":"-t,8080:80"}}`, opts: deny1, wantStatus: deny},
		{name: "libpod: slirp4netns netns value", path: libpod, body: `{"netns":{"nsmode":"SLIRP4NETNS","value":"x"}}`, opts: deny1, wantStatus: deny},
		{name: "libpod: empty pasta options", path: libpod, body: `{"netns":{"nsmode":"pasta"},"network_options":{"pasta":[]}}`, opts: deny1, wantStatus: ok},
		{name: "libpod: null pasta options", path: libpod, body: `{"netns":{"nsmode":"pasta"},"network_options":{"pasta":null}}`, opts: deny1, wantStatus: ok},
		{name: "libpod: bare pasta", path: libpod, body: `{"netns":{"nsmode":"pasta"}}`, opts: deny1, wantStatus: ok},
		{name: "libpod: other network_options key", path: libpod, body: `{"network_options":{"bridge":["x"]}}`, opts: deny1, wantStatus: ok},
		{name: "libpod: gates off", path: libpod, body: `{"network_options":{"pasta":["-t","8080"]}}`, opts: NetworkExposureOptions{}, wantStatus: ok},
		{name: "libpod: networks gate alone", path: libpod, body: `{"netns":{"nsmode":"bridge"},"network_options":{"pasta":["-t","8080"]},"networks":{"proxy":{}}}`, opts: nets("proxy"), wantStatus: ok, skipLookupCk: true},
		{name: "pod: pasta network_options", path: pod, body: `{"name":"p1","network_options":{"pasta":["-t","0.0.0.0/8080:80"]}}`, opts: deny1, wantStatus: deny},
		{name: "pod: slirp4netns netns value", path: "/v6.1.3" + pod, body: `{"netns":{"nsmode":"slirp4netns","value":"x"}}`, opts: ports("127.0.0.1"), wantStatus: deny},
	}
	checkExposureCases(t, cases, applyLibpod)

	checkExposureCases(t, []exposureCase{
		{name: "compat: pasta with options", path: docker, body: `{"Image":"alpine","HostConfig":{"NetworkMode":"pasta:-t,0.0.0.0/8080:80"}}`, opts: deny1, wantStatus: deny},
		{name: "compat: slirp4netns with options", path: docker, body: `{"HostConfig":{"NetworkMode":"slirp4netns:port_handler=slirp4netns"}}`, opts: ports("127.0.0.1"), wantStatus: deny},
		{name: "compat: prefix case", path: docker, body: `{"HostConfig":{"NetworkMode":" PASTA:-t,8080"}}`, opts: deny1, wantStatus: deny},
		{name: "compat: bare pasta", path: docker, body: `{"HostConfig":{"NetworkMode":"pasta"}}`, opts: deny1, wantStatus: ok},
		{name: "compat: gates off", path: docker, body: `{"HostConfig":{"NetworkMode":"pasta:-t,8080"}}`, opts: NetworkExposureOptions{}, wantStatus: ok},
		{name: "compat: networks gate alone", path: docker, body: `{"HostConfig":{"NetworkMode":"proxy"}}`, opts: nets("proxy"), wantStatus: ok, skipLookupCk: true},
	}, applyDocker)

	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{}
			applyLibpod(&opts, deny1, false)
			body := `{"network_options":{"pasta":["-t","8080"]}}`
			out := runResourceGuardRequest(t, opts, http.MethodPost, libpod, body, mode)
			if out.status != ok || out.forwarded != 1 || out.forwardedBody != body {
				t.Fatalf("status %d forwarded %d", out.status, out.forwarded)
			}
			if out.meta.Decision != logging.DecisionWouldDeny {
				t.Fatalf("decision = %q", out.meta.Decision)
			}
		})
	}
}

func TestNetworkExposureEndpointNetworkID(t *testing.T) {
	const docker = "/containers/create"
	only := nets("proxy")
	create := func(key, networkID string) string {
		return `{"Image":"alpine","HostConfig":{"NetworkMode":"` + key + `"},"NetworkingConfig":{"EndpointsConfig":{"` + key + `":{"NetworkID":"` + networkID + `"}}}}`
	}
	checkExposureCases(t, []exposureCase{
		{name: "create: NetworkID overrides the key", path: docker, body: create("proxy", "backend"), opts: only, wantStatus: deny, wantLookups: []string{"proxy", "backend"}},
		{name: "create: NetworkID of an unlisted network by ID", path: docker, body: create("proxy", backendNetworkID), opts: only, wantStatus: deny, wantLookups: []string{"proxy", backendNetworkID}},
		{name: "create: matching NetworkID by full ID", path: docker, body: create("proxy", proxyNetworkID), opts: only, wantStatus: ok, wantLookups: []string{"proxy", proxyNetworkID}},
		{name: "create: matching NetworkID by prefix", path: docker, body: create("proxy", proxyNetworkID[:8]), opts: only, wantStatus: ok, wantLookups: []string{"proxy", proxyNetworkID[:8]}},
		{name: "create: NetworkID equal to the key", path: docker, body: create("proxy", "proxy"), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "create: empty NetworkID", path: docker, body: create("proxy", ""), opts: only, wantStatus: ok, wantLookups: []string{"proxy"}},
		{name: "create: unknown NetworkID", path: docker, body: create("proxy", "missing"), opts: only, wantStatus: deny, wantLookups: []string{"proxy", "missing"}},
		{name: "create: NetworkID lookup failure", path: docker, body: create("proxy", "boom"), opts: only, wantStatus: bad, wantLookups: []string{"proxy", "boom"}},
		{name: "create: NetworkID with no inspector", path: docker, body: create("proxy", "backend"), opts: only, noInspector: true, wantStatus: bad},
		{name: "create: host key with another NetworkID", path: docker, body: create("host", "backend"), opts: only, allowHost: true, wantStatus: deny, wantLookups: []string{"backend"}},
		{name: "create: NetworkID ignored while the list is off", path: docker, body: create("proxy", "backend"), opts: NetworkExposureOptions{}, wantStatus: ok},
	}, applyDocker)

	const connectBody = `{"Container":"c1","EndpointConfig":{"NetworkID":"%s"}}`
	connect := []struct {
		name        string
		path        string
		body        string
		wantStatus  int
		wantLookups []string
	}{
		{"connect: NetworkID overrides the path", "/networks/proxy/connect", fmtConnect(connectBody, "backend"), deny, []string{"proxy", "backend"}},
		{"connect: matching NetworkID", "/v1.45/networks/proxy/connect", fmtConnect(connectBody, proxyNetworkID), ok, []string{"proxy", proxyNetworkID}},
		{"connect: empty NetworkID", "/networks/proxy/connect", fmtConnect(connectBody, ""), ok, []string{"proxy"}},
		{"connect: no EndpointConfig", "/networks/proxy/connect", `{"Container":"c1"}`, ok, []string{"proxy"}},
		{"connect: undecodable body", "/networks/proxy/connect", `{`, ok, []string{"proxy"}},
		{"connect: unknown NetworkID", "/networks/proxy/connect", fmtConnect(connectBody, "missing"), deny, []string{"proxy", "missing"}},
		{"connect: NetworkID lookup failure", "/networks/proxy/connect", fmtConnect(connectBody, "boom"), bad, []string{"proxy", "boom"}},
		{"libpod connect: body is not read", "/libpod/networks/proxy/connect", fmtConnect(connectBody, "backend"), ok, []string{"proxy"}},
	}
	for _, tt := range connect {
		t.Run(tt.name, func(t *testing.T) {
			fake := &exposureNetworks{}
			opts := ResourceLimitGuardOptions{InspectNetwork: fake.inspect}
			applyDocker(&opts, only, false)
			applyLibpod(&opts, only, false)
			out := runResourceGuardRequest(t, opts, http.MethodPost, tt.path, tt.body, "")
			if out.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", out.status, tt.wantStatus, out.body)
			}
			if tt.wantStatus == ok && out.forwardedBody != tt.body {
				t.Fatalf("forwarded body = %q, want it unchanged", out.forwardedBody)
			}
			if !slices.Equal(fake.lookups, tt.wantLookups) {
				t.Fatalf("lookups = %v, want %v", fake.lookups, tt.wantLookups)
			}
		})
	}
	t.Run("connect: oversized body", func(t *testing.T) {
		opts := ResourceLimitGuardOptions{InspectNetwork: (&exposureNetworks{}).inspect}
		applyDocker(&opts, only, false)
		body := `{"Container":"` + strings.Repeat("a", maxNetworkBodyBytes) + `"}`
		out := runResourceGuardRequest(t, opts, http.MethodPost, "/networks/proxy/connect", body, "")
		if out.status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", out.status)
		}
	})
}

func fmtConnect(format, networkID string) string {
	return strings.Replace(format, "%s", networkID, 1)
}

func TestNetworkExposurePortEntryUnknownKeys(t *testing.T) {
	deny1 := NetworkExposureOptions{DenyPublishedPorts: true}
	hostIPs := ports("127.0.0.1")
	libpodEntry := func(extra string) string {
		return `{"portmappings":[{"host_ip":"127.0.0.1","container_port":80,"host_port":8080` + extra + `}]}`
	}
	checkExposureCases(t, []exposureCase{
		{name: "libpod: only real keys", path: "/libpod/containers/create", body: libpodEntry(`,"protocol":"tcp","range":1`), opts: hostIPs, wantStatus: ok},
		{name: "libpod: key case folds", path: "/libpod/containers/create", body: `{"portmappings":[{"Host_IP":"127.0.0.1"}]}`, opts: hostIPs, wantStatus: ok},
		{name: "libpod: unknown key", path: "/libpod/containers/create", body: libpodEntry(`,"host_ipx":"0.0.0.0"`), opts: hostIPs, wantStatus: deny},
		{name: "libpod: unknown key under deny_published_ports", path: "/libpod/containers/create", body: libpodEntry(`,"zz":1`), opts: deny1, wantStatus: deny},
		{name: "libpod: unknown key with the ports gates off", path: "/libpod/containers/create", body: libpodEntry(`,"zz":1`), opts: nets("proxy"), wantStatus: ok, skipLookupCk: true},
		{name: "libpod: null entry binds every interface", path: "/libpod/containers/create", body: `{"portmappings":[null]}`, opts: hostIPs, wantStatus: deny},
		{name: "libpod: non-string host_ip is the daemon's to refuse", path: "/libpod/containers/create", body: `{"portmappings":[{"host_ip":1}]}`, opts: hostIPs, wantStatus: ok},
		{name: "pod: unknown key", path: "/libpod/pods/create", body: libpodEntry(`,"zz":1`), opts: hostIPs, wantStatus: deny},
	}, applyLibpod)
	checkExposureCases(t, []exposureCase{
		{name: "docker: only real keys", path: "/containers/create", body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}}}`, opts: hostIPs, wantStatus: ok},
		{name: "docker: unknown key", path: "/containers/create", body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostIpx":"0.0.0.0"}]}}}`, opts: hostIPs, wantStatus: deny},
		{name: "docker: unknown key with the ports gates off", path: "/containers/create", body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"zz":1}]}}}`, opts: nets("proxy"), wantStatus: ok, skipLookupCk: true},
	}, applyDocker)
	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{}
			applyLibpod(&opts, hostIPs, false)
			body := libpodEntry(`,"zz":1`)
			out := runResourceGuardRequest(t, opts, http.MethodPost, "/libpod/containers/create", body, mode)
			if out.status != ok || out.forwarded != 1 || out.meta.Decision != logging.DecisionWouldDeny {
				t.Fatalf("status %d forwarded %d decision %q", out.status, out.forwarded, out.meta.Decision)
			}
		})
	}
}

func TestNetworkExposureRestore(t *testing.T) {
	for _, path := range []string{"/libpod/containers/c1/restore", "/v6.1.3/libpod/containers/c1/restore?import=true", "/libpod/containers/c1/restore?publishPorts=8080:80"} {
		for name, e := range map[string]NetworkExposureOptions{
			"deny_published_ports":  {DenyPublishedPorts: true},
			"allowed_port_host_ips": ports("127.0.0.1"),
			"allowed_networks":      nets("proxy"),
		} {
			t.Run(path+"/"+name, func(t *testing.T) {
				opts := ResourceLimitGuardOptions{}
				applyLibpod(&opts, e, false)
				out := runResourceGuardRequest(t, opts, http.MethodPost, path, "", "")
				if out.status != deny || out.forwarded != 0 || !strings.Contains(out.body, "container restore denied") {
					t.Fatalf("status %d forwarded %d body %s", out.status, out.forwarded, out.body)
				}
			})
		}
		t.Run(path+"/gates off", func(t *testing.T) {
			if out := runResourceGuardRequest(t, ResourceLimitGuardOptions{}, http.MethodPost, path, "", ""); out.status != ok {
				t.Fatalf("status %d, want it forwarded", out.status)
			}
		})
		t.Run(path+"/docker gates only", func(t *testing.T) {
			opts := ResourceLimitGuardOptions{}
			applyDocker(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
			if out := runResourceGuardRequest(t, opts, http.MethodPost, path, "", ""); out.status != ok {
				t.Fatalf("status %d, want it forwarded", out.status)
			}
		})
		for _, mode := range []string{"warn", "audit"} {
			t.Run(mode+path, func(t *testing.T) {
				opts := ResourceLimitGuardOptions{}
				applyLibpod(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
				out := runResourceGuardRequest(t, opts, http.MethodPost, path, "", mode)
				if out.status != ok || out.forwarded != 1 {
					t.Fatalf("status %d forwarded %d", out.status, out.forwarded)
				}
				if out.meta.Decision != logging.DecisionWouldDeny || out.meta.ReasonCode != reasonCodeRequestBodyPolicyDenied {
					t.Fatalf("decision/reason code = %q/%q", out.meta.Decision, out.meta.ReasonCode)
				}
			})
		}
	}
	for _, path := range []string{"/libpod/containers/c1/checkpoint", "/libpod/containers/c1/restore/x", "/containers/c1/restore"} {
		t.Run("untouched "+path, func(t *testing.T) {
			opts := ResourceLimitGuardOptions{}
			applyLibpod(&opts, NetworkExposureOptions{DenyPublishedPorts: true}, false)
			if out := runResourceGuardRequest(t, opts, http.MethodPost, path, "", ""); out.status != ok {
				t.Fatalf("status %d, want it forwarded", out.status)
			}
		})
	}
}
