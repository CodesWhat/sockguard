package responsefilter

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// Typed Docker clients (moby/api >= 1.52) decode these fields as netip.Addr,
// netip.Prefix and HardwareAddr. The standard library cannot import those
// types here, so the tests assert the same parse semantics: every address
// field is "" or parses, and nothing from the original body survives.

const typedEndpointJSON = `{
	"NetworkID":"net-id-123",
	"EndpointID":"ep-id-123",
	"Gateway":"172.18.0.1",
	"IPAddress":"172.18.0.5",
	"IPPrefixLen":16,
	"IPv6Gateway":"2001:db8::1",
	"GlobalIPv6Address":"2001:db8::5",
	"GlobalIPv6PrefixLen":64,
	"MacAddress":"02:42:ac:12:00:05"
}`

const typedNetworkSettingsJSON = `{
	"Bridge":"docker0",
	"SandboxID":"sandbox-123",
	"SandboxKey":"/var/run/docker/netns/sandbox-123",
	"EndpointID":"ep-id-123",
	"Gateway":"172.18.0.1",
	"IPAddress":"172.18.0.5",
	"IPPrefixLen":16,
	"IPv6Gateway":"2001:db8::1",
	"GlobalIPv6Address":"2001:db8::5",
	"GlobalIPv6PrefixLen":64,
	"LinkLocalIPv6Address":"fe80::5",
	"LinkLocalIPv6PrefixLen":64,
	"MacAddress":"02:42:ac:12:00:05",
	"SecondaryIPAddresses":[{"Addr":"172.18.0.9","PrefixLen":16}],
	"Networks":{"bridge":` + typedEndpointJSON + `}
}`

var typedAddressKeys = []string{
	"Gateway", "IPv6Gateway", "IPAddress", "GlobalIPv6Address", "LinkLocalIPv6Address",
}

var typedOpaqueKeys = []string{"SandboxID", "SandboxKey", "Bridge"}

func assertTypedAddressObject(t *testing.T, where string, obj map[string]any) {
	t.Helper()
	for _, key := range typedAddressKeys {
		value, present := obj[key]
		if !present {
			continue
		}
		s, ok := value.(string)
		if !ok {
			t.Errorf("%s.%s = %#v, want string", where, key, value)
			continue
		}
		if s == "" {
			continue
		}
		if _, err := netip.ParseAddr(s); err != nil {
			t.Errorf("%s.%s = %q does not parse as netip.Addr: %v", where, key, s, err)
		}
	}
	if value, present := obj["MacAddress"]; present {
		s, _ := value.(string)
		if s != "" {
			if _, err := net.ParseMAC(s); err != nil {
				t.Errorf("%s.MacAddress = %q does not parse as a MAC: %v", where, s, err)
			}
		}
	}
	for _, key := range typedOpaqueKeys {
		if value, present := obj[key]; present && value != "<redacted>" {
			t.Errorf("%s.%s = %#v, want <redacted>", where, key, value)
		}
	}
	for _, key := range []string{"IPPrefixLen", "GlobalIPv6PrefixLen", "LinkLocalIPv6PrefixLen"} {
		if value, present := obj[key]; present && value != float64(0) {
			t.Errorf("%s.%s = %#v, want 0", where, key, value)
		}
	}
	for _, key := range []string{"SecondaryIPAddresses", "SecondaryIPv6Addresses"} {
		if value, present := obj[key]; present {
			if arr, ok := value.([]any); !ok || len(arr) != 0 {
				t.Errorf("%s.%s = %#v, want empty array", where, key, value)
			}
		}
	}
}

func assertTypedNetworkSettings(t *testing.T, where string, settings map[string]any) {
	t.Helper()
	assertTypedAddressObject(t, where, settings)
	for _, key := range typedAddressKeys {
		if value, present := settings[key]; present && value != "" {
			t.Errorf("%s.%s = %#v, want empty string", where, key, value)
		}
	}
	if value, present := settings["MacAddress"]; present && value != "" {
		t.Errorf("%s.MacAddress = %#v, want empty string", where, value)
	}
	networks, ok := settings["Networks"].(map[string]any)
	if !ok {
		return
	}
	for name, raw := range networks {
		endpoint, _ := raw.(map[string]any)
		assertTypedAddressObject(t, where+".Networks."+name, endpoint)
		for _, key := range append([]string{"MacAddress"}, typedAddressKeys...) {
			if value, present := endpoint[key]; present && value != "" {
				t.Errorf("%s.Networks.%s.%s = %#v, want empty string", where, name, key, value)
			}
		}
	}
}

func readBodyForTest(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return body
}

func TestRedactNetworkTopology_AddressFieldsStayTypeValid(t *testing.T) {
	t.Parallel()
	filter := New(Options{RedactNetworkTopology: true})

	tests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, body []byte)
	}{
		{
			name: "container inspect",
			path: "/v1.53/containers/abc/json",
			body: `{"HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":` + typedNetworkSettingsJSON + `}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				settings, _ := got["NetworkSettings"].(map[string]any)
				assertTypedNetworkSettings(t, "NetworkSettings", settings)
			},
		},
		{
			name: "container list",
			path: "/v1.53/containers/json",
			body: `[{"Id":"abc","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Networks":{"bridge":` + typedEndpointJSON + `}}}]`,
			check: func(t *testing.T, body []byte) {
				var got []map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				settings, _ := got[0]["NetworkSettings"].(map[string]any)
				assertTypedNetworkSettings(t, "NetworkSettings", settings)
			},
		},
		{
			name: "system df",
			path: "/v1.53/system/df",
			body: `{"Containers":[{"Id":"abc","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Networks":{"bridge":` + typedEndpointJSON + `}}}]}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				containers, _ := got["Containers"].([]any)
				container, _ := containers[0].(map[string]any)
				settings, _ := container["NetworkSettings"].(map[string]any)
				assertTypedNetworkSettings(t, "NetworkSettings", settings)
			},
		},
		{
			name: "service inspect virtual IPs",
			path: "/v1.53/services/svc-1",
			body: `{"ID":"svc-1","Endpoint":{"VirtualIPs":[{"NetworkID":"net-1","Addr":"10.0.0.5/24"}]}}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				endpoint, _ := got["Endpoint"].(map[string]any)
				vips, _ := endpoint["VirtualIPs"].([]any)
				vip, _ := vips[0].(map[string]any)
				// netip.Prefix decodes "" as the zero prefix.
				if vip["Addr"] != "" {
					t.Errorf("VirtualIPs[0].Addr = %#v, want empty string", vip["Addr"])
				}
				if vip["NetworkID"] != "net-1" {
					t.Errorf("VirtualIPs[0].NetworkID = %#v, want net-1", vip["NetworkID"])
				}
			},
		},
		{
			name: "task network attachments",
			path: "/v1.53/tasks/task-1",
			body: `{"ID":"task-1","NetworksAttachments":[{"Network":{"ID":"net-1"},"Addresses":["10.0.0.5/24","fd00::5/64"]}]}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				attachments, _ := got["NetworksAttachments"].([]any)
				attachment, _ := attachments[0].(map[string]any)
				addrs, ok := attachment["Addresses"].([]any)
				if !ok || len(addrs) != 0 {
					t.Errorf("Addresses = %#v, want empty array", attachment["Addresses"])
				}
			},
		},
		{
			name: "network inspect",
			path: "/v1.53/networks/net-1",
			body: `{"Id":"net-1","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]},"Containers":{"abc":{"IPv4Address":"172.18.0.5/16","MacAddress":"02:42:ac:12:00:05"}}}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				ipam, _ := got["IPAM"].(map[string]any)
				if cfg, ok := ipam["Config"].([]any); !ok || len(cfg) != 0 {
					t.Errorf("IPAM.Config = %#v, want empty array", ipam["Config"])
				}
				if containers, ok := got["Containers"].(map[string]any); !ok || len(containers) != 0 {
					t.Errorf("Containers = %#v, want empty object", got["Containers"])
				}
			},
		},
		{
			name: "libpod container inspect",
			path: "/v5.8.1/libpod/containers/abc/json",
			body: `{"Id":"abc","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":` + typedNetworkSettingsJSON + `}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				settings, _ := got["NetworkSettings"].(map[string]any)
				assertTypedNetworkSettings(t, "NetworkSettings", settings)
			},
		},
		{
			name: "node inspect keeps string Addr placeholder",
			path: "/v1.53/nodes/node-1",
			body: `{"ID":"node-1","Status":{"State":"ready","Addr":"10.0.0.7"},"ManagerStatus":{"Addr":"10.0.0.7:2377"}}`,
			check: func(t *testing.T, body []byte) {
				var got map[string]any
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				// swarm.NodeStatus.Addr and ManagerStatus.Addr are plain strings in moby.
				status, _ := got["Status"].(map[string]any)
				manager, _ := got["ManagerStatus"].(map[string]any)
				if status["Addr"] != "<redacted>" || manager["Addr"] != "<redacted>" {
					t.Errorf("node Addr = %#v / %#v, want <redacted>", status["Addr"], manager["Addr"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := newResponseForTest(t, http.MethodGet, tt.path, tt.body)
			if err := filter.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse() error = %v", err)
			}
			body := readBodyForTest(t, resp)
			for _, leaked := range []string{"172.18.0", "2001:db8", "02:42:ac", "fe80::", "10.0.0.5", "10.0.0.7"} {
				if strings.Contains(string(body), leaked) {
					t.Errorf("redacted body still contains %q: %s", leaked, body)
				}
			}
			tt.check(t, body)
		})
	}
}
