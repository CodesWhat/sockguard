package responsefilter

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// S118: fields that still carried addresses under redact_network_topology.
// Every one is a netip type in current Docker clients, so the value is "".
func TestRedactNetworkTopology_RemainingAddressLeaks(t *testing.T) {
	t.Parallel()
	filter := New(Options{RedactNetworkTopology: true})

	decode := func(t *testing.T, body []byte) any {
		t.Helper()
		var got any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	tests := []struct {
		name  string
		path  string
		body  string
		check func(t *testing.T, got any)
	}{
		{
			name: "network inspect verbose services",
			path: "/v1.53/networks/net-1?verbose=true",
			body: `{"Id":"net-1","Services":{"web":{"VIP":"10.0.9.2","Ports":["80/tcp"],"LocalLBIndex":3,"Tasks":[{"Name":"web.1","EndpointID":"ep-1","EndpointIP":"10.0.9.3","Info":{"k":"v"}},{"Name":"web.2","EndpointID":"ep-2","EndpointIP":"10.0.9.4","Info":{}}]},"db":{"VIP":"10.0.9.9","Ports":null,"LocalLBIndex":4,"Tasks":null}}}`,
			check: func(t *testing.T, got any) {
				svcs := got.(map[string]any)["Services"].(map[string]any)
				web := svcs["web"].(map[string]any)
				if web["VIP"] != "" {
					t.Errorf("web VIP = %#v, want empty string", web["VIP"])
				}
				if web["LocalLBIndex"] != float64(3) {
					t.Errorf("LocalLBIndex = %#v, want 3", web["LocalLBIndex"])
				}
				for i, raw := range web["Tasks"].([]any) {
					task := raw.(map[string]any)
					if task["EndpointIP"] != "" {
						t.Errorf("Tasks[%d].EndpointIP = %#v, want empty string", i, task["EndpointIP"])
					}
					if task["EndpointID"] == "" || task["Name"] == "" {
						t.Errorf("Tasks[%d] lost opaque fields: %#v", i, task)
					}
				}
				if svcs["db"].(map[string]any)["VIP"] != "" {
					t.Errorf("db VIP not blanked")
				}
			},
		},
		{
			name: "info DefaultAddressPools",
			path: "/v1.53/info",
			body: `{"ID":"d","DefaultAddressPools":[{"Base":"10.20.0.0/16","Size":24},{"Base":"fd00:1::/48","Size":64}]}`,
			check: func(t *testing.T, got any) {
				pools := got.(map[string]any)["DefaultAddressPools"].([]any)
				if len(pools) != 2 {
					t.Fatalf("pools = %#v", pools)
				}
				for i, raw := range pools {
					if raw.(map[string]any)["Base"] != "" {
						t.Errorf("DefaultAddressPools[%d].Base = %#v, want empty string", i, raw)
					}
				}
			},
		},
		{
			name: "info Swarm.Cluster pools",
			path: "/v1.53/info",
			body: `{"ID":"d","Swarm":{"NodeID":"n","Cluster":{"ID":"c","DefaultAddrPool":["10.0.0.0/8"],"DefaultAddressPools":[{"Base":"10.30.0.0/16","Size":24}]}}}`,
			check: func(t *testing.T, got any) {
				cluster := got.(map[string]any)["Swarm"].(map[string]any)["Cluster"].(map[string]any)
				if pool, ok := cluster["DefaultAddrPool"].([]any); !ok || len(pool) != 0 {
					t.Errorf("DefaultAddrPool = %#v, want empty array", cluster["DefaultAddrPool"])
				}
				if cluster["DefaultAddressPools"].([]any)[0].(map[string]any)["Base"] != "" {
					t.Errorf("Cluster.DefaultAddressPools Base not blanked: %#v", cluster["DefaultAddressPools"])
				}
			},
		},
		{
			name: "swarm inspect DefaultAddressPools",
			path: "/v1.53/swarm",
			body: `{"ID":"c","DefaultAddrPool":["10.0.0.0/8"],"DefaultAddressPools":[{"Base":"10.30.0.0/16","Size":24}]}`,
			check: func(t *testing.T, got any) {
				m := got.(map[string]any)
				if pool, ok := m["DefaultAddrPool"].([]any); !ok || len(pool) != 0 {
					t.Errorf("DefaultAddrPool = %#v, want empty array", m["DefaultAddrPool"])
				}
				if m["DefaultAddressPools"].([]any)[0].(map[string]any)["Base"] != "" {
					t.Errorf("DefaultAddressPools Base not blanked")
				}
			},
		},
		{
			name: "container list Ports",
			path: "/v1.53/containers/json",
			body: `[{"Id":"abc","Ports":[{"IP":"192.168.1.10","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},{"PrivatePort":9000,"Type":"tcp"}]}]`,
			check: func(t *testing.T, got any) {
				ports := got.([]any)[0].(map[string]any)["Ports"].([]any)
				first := ports[0].(map[string]any)
				if first["IP"] != "" {
					t.Errorf("Ports[0].IP = %#v, want empty string", first["IP"])
				}
				if first["PublicPort"] != float64(8080) || first["PrivatePort"] != float64(80) || first["Type"] != "tcp" {
					t.Errorf("Ports[0] lost non-address fields: %#v", first)
				}
				if _, present := ports[1].(map[string]any)["IP"]; present {
					t.Errorf("Ports[1] gained an IP key")
				}
			},
		},
		{
			name: "container inspect NetworkSettings.Ports",
			path: "/v1.53/containers/abc/json",
			body: `{"Id":"abc","NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"192.168.1.10","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}],"443/tcp":null}}}`,
			check: func(t *testing.T, got any) {
				ports := got.(map[string]any)["NetworkSettings"].(map[string]any)["Ports"].(map[string]any)
				for i, raw := range ports["80/tcp"].([]any) {
					b := raw.(map[string]any)
					if b["HostIp"] != "" || b["HostPort"] != "8080" {
						t.Errorf("80/tcp[%d] = %#v, want HostIp empty and HostPort kept", i, b)
					}
				}
				if ports["443/tcp"] != nil {
					t.Errorf("443/tcp = %#v, want null kept", ports["443/tcp"])
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
			for _, leaked := range []string{"10.0.9.", "10.20.0", "fd00:1", "10.30.0", "192.168.1.10", "10.0.0.0/8"} {
				if strings.Contains(string(body), leaked) {
					t.Errorf("redacted body still contains %q: %s", leaked, body)
				}
			}
			tt.check(t, decode(t, body))
		})
	}
}

func TestRedactNetworkTopology_RemainingLeaksRejectBadShapes(t *testing.T) {
	t.Parallel()
	filter := New(Options{RedactNetworkTopology: true})
	tests := []struct{ name, path, body string }{
		{"services not object", "/v1.53/networks/n", `{"Services":[]}`},
		{"service not object", "/v1.53/networks/n", `{"Services":{"a":1}}`},
		{"tasks not array", "/v1.53/networks/n", `{"Services":{"a":{"Tasks":{}}}}`},
		{"pools not array", "/v1.53/info", `{"DefaultAddressPools":{}}`},
		{"container ports not array", "/v1.53/containers/abc/json", `{"Ports":{}}`},
		{"settings ports not map", "/v1.53/containers/abc/json", `{"NetworkSettings":{"Ports":[]}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := newResponseForTest(t, http.MethodGet, tt.path, tt.body)
			if err := filter.ModifyResponse(resp); err == nil {
				t.Fatal("ModifyResponse() = nil, want rejection")
			}
		})
	}
}

func TestRedactNetworkTopology_OffLeavesPortsAndServices(t *testing.T) {
	t.Parallel()
	filter := New(Options{RedactContainerEnv: true})
	resp := newResponseForTest(t, http.MethodGet, "/v1.53/containers/json", `[{"Id":"a","Ports":[{"IP":"192.168.1.10","PrivatePort":80}]}]`)
	if err := filter.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readBodyForTest(t, resp)), "192.168.1.10") {
		t.Error("Ports IP redacted with redact_network_topology off")
	}
}
