package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkInspectPolicies(b *testing.B) {
	volumePolicy := newVolumePolicy(VolumeOptions{})
	secretPolicy := newSecretPolicy(SecretOptions{})
	configPolicy := newConfigPolicy(ConfigOptions{})
	servicePolicy := newServicePolicy(ServiceOptions{
		AllowedBindMounts: []string{"/srv/services"},
		AllowOfficial:     true,
	})
	swarmPolicy := newSwarmPolicy(SwarmOptions{
		AllowedJoinRemoteAddrs: []string{"10.0.0.11:2377"},
	})
	pluginPolicy := newPluginPolicy(PluginOptions{
		AllowedBindMounts:     []string{"/allowed"},
		AllowedDevices:        []string{"/dev/allowed"},
		AllowedCapabilities:   []string{"NET_ADMIN"},
		AllowedSetEnvPrefixes: []string{"DEBUG="},
		AllowOfficial:         true,
		AllowedRegistries:     []string{"registry.example.com"},
	})

	serviceBody := []byte(`{
		"TaskTemplate": {
			"ContainerSpec": {
				"Image": "nginx:latest",
				"Mounts": [
					{"Type": "bind", "Source": "/srv/services/web", "Target": "/config"}
				]
			}
		},
		"Networks": [
			{"Target": "frontend"}
		]
	}`)
	volumeBody := []byte(`{"Name":"cache","Driver":"local"}`)
	secretBody := []byte(`{"Name":"db-password","Data":"c2VjcmV0"}`)
	configBody := []byte(`{"Name":"app-config","Data":"Y29uZmln"}`)
	swarmInitBody := []byte(`{
		"ListenAddr": "0.0.0.0:2377",
		"AdvertiseAddr": "10.0.0.10:2377"
	}`)
	swarmJoinBody := []byte(`{
		"ListenAddr": "0.0.0.0:2377",
		"AdvertiseAddr": "10.0.0.10:2377",
		"RemoteAddrs": ["10.0.0.11:2377"],
		"JoinToken": "SWMTKN-1-join"
	}`)
	swarmUpdateBody := []byte(`{
		"CAConfig": {
			"NodeCertExpiry": 7776000000000000
		},
		"EncryptionConfig": {
			"AutoLockManagers": false
		}
	}`)
	pluginPrivilegesBody := []byte(`[
		{"Name":"network","Value":["bridge"]},
		{"Name":"mount","Value":["/allowed"]},
		{"Name":"device","Value":["/dev/allowed"]},
		{"Name":"capabilities","Value":["NET_ADMIN"]}
	]`)
	pluginSetBody := []byte(`["mybind.source=/allowed","mydevice.path=/dev/allowed","DEBUG=1"]`)
	pluginCreateBody := mustPluginCreateContextTar(b, pluginCreateConfig{
		PropagatedMount: "/allowed",
		Mounts: []struct {
			Source string `json:"Source"`
		}{{Source: "/allowed"}},
		Linux: struct {
			Capabilities    []string `json:"Capabilities"`
			AllowAllDevices bool     `json:"AllowAllDevices"`
			Devices         []struct {
				Path string `json:"Path"`
			} `json:"Devices"`
		}{
			Capabilities: []string{"NET_ADMIN"},
			Devices: []struct {
				Path string `json:"Path"`
			}{{Path: "/dev/allowed"}},
		},
	}, true)

	cases := []struct {
		name        string
		makeRequest func() *http.Request
		inspect     func(*http.Request, string) (string, error)
	}{
		{
			name: "volume_create",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/volumes/create", volumeBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return volumePolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "secret_create",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/secrets/create", secretBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return secretPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "config_create",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/configs/create", configBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return configPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "service_create",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/services/create", serviceBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return servicePolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "swarm_init",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/swarm/init", swarmInitBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return swarmPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "swarm_join",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/swarm/join", swarmJoinBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return swarmPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "swarm_update",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/swarm/update?version=42", swarmUpdateBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return swarmPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "plugin_pull",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/plugins/pull?remote=registry.example.com/acme/plugin:1.0&name=acme/plugin", pluginPrivilegesBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return pluginPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "plugin_set",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/plugins/acme/set", pluginSetBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return pluginPolicy.inspect(nil, req, normalizedPath)
			},
		},
		{
			name: "plugin_create_gzip",
			makeRequest: func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/plugins/create?name=acme/plugin", pluginCreateBody)
			},
			inspect: func(req *http.Request, normalizedPath string) (string, error) {
				return pluginPolicy.inspect(nil, req, normalizedPath)
			},
		},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			benchmarkInspectPolicy(b, tt.makeRequest, tt.inspect)
		})
	}
}

func benchmarkInspectPolicy(
	b *testing.B,
	makeRequest func() *http.Request,
	inspect func(*http.Request, string) (string, error),
) {
	b.Helper()

	req := makeRequest()
	normalizedPath := NormalizePath(req.URL.Path)
	denyReason, err := inspect(req, normalizedPath)
	if err != nil {
		b.Fatalf("inspect() error = %v", err)
	}
	if denyReason != "" {
		b.Fatalf("inspect() denyReason = %q, want allow", denyReason)
	}

	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		req = makeRequest()
		normalizedPath = NormalizePath(req.URL.Path)
		b.StartTimer()

		denyReason, err = inspect(req, normalizedPath)
		if err != nil {
			b.Fatalf("inspect() error = %v", err)
		}
		if denyReason != "" {
			b.Fatalf("inspect() denyReason = %q, want allow", denyReason)
		}
	}
}

func newBenchmarkInspectorRequest(method, target string, body []byte) *http.Request {
	if len(body) == 0 {
		return httptest.NewRequest(method, target, nil)
	}
	return httptest.NewRequest(method, target, bytes.NewReader(body))
}
