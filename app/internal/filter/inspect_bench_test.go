package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// BenchmarkInspectContainerCreate covers the most security-critical inspector.
// Permissive variant takes the allowsAllContainerCreateBodies early-exit;
// strict variant walks the full HostConfig.
func BenchmarkInspectContainerCreate(b *testing.B) {
	permissive := newContainerCreatePolicy(ContainerCreateOptions{
		AllowPrivileged:        true,
		AllowHostNetwork:       true,
		AllowHostPID:           true,
		AllowHostIPC:           true,
		AllowHostUserNS:        true,
		AllowedBindMounts:      []string{"/"},
		AllowAllDevices:        true,
		AllowDeviceRequests:    true,
		AllowDeviceCgroupRules: true,
		AllowAllCapabilities:   true,
		AllowSysctls:           true,
	})
	strict := newContainerCreatePolicy(ContainerCreateOptions{
		AllowedBindMounts:          []string{"/srv"},
		AllowedDevices:             []string{"/dev/null"},
		AllowedCapabilities:        []string{"NET_BIND_SERVICE"},
		RequireNoNewPrivileges:     true,
		RequireDropAllCapabilities: true,
		RequireMemoryLimit:         true,
		RequireCPULimit:            true,
		RequirePidsLimit:           true,
		DenyUnconfinedSeccomp:      true,
		DenyUnconfinedAppArmor:     true,
	})

	simpleBody := []byte(`{
		"Image":"alpine:3.19",
		"Cmd":["sh","-c","echo hi"],
		"Labels":{"app":"web"},
		"HostConfig":{"NetworkMode":"bridge"}
	}`)
	strictBody := []byte(`{
		"Image":"alpine:3.19",
		"Cmd":["sh","-c","echo hi"],
		"Labels":{"app":"web"},
		"HostConfig":{
			"NetworkMode":"bridge",
			"Binds":["/srv/data:/data:ro"],
			"Memory":67108864,
			"NanoCpus":500000000,
			"PidsLimit":256,
			"CapAdd":["NET_BIND_SERVICE"],
			"CapDrop":["ALL"],
			"SecurityOpt":["seccomp=runtime/default","apparmor=docker-default","no-new-privileges:true"],
			"ReadonlyRootfs":true
		},
		"User":"1000:1000",
		"Config":{"User":"1000:1000"}
	}`)

	cases := []struct {
		name   string
		body   []byte
		policy containerCreatePolicy
	}{
		{"permissive_early_exit", simpleBody, permissive},
		{"strict_full_walk", strictBody, strict},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkInspectPolicy(b, func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, "/containers/create?name=web", tc.body)
			}, func(req *http.Request, normalizedPath string) (string, error) {
				return tc.policy.inspect(nil, req, normalizedPath)
			})
		})
	}
}

// BenchmarkInspectBuild covers POST /build (query-only inspection in the
// allow path).
func BenchmarkInspectBuild(b *testing.B) {
	policy := newBuildPolicy(BuildOptions{
		AllowRemoteContext:   true,
		AllowHostNetwork:     false,
		AllowRunInstructions: true,
	})
	cases := []struct {
		name   string
		target string
	}{
		{"local_context", "/build?t=app:latest&dockerfile=Dockerfile"},
		{"with_buildargs", "/build?t=app:latest&buildargs=" + url.QueryEscape(`{"VERSION":"1.0","COMMIT":"abc"}`)},
		{"remote_context", "/build?remote=https://github.com/example/repo.git"},
		{"networkmode_default", "/build?networkmode=default&t=app:latest"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkInspectPolicy(b, func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, tc.target, nil)
			}, func(req *http.Request, normalizedPath string) (string, error) {
				return policy.inspect(nil, req, normalizedPath)
			})
		})
	}
}

// BenchmarkInspectImagePull covers POST /images/create (query-only).
func BenchmarkInspectImagePull(b *testing.B) {
	policy := newImagePullPolicy(ImagePullOptions{
		AllowedRegistries: []string{"docker.io", "ghcr.io", "registry.example.com"},
	})
	cases := []struct {
		name   string
		target string
	}{
		{"dockerhub_official", "/images/create?fromImage=docker.io/library/alpine&tag=3.19"},
		{"ghcr_namespaced", "/images/create?fromImage=ghcr.io/org/app&tag=v1.2.3"},
		{"private_registry", "/images/create?fromImage=registry.example.com/team/app:latest"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkInspectPolicy(b, func() *http.Request {
				return newBenchmarkInspectorRequest(http.MethodPost, tc.target, nil)
			}, func(req *http.Request, normalizedPath string) (string, error) {
				return policy.inspect(nil, req, normalizedPath)
			})
		})
	}
}

// BenchmarkInspectExecCreate exercises the exec create body inspector. The
// allowed-command list is walked with slices.Equal; the second entry matches.
func BenchmarkInspectExecCreate(b *testing.B) {
	policy := newExecPolicy(ExecOptions{
		AllowPrivileged: true,
		AllowRootUser:   true,
		AllowedCommands: [][]string{
			{"sh", "-c", "echo hi"},
			{"echo", "hi"},
			{"ls", "-la"},
			{"cat", "/etc/hostname"},
		},
	})
	body := []byte(`{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Cmd":["echo","hi"],"Privileged":false,"User":"app"}`)

	benchmarkInspectPolicy(b, func() *http.Request {
		return newBenchmarkInspectorRequest(http.MethodPost, "/containers/abc123/exec", body)
	}, func(req *http.Request, normalizedPath string) (string, error) {
		return policy.inspect(nil, req, normalizedPath)
	})
}
