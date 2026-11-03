package filter

import (
	"testing"
)

func TestLibpodContainerCreateResidualFieldGates(t *testing.T) {
	const (
		unifiedDeny = "libpod container create denied: raw cgroup v2 settings (unified) are not allowed (set allow_unified_cgroup_settings: true)"
		envHostDeny = "libpod container create denied: inheriting the host environment (env_host) is not allowed (set allow_env_host: true)"
	)
	cases := []struct {
		name string
		opts LibpodContainerCreateOptions
		body string
		want string
	}{
		{"unified denied by default", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","unified":{"memory.max":"max"}}`, unifiedDeny},
		{"unified allowed with opt-in", LibpodContainerCreateOptions{AllowUnifiedCgroupSettings: true}, `{"image":"alpine","systemd":"false","unified":{"memory.max":"max"}}`, ""},
		{"unified spelled in another case is denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","Unified":{"pids.max":"max"}}`, unifiedDeny},
		{"empty unified passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","unified":{}}`, ""},
		{"null unified passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","unified":null}`, ""},
		{"env_host denied by default", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","env_host":true}`, envHostDeny},
		{"env_host allowed with opt-in", LibpodContainerCreateOptions{AllowEnvHost: true}, `{"image":"alpine","systemd":"false","env_host":true}`, ""},
		{"env_host false passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","env_host":false}`, ""},
		{"env_host still refused by env restriction with opt-in", LibpodContainerCreateOptions{AllowEnvHost: true, AllowedEnvVars: []string{"FOO"}},
			`{"image":"alpine","systemd":"false","env_host":true}`, "libpod container create denied: environment policy forbids env_host, httpproxy, secret_env and envmerge"},
		{"r_limits stays ungated like Docker Ulimits", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","r_limits":[{"type":"RLIMIT_NOFILE","soft":1024,"hard":4096}]}`, ""},
		{"pod passes while sharing is unrestricted", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","pod":"p1"}`, ""},
		{"pod denied while sharing is restricted", LibpodContainerCreateOptions{RestrictNamespaceSharing: true, AllowedNamespaceSharingContainers: []string{"p1"}}, `{"image":"alpine","systemd":"false","pod":"p1"}`, "libpod container create denied: joining a pod is not allowed while namespace sharing is restricted"},
		{"empty pod passes while sharing is restricted", LibpodContainerCreateOptions{RestrictNamespaceSharing: true}, `{"image":"alpine","systemd":"false","pod":" "}`, ""},
		{"dependencyContainers is not body-gated", LibpodContainerCreateOptions{RestrictNamespaceSharing: true}, `{"image":"alpine","systemd":"false","dependencyContainers":["c1"]}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectLibpod(t, newLibpodContainerCreatePolicy(tc.opts), []byte(tc.body))
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
