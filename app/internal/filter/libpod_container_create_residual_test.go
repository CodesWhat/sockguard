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

func TestLibpodContainerCreateStorageOptsAndRuntimeAnnotationGates(t *testing.T) {
	const storageDeny = "libpod container create denied: storage_opts is not allowed (set allow_storage_opts: true)"
	annotationDeny := func(key string) string {
		return `libpod container create denied: runtime annotation "` + key + `" is not allowed (set allow_runtime_annotations: true)`
	}
	cases := []struct {
		name string
		opts LibpodContainerCreateOptions
		body string
		want string
	}{
		{"storage_opts denied by default", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","storage_opts":{"size":"1T"}}`, storageDeny},
		{"storage_opts allowed with opt-in", LibpodContainerCreateOptions{AllowStorageOpts: true}, `{"image":"alpine","systemd":"false","storage_opts":{"size":"1T"}}`, ""},
		{"storage_opts spelled in another case is denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","Storage_Opts":{"size":"1T"}}`, storageDeny},
		{"empty storage_opts passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","storage_opts":{}}`, ""},
		{"null storage_opts passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","storage_opts":null}`, ""},
		{"run.oci annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.keep_original_groups":"1"}}`, annotationDeny("run.oci.keep_original_groups")},
		{"run.oci annotation in another case is denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"RUN.OCI.handler":"wasm"}}`, annotationDeny("RUN.OCI.handler")},
		{"io.podman.annotations markers pass, podman-remote sends them", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.seccomp":"unconfined","io.podman.annotations.userns":"private","io.podman.annotations.pids-limit":"100"}}`, ""},
		{"first sorted runtime key is reported", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.b":"1","run.oci.a":"1","org.example":"x"}}`, annotationDeny("run.oci.a")},
		{"cid-file annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.cid-file":"/etc/passwd"}}`, annotationDeny("io.podman.annotations.cid-file")},
		{"autoremove annotation denied", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.autoremove":"TRUE"}}`, annotationDeny("io.podman.annotations.autoremove")},
		{"autoremove-image annotation denied in another case", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"IO.Podman.Annotations.Autoremove-Image":"true"}}`, annotationDeny("IO.Podman.Annotations.Autoremove-Image")},
		{"acted annotations allowed with opt-in", LibpodContainerCreateOptions{AllowRuntimeAnnotations: true}, `{"image":"alpine","systemd":"false","annotations":{"io.podman.annotations.cid-file":"/x","io.podman.annotations.autoremove":"true"}}`, ""},
		{"runtime annotations allowed with opt-in", LibpodContainerCreateOptions{AllowRuntimeAnnotations: true}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.keep_original_groups":"1"}}`, ""},
		{"plain annotation passes", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{"org.example.team":"a","io.podman":"x","run.ocix":"y"}}`, ""},
		{"empty annotations pass", LibpodContainerCreateOptions{}, `{"image":"alpine","systemd":"false","annotations":{}}`, ""},
		{"storage_opts opt-in does not open annotations", LibpodContainerCreateOptions{AllowStorageOpts: true}, `{"image":"alpine","systemd":"false","annotations":{"run.oci.handler":"x"}}`, annotationDeny("run.oci.handler")},
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
