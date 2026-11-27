package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestWoodpeckerPresetConformance pins the Docker Engine API surface of the
// Woodpecker agent's docker backend at v3.21.0. The call sites are
// pipeline/backend/docker/docker.go (Load, SetupWorkflow, StartStep, WaitStep,
// TailStep, DestroyStep, DestroyWorkflow) and pipeline/backend/docker/convert.go
// (the container Config and HostConfig the create call carries). Calls and the
// HTTP routes they map to:
//
//	client.New (negotiation)  GET|HEAD /_ping
//	Info                      GET /info
//	VolumeCreate              POST /volumes/create
//	NetworkCreate             POST /networks/create
//	ImagePull                 POST /images/create?fromImage=...&tag=...
//	ContainerCreate           POST /containers/create?name=wp_<uuid>
//	NetworkConnect            POST /networks/{name}/connect
//	ContainerStart            POST /containers/{id}/start
//	ContainerWait             POST /containers/{id}/wait
//	ContainerInspect          GET /containers/{id}/json
//	ContainerLogs             GET /containers/{id}/logs (follow, stdout, stderr)
//	ContainerStop             POST /containers/{id}/stop?t=N
//	ContainerKill             POST /containers/{id}/kill?signal=9
//	ContainerRemove           DELETE /containers/{id}?v=1
//	VolumeRemove              DELETE /volumes/{name}?force=1
//	NetworkRemove             DELETE /networks/{name}
//
// The backend never execs, attaches, lists containers or reads stats. Privileged
// steps, host namespaces, devices, host bind mounts and extra_hosts are refused
// by the create policy, so those workflows are unsupported.
func TestWoodpeckerPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "woodpecker.yaml"))
	if err != nil {
		t.Fatalf("load preset woodpecker.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("woodpecker.yaml must acknowledge read exfiltration because the agent streams container logs")
	}
	if cfg.Ownership.Owner == "" {
		t.Fatal("woodpecker.yaml must set ownership.owner so the agent is bound to its own resources")
	}

	// Published ports are refused by the resource-limit guard that serve.go
	// wires in after the filter, which this harness does not build, so pin the
	// setting rather than the verdict.
	if !cfg.RequestBody.ContainerCreate.DenyPublishedPorts {
		t.Fatal("woodpecker.yaml must set request_body.container_create.deny_published_ports")
	}

	stepBody := `{"Image":"alpine:3","Labels":{"wp_uuid":"u","wp_step":"build"},"WorkingDir":"/woodpecker/src","AttachStdout":true,"AttachStderr":true,"Env":["CI=woodpecker"],"Entrypoint":["/bin/sh","-c","echo ok"],"HostConfig":{"Binds":["wp_01abc:/woodpecker/src"],"LogConfig":{"Type":"json-file"},"Tmpfs":{"/tmp":""},"DNS":["1.1.1.1"],"Memory":536870912}}`

	handler := buildDrydockPresetHandler(t, "woodpecker.yaml")
	cases := []presetCase{
		// The agent's complete call surface.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"wp_01abc","Driver":"local"}`, true},
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"wp_net_01abc","Driver":"bridge","EnableIPv6":false}`, true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=alpine&tag=3", "", true},
		{"image-pull-registry", http.MethodPost, "/images/create?fromImage=ghcr.io%2Fowner%2Fimg&tag=1", "", true},
		{"container-create", http.MethodPost, "/containers/create?name=wp_01abc", stepBody, true},
		{"network-connect", http.MethodPost, "/networks/wp_net_01abc/connect", `{"Container":"wp_01abc","EndpointConfig":{"Aliases":["db"]}}`, true},
		{"container-start", http.MethodPost, "/containers/wp_01abc/start", "", true},
		{"container-wait", http.MethodPost, "/containers/wp_01abc/wait", "", true},
		{"container-inspect", http.MethodGet, "/containers/wp_01abc/json", "", true},
		{"container-logs", http.MethodGet, "/containers/wp_01abc/logs?follow=1&stdout=1&stderr=1", "", true},
		{"container-stop", http.MethodPost, "/containers/wp_01abc/stop?t=10", "", true},
		{"container-kill", http.MethodPost, "/containers/wp_01abc/kill?signal=9", "", true},
		{"container-remove", http.MethodDelete, "/containers/wp_01abc?v=1", "", true},
		{"volume-remove", http.MethodDelete, "/volumes/wp_01abc?force=1", "", true},
		{"network-remove", http.MethodDelete, "/networks/wp_net_01abc", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-ping", http.MethodGet, "/v1.45/_ping", "", true},
		{"v-prefixed-info", http.MethodGet, "/v1.45/info", "", true},
		{"v-prefixed-volume-create", http.MethodPost, "/v1.45/volumes/create", `{"Name":"wp_01abc","Driver":"local"}`, true},
		{"v-prefixed-network-create", http.MethodPost, "/v1.45/networks/create", `{"Name":"wp_net_01abc","Driver":"bridge"}`, true},
		{"v-prefixed-image-pull", http.MethodPost, "/v1.45/images/create?fromImage=alpine&tag=3", "", true},
		{"v-prefixed-container-create", http.MethodPost, "/v1.45/containers/create?name=wp_01abc", stepBody, true},
		{"v-prefixed-network-connect", http.MethodPost, "/v1.45/networks/wp_net_01abc/connect", `{"Container":"wp_01abc"}`, true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/wp_01abc/start", "", true},
		{"v-prefixed-container-wait", http.MethodPost, "/v1.45/containers/wp_01abc/wait", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/wp_01abc/json", "", true},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/wp_01abc/logs?follow=1&stdout=1&stderr=1", "", true},
		{"v-prefixed-container-stop", http.MethodPost, "/v1.45/containers/wp_01abc/stop?t=10", "", true},
		{"v-prefixed-container-kill", http.MethodPost, "/v1.45/containers/wp_01abc/kill?signal=9", "", true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/wp_01abc?v=1", "", true},
		{"v-prefixed-volume-remove", http.MethodDelete, "/v1.45/volumes/wp_01abc?force=1", "", true},
		{"v-prefixed-network-remove", http.MethodDelete, "/v1.45/networks/wp_net_01abc", "", true},

		// Create policy: privileged steps and host access are unsupported.
		{"create-privileged-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, false},
		{"create-host-network-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`, false},
		{"create-host-pid-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"PidMode":"host"}}`, false},
		{"create-host-ipc-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"IpcMode":"host"}}`, false},
		{"create-docker-sock-bind-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"create-host-root-bind-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Binds":["/:/host"]}}`, false},
		{"create-device-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}`, false},
		{"create-cap-add-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"create-sysctl-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`, false},
		{"create-extra-hosts-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"ExtraHosts":["db:10.0.0.2"]}}`, false},
		{"create-unconfined-seccomp-denied", http.MethodPost, "/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, false},
		{"v-prefixed-create-privileged-denied", http.MethodPost, "/v1.45/containers/create?name=wp_x", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, false},
		{"container-remove-force-denied", http.MethodDelete, "/containers/wp_01abc?force=1", "", false},

		// Exec, attach, stats and other container operations are outside the backend.
		{"exec-create-denied", http.MethodPost, "/containers/wp_01abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/wp_01abc/attach?stream=1&stdin=1", "", false},
		{"container-list-denied", http.MethodGet, "/containers/json", "", false},
		{"container-stats-denied", http.MethodGet, "/containers/wp_01abc/stats", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/wp_01abc/restart", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/wp_01abc/rename?name=x", "", false},
		{"container-update-denied", http.MethodPost, "/containers/wp_01abc/update", `{}`, false},
		{"container-top-denied", http.MethodGet, "/containers/wp_01abc/top", "", false},
		{"container-archive-denied", http.MethodGet, "/containers/wp_01abc/archive?path=/etc", "", false},
		{"container-export-denied", http.MethodGet, "/containers/wp_01abc/export", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},

		// Images: pull only. No build, list, inspect, remove or push.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-inspect-denied", http.MethodGet, "/images/alpine/json", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/alpine", "", false},
		{"image-push-denied", http.MethodPost, "/images/alpine/push", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},

		// Volumes and networks: the agent writes its own, reads nothing.
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-inspect-denied", http.MethodGet, "/volumes/wp_01abc", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-inspect-denied", http.MethodGet, "/networks/wp_net_01abc", "", false},
		{"network-disconnect-denied", http.MethodPost, "/networks/wp_net_01abc/disconnect", `{"Container":"abc"}`, false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},

		// Swarm and the rest of the engine surface.
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// Logs are the one read-exfiltration route the agent needs. Reuse the #379
	// catalog for every other Docker-compat exfiltration path.
	cases = append(cases, systemPathsDeniedCases(`{"Image":"alpine:3"`, true)...)

	for _, c := range exfilDenialCases {
		if c.name == "logs-denied" || c.name == "v-prefixed-logs-denied" {
			continue
		}
		cases = append(cases, c)
	}

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
