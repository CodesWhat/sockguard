package filter_test

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// TestArcaneWithManagementPresetConformance pins the Docker Engine API
// surface of Arcane v3.1.1 (getarcaneapp/arcane) with its management actions
// enabled. On top of the read-only calls pinned by TestArcanePresetConformance
// the call sites are backend/internal/container/service.go (ContainerStart,
// ContainerStop, ContainerRestart, ContainerRename, ContainerCreate,
// ContainerRemove), backend/internal/image/service.go (ImagePull), the
// updater (backend/internal/updater/) and compose projects
// (backend/pkg/projects/). Routes added:
//
//	ContainerCreate      POST /containers/create
//	ContainerStart       POST /containers/{id}/start
//	ContainerStop        POST /containers/{id}/stop
//	ContainerRestart     POST /containers/{id}/restart
//	ContainerRename      POST /containers/{id}/rename
//	ContainerRemove      DELETE /containers/{id}
//	ImagePull            POST /images/create
//	NetworkCreate        POST /networks/create
//	NetworkConnect       POST /networks/{id}/connect
//	NetworkDisconnect    POST /networks/{id}/disconnect
//	NetworkRemove        DELETE /networks/{id}
//	VolumeCreate         POST /volumes/create
//
// Exec, attach, kill, pause, commit, archive, image remove, tag, prune, load
// and build, volume remove and Swarm stay denied.
func TestArcaneWithManagementPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "arcane-with-management.yaml"))
	if err != nil {
		t.Fatalf("load preset arcane-with-management.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("arcane-with-management.yaml must acknowledge read exfiltration because Arcane reads container logs and the process list")
	}
	if cfg.InsecureAllowBodyBlindWrites {
		t.Fatal("arcane-with-management.yaml must not set insecure_allow_body_blind_writes")
	}
	if cfg.Ownership.Owner == "" {
		t.Fatal("arcane-with-management.yaml must set an ownership owner")
	}

	// deny_published_ports is enforced by the resource-limit guard, which
	// serve.go runs after ownership and before the rule layer. Mirror that
	// here so the pin covers it.
	policy := cfg.RequestBody.ToFilterOptions()
	guard := filter.ResourceLimitGuardWithOptions(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		filter.ResourceLimitGuardOptions{PolicyConfig: policy},
	)
	handler := guard(drydockPresetHandlerFromConfig(t, cfg))

	const app = `{"Image":"ghcr.io/example/app:1"`
	cases := []presetCase{
		// Read surface shared with arcane.yaml.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events?since=1700000000.000000000", "", true},
		{"system-df", http.MethodGet, "/system/df?type=container&type=image&type=volume&type=build-cache&verbose=1", "", true},
		{"containers-list", http.MethodGet, "/containers/json?all=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=0", "", true},
		{"container-top", http.MethodGet, "/containers/abc/top?ps_args=-eo+pid%2Cuser%2C%25cpu%2C%25mem%2Cetime%2Ccmd", "", true},
		{"container-top-fallback-args", http.MethodGet, "/containers/abc/top?ps_args=-o+pid%2Cuser%2Cetime%2Cargs", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1&stderr=1&tail=100&timestamps=1", "", true},
		{"images-list", http.MethodGet, "/images/json?all=1", "", true},
		{"image-inspect-bare", http.MethodGet, "/images/nginx/json", "", true},
		{"image-inspect-registry-qualified", http.MethodGet, "/images/ghcr.io/getarcaneapp/arcane:v3.1.1/json", "", true},
		{"image-inspect-digest", http.MethodGet, "/images/sha256:0000000000000000000000000000000000000000000000000000000000000000/json", "", true},
		{"image-history", http.MethodGet, "/images/nginx:latest/history", "", true},
		{"image-history-registry-qualified", http.MethodGet, "/images/ghcr.io/getarcaneapp/arcane:v3.1.1/history", "", true},
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/data", "", true},
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect", http.MethodGet, "/networks/bridge", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-ping", http.MethodGet, "/v1.45/_ping", "", true},
		{"v-prefixed-info", http.MethodGet, "/v1.45/info", "", true},
		{"v-prefixed-events", http.MethodGet, "/v1.45/events", "", true},
		{"v-prefixed-system-df", http.MethodGet, "/v1.45/system/df", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=1", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats", "", true},
		{"v-prefixed-container-top", http.MethodGet, "/v1.45/containers/abc/top?ps_args=-eo+pid%2Cuser%2C%25cpu%2C%25mem%2Cetime%2Ccmd", "", true},
		{"top-ps-args-e-denied", http.MethodGet, "/containers/abc/top?ps_args=e", "", false},
		{"top-ps-args-auxeww-denied", http.MethodGet, "/containers/abc/top?ps_args=auxeww", "", false},
		{"top-ps-args-aux-denied", http.MethodGet, "/containers/abc/top?ps_args=aux", "", false},
		{"top-ps-args-empty-denied", http.MethodGet, "/containers/abc/top?ps_args=", "", false},
		{"top-bare-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"v-prefixed-top-ps-args-e-denied", http.MethodGet, "/v1.45/containers/abc/top?ps_args=e", "", false},
		{"top-ps-args-duplicate-denied", http.MethodGet, "/containers/abc/top?ps_args=-ef&ps_args=e", "", false},
		{"top-ps-args-duplicate-pinned-then-e-denied", http.MethodGet, "/containers/abc/top?ps_args=-eo+pid%2Cuser%2C%25cpu%2C%25mem%2Cetime%2Ccmd&ps_args=e", "", false},
		{"top-ps-args-encoded-key-denied", http.MethodGet, "/containers/abc/top?ps%5Fargs=e", "", false},
		{"top-ps-args-unparseable-denied", http.MethodGet, "/containers/abc/top?ps_args=e;x", "", false},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/abc/logs?follow=1", "", true},
		{"v-prefixed-images-list", http.MethodGet, "/v1.45/images/json", "", true},
		{"v-prefixed-image-inspect", http.MethodGet, "/v1.45/images/docker.io/library/nginx/json", "", true},
		{"v-prefixed-image-history", http.MethodGet, "/v1.45/images/nginx/history", "", true},
		{"v-prefixed-volumes-list", http.MethodGet, "/v1.45/volumes", "", true},
		{"v-prefixed-networks-list", http.MethodGet, "/v1.45/networks", "", true},

		// Management: container lifecycle and the updater.
		{"container-create", http.MethodPost, "/containers/create?name=app", app + `,"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}`, true},
		{"container-create-allowed-bind", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/opt/arcane/projects/app:/data"]}}`, true},
		{"container-create-named-volume", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["appdata:/data"]}}`, true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-stop-timeout", http.MethodPost, "/containers/abc/stop?t=10", "", true},
		{"container-restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"container-rename", http.MethodPost, "/containers/abc/rename?name=app-backup", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},
		{"container-remove-force-volumes", http.MethodDelete, "/containers/abc?force=1&v=1", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=ghcr.io/example/app&tag=1", "", true},
		{"v-prefixed-container-create", http.MethodPost, "/v1.45/containers/create", app + `}`, true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-container-stop", http.MethodPost, "/v1.45/containers/abc/stop", "", true},

		// ?signal= on stop or restart is arbitrary signal delivery.
		{"container-stop-signal-denied", http.MethodPost, "/containers/abc/stop?signal=SIGUSR1&t=5", "", false},
		{"v-prefixed-container-stop-signal-denied", http.MethodPost, "/v1.45/containers/abc/stop?signal=SIGUSR1", "", false},
		{"container-stop-sigstop-freeze-denied", http.MethodPost, "/containers/abc/stop?signal=SIGSTOP&t=-1", "", false},
		{"container-stop-empty-signal-denied", http.MethodPost, "/containers/abc/stop?signal=", "", false},
		{"container-stop-cased-signal-denied", http.MethodPost, "/containers/abc/stop?Signal=SIGUSR1", "", false},
		{"container-restart-signal-denied", http.MethodPost, "/containers/abc/restart?signal=SIGHUP", "", false},
		{"v-prefixed-container-restart-signal-denied", http.MethodPost, "/v1.45/containers/abc/restart?signal=SIGHUP", "", false},
		{"v-prefixed-container-restart", http.MethodPost, "/v1.45/containers/abc/restart", "", true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/abc", "", true},
		{"v-prefixed-image-pull", http.MethodPost, "/v1.45/images/create?fromImage=nginx&tag=latest", "", true},

		// Management: compose project networks and volumes.
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"proj_default"}`, true},
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		{"network-disconnect", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc"}`, true},
		{"network-remove", http.MethodDelete, "/networks/abc", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"proj_data"}`, true},

		// Create policy: the body is inspected.
		{"create-privileged-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Privileged":true}}`, false},
		{"create-bind-root-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/:/host"]}}`, false},
		{"create-bind-outside-allowlist-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/etc:/etc"]}}`, false},
		{"create-bind-prefix-sibling-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/opt/arcane/projects-evil:/data"]}}`, false},
		{"create-bind-traversal-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/opt/arcane/projects/../../../etc:/data"]}}`, false},
		{"create-docker-sock-bind-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"create-mounts-bind-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}`, false},
		{"create-host-network-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"NetworkMode":"host"}}`, false},
		{"create-host-pid-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"PidMode":"host"}}`, false},
		{"create-host-ipc-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"IpcMode":"host"}}`, false},
		{"create-userns-host-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"UsernsMode":"host"}}`, false},
		{"create-cgroupns-host-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"CgroupnsMode":"host"}}`, false},
		{"create-container-netns-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"NetworkMode":"container:victim"}}`, false},
		{"create-container-pidns-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"PidMode":"container:victim"}}`, false},
		{"create-container-ipcns-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"IpcMode":"container:victim"}}`, false},
		{"create-netns-path-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"NetworkMode":"ns:/proc/1/ns/net"}}`, false},
		{"create-cap-add-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"create-device-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}`, false},
		{"create-unconfined-seccomp-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, false},
		{"create-unconfined-apparmor-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, false},
		{"create-sysctl-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`, false},
		{"create-published-port-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"80"}]}}}`, false},
		{"create-publish-all-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"PublishAllPorts":true}}`, false},
		{"create-volumes-from-denied", http.MethodPost, "/containers/create", app + `,"HostConfig":{"VolumesFrom":["other"]}}`, false},
		{"v-prefixed-create-privileged-denied", http.MethodPost, "/v1.45/containers/create", app + `,"HostConfig":{"Privileged":true}}`, false},
		{"libpod-create-denied", http.MethodPost, "/libpod/containers/create", app + `}`, false},
		{"dot-segment-exec-denied", http.MethodPost, "/containers/abc/../abc/exec", `{}`, false},
		{"encoded-slash-archive-denied", http.MethodPut, "/containers/abc%2Farchive?path=/", "", false},

		// Pull policy: import from a URL stays denied.
		{"pull-import-denied", http.MethodPost, "/images/create?fromSrc=http://evil.example.com/x.tar", "", false},

		// Still denied: exec, attach and the other container operations.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-archive-put-denied", http.MethodPut, "/containers/abc/archive?path=/", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"commit-denied", http.MethodPost, "/commit?container=abc", `{}`, false},

		// Still denied: image removal, tagging, prune, load and build.
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag?repo=x", "", false},
		{"image-push-denied", http.MethodPost, "/images/nginx/push", "", false},
		{"image-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"build-prune-denied", http.MethodPost, "/build/prune", "", false},

		// Still denied: volume removal and prunes.
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},

		// Swarm and the remaining surface.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// Logs and the pinned process list are the read-exfiltration routes Arcane needs. Reuse the #379
	// catalog for every other Docker-compat exfiltration path.
	cases = append(cases, systemPathsDeniedCases(app, true)...)

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
