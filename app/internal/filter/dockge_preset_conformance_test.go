package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestDockgePresetConformance pins the Docker Engine API surface behind
// Dockge 1.5.0's default stack workflow. Dockge has no Docker client of its
// own. backend/stack.ts and backend/dockge-server.ts spawn the docker CLI:
//
//	docker compose ls --all --format json   (stack status)
//	docker compose ps --format json         (service status)
//	docker compose up -d --remove-orphans   (deploy, update)
//	docker compose down [--remove-orphans]  (stop and remove)
//	docker compose stop | restart | pull
//	docker compose logs -f --tail 100
//	docker compose exec <service> <shell>   (stack shell, refused)
//	docker network ls                       (network picker)
//
// with DOCKER_HOST inherited. The Engine calls behind those are the Compose
// plugin's, read from docker/compose v5.8.0 pkg/compose (create.go, down.go,
// executor_ops.go, restart.go, logs and ps in compose.go, pre_start.go):
//
//	Ping, ServerVersion, Info          GET|HEAD /_ping, GET /version, GET /info
//	ContainerList / ContainerInspect   GET /containers/json, /containers/{id}/json
//	ContainerCreate / Start / Stop     POST /containers/create, /{id}/start, /{id}/stop
//	ContainerRestart / Kill / Rename   POST /containers/{id}/restart, /kill, /rename
//	ContainerWait / ContainerRemove    POST /containers/{id}/wait, DELETE /containers/{id}
//	ContainerLogs                      GET /containers/{id}/logs
//	ImageInspect / ImagePull           GET /images/{name}/json, POST /images/create
//	NetworkList/Inspect/Create         GET /networks, /networks/{id}, POST /networks/create
//	NetworkConnect/Disconnect/Remove   POST /networks/{id}/connect|disconnect, DELETE /networks/{id}
//	VolumeList/Inspect/Create          GET /volumes, /volumes/{name}, POST /volumes/create
//
// Dockge's compose.yaml pins louislam/dockge:1.5.0 at the time of writing.
// Calls outside that set (exec for the shell and hooks, build, image remove
// for down --rmi, volume remove for down -v, copy-to-container for inline
// config content, pause) are refused.
func TestDockgePresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "dockge.yaml"))
	if err != nil {
		t.Fatalf("load preset dockge.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("dockge.yaml must acknowledge read exfiltration because Dockge tails container logs")
	}
	if cfg.Ownership.Owner == "" {
		t.Fatal("dockge.yaml must set ownership.owner, it is what bounds Dockge's container creates")
	}

	handler := buildDrydockPresetHandler(t, "dockge.yaml")
	cases := []presetCase{
		// Engine identity.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// compose ls / ps.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"containers-list-project-filter", http.MethodGet, "/containers/json?all=1&filters=%7B%22label%22%3A%5B%22com.docker.compose.project%3Dweb%22%5D%7D", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=0", "", true},
		{"container-logs-follow", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1&stderr=1&tail=100&timestamps=1", "", true},

		// compose up: image inspect and pull, network, volume, create, start.
		{"image-list", http.MethodGet, "/images/json", "", true},
		{"image-inspect", http.MethodGet, "/images/nginx:latest/json", "", true},
		{"image-inspect-namespaced", http.MethodGet, "/images/ghcr.io/owner/repo:tag/json", "", true},
		{"image-history", http.MethodGet, "/images/nginx/history", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=nginx&tag=latest", "", true},
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect", http.MethodGet, "/networks/web_default", "", true},
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"web_default","Driver":"bridge"}`, true},
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/web_data", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"web_data","Driver":"local"}`, true},
		{"container-create", http.MethodPost, "/containers/create?name=web-app-1", `{"Image":"nginx"}`, true},
		{"container-create-stack-bind", http.MethodPost, "/containers/create?name=web-app-1", `{"Image":"nginx","HostConfig":{"Binds":["/opt/stacks/web/data:/data"]}}`, true},
		{"container-create-named-volume", http.MethodPost, "/containers/create?name=web-app-1", `{"Image":"nginx","HostConfig":{"Binds":["web_data:/data"]}}`, true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},

		// compose up on a changed service: recreate renames the old container.
		{"container-rename", http.MethodPost, "/containers/abc/rename?name=abc_old", "", true},
		{"container-wait", http.MethodPost, "/containers/abc/wait?condition=not-running", "", true},

		// stop, restart, down.
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"container-kill", http.MethodPost, "/containers/abc/kill", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},
		{"container-remove-force-and-volumes", http.MethodDelete, "/containers/abc?force=1&v=1", "", true},
		{"network-disconnect", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc","Force":true}`, true},
		{"network-remove", http.MethodDelete, "/networks/abc", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-ping", http.MethodGet, "/v1.45/_ping", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=1", "", true},
		{"v-prefixed-container-create", http.MethodPost, "/v1.45/containers/create?name=web-app-1", `{"Image":"nginx"}`, true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/abc/logs?follow=1&stdout=1", "", true},
		{"v-prefixed-image-pull", http.MethodPost, "/v1.45/images/create?fromImage=nginx", "", true},
		{"v-prefixed-network-create", http.MethodPost, "/v1.45/networks/create", `{"Name":"web_default"}`, true},
		{"v-prefixed-volume-create", http.MethodPost, "/v1.45/volumes/create", `{"Name":"web_data"}`, true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/abc?force=1", "", true},

		// Container-create inspection bounds a stack deploy.
		{"create-privileged-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Privileged":true}}`, false},
		{"create-host-network-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"NetworkMode":"host"}}`, false},
		{"create-host-pid-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"PidMode":"host"}}`, false},
		{"create-host-ipc-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"IpcMode":"host"}}`, false},
		{"create-cap-add-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"create-device-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda"}]}}`, false},
		{"create-root-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/:/host"]}}`, false},
		{"create-etc-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc:/host-etc:ro"]}}`, false},
		{"create-docker-sock-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"create-stacks-traversal-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/opt/stacks/../../etc:/host-etc"]}}`, false},
		{"create-stacks-sibling-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/opt/stacks-evil:/x"]}}`, false},
		{"network-create-custom-driver-denied", http.MethodPost, "/networks/create", `{"Name":"x","Driver":"weave"}`, false},
		{"volume-create-custom-driver-denied", http.MethodPost, "/volumes/create", `{"Name":"x","Driver":"nfs"}`, false},
		{"container-remove-link-denied", http.MethodDelete, "/containers/abc?link=1", "", false},

		// Exec and attach: the stack shell, Dockge console and hooks.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1", "", false},
		{"container-attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},

		// Other container operations Compose can make but Dockge does not.
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-unpause-denied", http.MethodPost, "/containers/abc/unpause", "", false},
		{"container-copy-in-denied", http.MethodPut, "/containers/abc/archive?path=/etc", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"v-prefixed-container-exec-denied", http.MethodPost, "/v1.45/containers/abc/exec", `{"Cmd":["sh"]}`, false},

		// Images: no build, remove, push or tag.
		{"build-denied", http.MethodPost, "/build", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"grpc-denied", http.MethodPost, "/grpc", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-push-denied", http.MethodPost, "/images/nginx/push", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag?repo=x", "", false},
		{"image-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},

		// Volumes and networks: no removal of volumes, no prune.
		{"volume-remove-denied", http.MethodDelete, "/volumes/web_data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},

		// Swarm and the rest of the engine surface.
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// Logs are the sole read-exfiltration route Dockge needs. Reuse the #379
	// catalog for every other Docker-compat exfiltration path.
	cases = append(cases, systemPathsDeniedCases(`{"Image":"nginx"`, true)...)

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
