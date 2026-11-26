package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestKomodoDeployPresetConformance pins the Docker Engine API surface behind
// Komodo Periphery v2.3.4's deploy paths. Source: moghtech/komodo at tag
// v2.3.4, bin/periphery/src. Periphery shells out to the docker CLI for every
// write, with DOCKER_HOST inherited:
//
//	Deployment deploy  api/container/run.rs   docker pull, stop and rm the old
//	                                          container, then docker run -d
//	                                          --name --network -p -v --env
//	                                          --restart --label EXTRA_ARGS
//	Container actions  api/container/mod.rs   docker start|restart|stop|rename,
//	                                          docker container rm
//	Stack deploy       api/compose.rs         docker compose up -d, down, stop,
//	                                          restart, pull
//	Network create     api/docker.rs          docker network create, network rm
//
// The Engine routes behind those:
//
//	docker pull                    POST /images/create
//	docker run                     GET /images/{name}/json, POST /containers/create,
//	                               POST /containers/{id}/start
//	docker stop|restart|rename|rm  POST /containers/{id}/stop|restart|rename,
//	                               DELETE /containers/{id}
//	docker network create|rm       POST /networks/create, DELETE /networks/{id}
//	docker compose up|down         the Compose plugin calls pinned by
//	                               TestDockgePresetConformance (create, rename,
//	                               wait, connect, disconnect, volume create)
//
// Builds (a Build resource, or a Stack with run_build) use POST /build,
// /session and /grpc and stay denied, as do exec, attach, image and volume
// removal, pause, prune and Swarm.
func TestKomodoDeployPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "komodo-with-deploy.yaml"))
	if err != nil {
		t.Fatalf("load preset komodo-with-deploy.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("komodo-with-deploy.yaml must acknowledge read exfiltration because Periphery reads container logs")
	}
	if cfg.Ownership.Owner == "" {
		t.Fatal("komodo-with-deploy.yaml must set ownership.owner, it is what bounds Periphery's container creates")
	}

	handler := buildDrydockPresetHandler(t, "komodo-with-deploy.yaml")
	cases := []presetCase{
		// Everything in the komodo monitoring preset stays reachable.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},
		{"containers-list-all", http.MethodGet, "/containers/json?all=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats-once", http.MethodGet, "/containers/abc/stats?stream=false", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs?stdout=1&stderr=1&tail=5000&timestamps=1", "", true},
		{"images-list", http.MethodGet, "/images/json", "", true},
		{"image-inspect-registry-qualified", http.MethodGet, "/images/ghcr.io/moghtech/komodo-periphery:2.3.4/json", "", true},
		{"image-history", http.MethodGet, "/images/nginx/history", "", true},
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect-verbose", http.MethodGet, "/networks/bridge?verbose=true", "", true},
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/data", "", true},

		// Deployment deploy: pull, stop and remove the old container, run.
		{"image-pull", http.MethodPost, "/images/create?fromImage=ghcr.io/owner/app&tag=1.0", "", true},
		{"container-stop-old", http.MethodPost, "/containers/app/stop?t=10", "", true},
		{"container-remove-old", http.MethodDelete, "/containers/app", "", true},
		{"container-create-deployment", http.MethodPost, "/containers/create?name=app", `{"Image":"ghcr.io/owner/app:1.0","HostConfig":{"NetworkMode":"app_net","PortBindings":{"80/tcp":[{"HostPort":"8080"}]},"RestartPolicy":{"Name":"unless-stopped"}}}`, true},
		{"container-create-named-volume", http.MethodPost, "/containers/create?name=app", `{"Image":"nginx","HostConfig":{"Binds":["app_data:/data"]}}`, true},
		{"container-create-komodo-root-bind", http.MethodPost, "/containers/create?name=app", `{"Image":"nginx","HostConfig":{"Binds":["/etc/komodo/stacks/web/data:/data"]}}`, true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},

		// Container actions in the UI.
		{"container-restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"container-rename", http.MethodPost, "/containers/abc/rename?name=abc2", "", true},
		{"container-kill", http.MethodPost, "/containers/abc/kill", "", true},
		{"container-wait", http.MethodPost, "/containers/abc/wait?condition=not-running", "", true},
		{"container-remove-force-and-volumes", http.MethodDelete, "/containers/abc?force=1&v=1", "", true},

		// Network and volume create, Compose attach and teardown.
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"app_net","Driver":"bridge"}`, true},
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		{"network-disconnect-force", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc","Force":true}`, true},
		{"network-remove", http.MethodDelete, "/networks/abc", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"app_data","Driver":"local"}`, true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-container-create", http.MethodPost, "/v1.45/containers/create?name=app", `{"Image":"nginx"}`, true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-image-pull", http.MethodPost, "/v1.45/images/create?fromImage=nginx", "", true},
		{"v-prefixed-network-create", http.MethodPost, "/v1.45/networks/create", `{"Name":"app_net"}`, true},
		{"v-prefixed-volume-create", http.MethodPost, "/v1.45/volumes/create", `{"Name":"app_data"}`, true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/abc?force=1", "", true},

		// Container-create inspection bounds a Deployment's extra_args and a
		// Stack's compose file.
		{"create-privileged-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Privileged":true}}`, false},
		{"create-host-network-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"NetworkMode":"host"}}`, false},
		{"create-host-pid-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"PidMode":"host"}}`, false},
		{"create-host-ipc-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"IpcMode":"host"}}`, false},
		{"create-host-userns-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"UsernsMode":"host"}}`, false},
		{"create-container-pid-join-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"PidMode":"container:abc"}}`, false},
		{"create-container-network-join-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"NetworkMode":"container:abc"}}`, false},
		{"create-cap-add-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"create-device-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda"}]}}`, false},
		{"create-root-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/:/host"]}}`, false},
		{"create-etc-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc:/host-etc:ro"]}}`, false},
		{"create-docker-sock-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"create-komodo-root-traversal-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc/komodo/../shadow:/x"]}}`, false},
		{"create-komodo-sibling-bind-denied", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Binds":["/etc/komodo-evil:/x"]}}`, false},
		{"network-create-custom-driver-denied", http.MethodPost, "/networks/create", `{"Name":"x","Driver":"weave"}`, false},
		{"volume-create-custom-driver-denied", http.MethodPost, "/volumes/create", `{"Name":"x","Driver":"nfs"}`, false},
		{"container-remove-link-denied", http.MethodDelete, "/containers/abc?link=1", "", false},

		// Exec and attach: Periphery terminals and container exec.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1", "", false},

		// Builds stay denied, including the BuildKit session and gRPC tunnel.
		{"build-denied", http.MethodPost, "/build", "", false},
		{"builder-prune-denied", http.MethodPost, "/build/prune", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"grpc-denied", http.MethodPost, "/grpc", "", false},

		// No removal of images or volumes, no prune, no pause.
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-push-denied", http.MethodPost, "/images/nginx/push", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag?repo=x", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},
		{"images-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/app_data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-unpause-denied", http.MethodPost, "/containers/abc/unpause", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-copy-in-denied", http.MethodPut, "/containers/abc/archive?path=/etc", "", false},

		// Registry login (a Deployment or Stack with a registry account).
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},

		// Swarm and the rest of the engine surface.
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
	}

	// Container logs are the sole read-exfiltration route Periphery needs.
	// Reuse the #379 catalog for every other Docker-compat exfiltration path.
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
