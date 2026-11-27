package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestKomodoPresetConformance pins Komodo Periphery v2.3.4's read-only Docker
// Engine API surface. Source: moghtech/komodo at tag v2.3.4, bin/periphery/src.
// The inventory goes through bollard (docker/container.rs list_containers and
// inspect_container, docker/image.rs list_images, inspect_image and
// image_history, docker/network.rs list_networks and inspect_network,
// docker/volume.rs list_volumes and inspect_volume, docker/stats.rs stats with
// stream=false). Stats and logs also shell out to the docker CLI
// (docker/stats.rs "docker stats --no-stream", api/container/mod.rs
// "docker logs"). Calls and the HTTP routes they map to:
//
//	Ping (CLI)                GET|HEAD /_ping
//	Version (CLI)             GET /version
//	list_containers           GET /containers/json (all=true)
//	inspect_container         GET /containers/{id}/json
//	stats                     GET /containers/{id}/stats (stream=false)
//	docker logs               GET /containers/{id}/logs
//	list_images               GET /images/json
//	inspect_image             GET /images/{name}/json
//	image_history             GET /images/{name}/history
//	list_networks             GET /networks
//	inspect_network           GET /networks/{id} (verbose=true)
//	list_volumes              GET /volumes
//	inspect_volume            GET /volumes/{name}
//
// Everything else Periphery does (deploy, stacks, builds, pull, prune, exec,
// attach, Swarm) is a write or a Swarm read and stays denied.
func TestKomodoPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "komodo.yaml"))
	if err != nil {
		t.Fatalf("load preset komodo.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("komodo.yaml must acknowledge read exfiltration because Periphery reads container logs")
	}

	handler := buildDrydockPresetHandler(t, "komodo.yaml")
	cases := []presetCase{
		// Periphery's monitoring read surface.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"containers-list-all", http.MethodGet, "/containers/json?all=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats-once", http.MethodGet, "/containers/abc/stats?stream=false", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs?stdout=1&stderr=1&tail=5000&timestamps=1", "", true},
		{"images-list", http.MethodGet, "/images/json", "", true},
		{"image-inspect-bare", http.MethodGet, "/images/nginx/json", "", true},
		{"image-inspect-registry-qualified", http.MethodGet, "/images/ghcr.io/moghtech/komodo-periphery:2.3.4/json", "", true},
		{"image-history", http.MethodGet, "/images/nginx/history", "", true},
		{"image-history-registry-qualified", http.MethodGet, "/images/ghcr.io/moghtech/komodo-periphery:2.3.4/history", "", true},
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect-verbose", http.MethodGet, "/networks/bridge?verbose=true", "", true},
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/data", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-ping", http.MethodGet, "/v1.45/_ping", "", true},
		{"v-prefixed-version", http.MethodGet, "/v1.45/version", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=1", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats?stream=false", "", true},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/abc/logs?stdout=1", "", true},
		{"v-prefixed-images-list", http.MethodGet, "/v1.45/images/json", "", true},
		{"v-prefixed-image-history", http.MethodGet, "/v1.45/images/nginx/history", "", true},
		{"v-prefixed-networks-list", http.MethodGet, "/v1.45/networks", "", true},
		{"v-prefixed-volumes-list", http.MethodGet, "/v1.45/volumes", "", true},

		// Container writes: deploys and container actions are unsupported.
		{"container-create-denied", http.MethodPost, "/containers/create?name=app", `{"Image":"alpine"}`, false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-unpause-denied", http.MethodPost, "/containers/abc/unpause", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"v-prefixed-container-start-denied", http.MethodPost, "/v1.45/containers/abc/start", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Exec and attach: Periphery terminals and container exec.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1", "", false},

		// Other container reads are outside Periphery's call surface.
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-archive-denied", http.MethodGet, "/containers/abc/archive?path=/etc", "", false},
		{"container-export-denied", http.MethodGet, "/containers/abc/export", "", false},

		// Images: no pull, remove, prune, build or export.
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"images-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"builder-prune-denied", http.MethodPost, "/build/prune", "", false},

		// Volumes and networks: reads only.
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},
		{"network-connect-denied", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, false},
		{"network-remove-denied", http.MethodDelete, "/networks/abc", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},

		// Engine reads Periphery does not make.
		{"info-denied", http.MethodGet, "/info", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},

		// Swarm: Periphery's Swarm features are unsupported.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"service-logs-denied-swarm", http.MethodGet, "/services/abc/logs", "", false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},
		{"swarm-inspect-denied", http.MethodGet, "/swarm", "", false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},

		// Remaining engine surface.
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
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
