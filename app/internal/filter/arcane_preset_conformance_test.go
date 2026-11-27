package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestArcanePresetConformance pins the Docker Engine API surface of Arcane
// v3.1.1 (getarcaneapp/arcane) for its read-only view. The call sites are
// backend/internal/docker/service.go (Ping, ServerVersion, Info, Events,
// ContainerList, ImageList, DiskUsage, VolumeList),
// backend/internal/container/service.go (ContainerInspect, ContainerTop,
// ContainerLogs), backend/internal/container/children/stats/service.go
// (ContainerStats), backend/internal/image/service.go (ImageInspect,
// ImageHistory) and the volume and network services (VolumeInspect,
// NetworkList, NetworkInspect). Calls and the HTTP routes they map to:
//
//	Ping                     GET|HEAD /_ping
//	ServerVersion            GET /version
//	Info                     GET /info
//	Events                   GET /events
//	DiskUsage                GET /system/df
//	ContainerList            GET /containers/json
//	ContainerInspect         GET /containers/{id}/json
//	ContainerStats           GET /containers/{id}/stats
//	ContainerTop             GET /containers/{id}/top
//	ContainerLogs            GET /containers/{id}/logs
//	ImageList                GET /images/json
//	ImageInspect             GET /images/{name}/json
//	ImageHistory             GET /images/{name}/history
//	VolumeList|VolumeInspect GET /volumes, /volumes/{name}
//	NetworkList|Inspect      GET /networks, /networks/{id}
//
// Everything else Arcane can call (container create/start/stop/restart/
// remove/rename/wait, ImagePull, ImageRemove, prunes, volume and network
// writes, Swarm, secrets and configs, exec for projects) needs a write or a
// Swarm read and stays denied.
func TestArcanePresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "arcane.yaml"))
	if err != nil {
		t.Fatalf("load preset arcane.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("arcane.yaml must acknowledge read exfiltration because Arcane reads container logs and the process list")
	}

	handler := buildDrydockPresetHandler(t, "arcane.yaml")
	cases := []presetCase{
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

		// Container writes: actions, the updater and redeploys are unsupported.
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"v-prefixed-container-start-denied", http.MethodPost, "/v1.45/containers/abc/start", "", false},
		{"v-prefixed-container-remove-denied", http.MethodDelete, "/v1.45/containers/abc", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"container-commit-denied", http.MethodPost, "/commit?container=abc", "", false},

		// Exec, attach and the other container reads.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1", "", false},
		{"container-attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-archive-denied", http.MethodGet, "/containers/abc/archive?path=/etc", "", false},
		{"container-export-denied", http.MethodGet, "/containers/abc/export", "", false},

		// Images: no pull, remove, tag, prune, build, save/load or search.
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag?repo=x", "", false},
		{"image-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},
		{"image-search-denied", http.MethodGet, "/images/search?term=nginx", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"build-prune-denied", http.MethodPost, "/build/prune", "", false},
		{"distribution-denied", http.MethodGet, "/distribution/nginx/json", "", false},

		// Volume and network writes.
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},
		{"network-connect-denied", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, false},
		{"network-disconnect-denied", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc"}`, false},
		{"network-remove-denied", http.MethodDelete, "/networks/abc", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},

		// Swarm: untested, so its reads and writes stay denied.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},
		{"swarm-inspect-denied", http.MethodGet, "/swarm", "", false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},

		// Remaining engine surface.
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// Logs and the pinned process list are the read-exfiltration routes Arcane needs. Reuse the #379
	// catalog for every other Docker-compat exfiltration path.
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
