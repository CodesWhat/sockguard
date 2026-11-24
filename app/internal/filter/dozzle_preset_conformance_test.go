package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// TestDozzlePresetConformance pins Dozzle v11.5.0's default read-only Docker
// Engine API surface. The call sites are internal/container/docker/client.go
// (Ping, Info and ServerVersion on connect; ContainerList, ContainerInspect,
// ContainerLogs, ContainerStats and Events at runtime) and
// internal/container/docker/stats_collector.go (the events stream that starts
// per-container stats). Calls and the HTTP routes they map to:
//
//	Ping                     GET|HEAD /_ping
//	Info                     GET /info
//	ServerVersion            GET /version
//	ContainerList            GET /containers/json (all=1, optional size=1)
//	ContainerInspect         GET /containers/{id}/json (optional size=1)
//	ContainerLogs            GET /containers/{id}/logs (follow, tail, since, until, timestamps)
//	ContainerStats           GET /containers/{id}/stats (stream=1)
//	Events                   GET /events
//
// Calls outside the default view are gated by DOZZLE_ENABLE_ACTIONS (start,
// stop, restart, remove, image pull/swap), DOZZLE_ENABLE_SHELL (exec, attach),
// swarm control (ServiceList for service labels), the disk-usage readout
// (GET /system/df) and volume/network inspects. The base preset denies all of
// them.
func TestDozzlePresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "dozzle.yaml"))
	if err != nil {
		t.Fatalf("load preset dozzle.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("dozzle.yaml must acknowledge read exfiltration because Dozzle reads container logs")
	}

	handler := buildDrydockPresetHandler(t, "dozzle.yaml")
	cases := []presetCase{
		// Dozzle's complete default read surface.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"containers-list-all", http.MethodGet, "/containers/json?all=1", "", true},
		{"containers-list-size", http.MethodGet, "/containers/json?all=1&size=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-inspect-size", http.MethodGet, "/containers/abc/json?size=1", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=1", "", true},
		{"container-logs-follow", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1&stderr=1&tail=100&timestamps=1", "", true},
		{"container-logs-range", http.MethodGet, "/containers/abc/logs?stdout=1&stderr=1&timestamps=1&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-ping", http.MethodGet, "/v1.45/_ping", "", true},
		{"v-prefixed-version", http.MethodGet, "/v1.45/version", "", true},
		{"v-prefixed-info", http.MethodGet, "/v1.45/info", "", true},
		{"v-prefixed-events", http.MethodGet, "/v1.45/events", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=1", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats", "", true},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/abc/logs?follow=1&stdout=1", "", true},

		// Container writes: DOZZLE_ENABLE_ACTIONS is not supported.
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"v-prefixed-container-start-denied", http.MethodPost, "/v1.45/containers/abc/start", "", false},
		{"v-prefixed-container-remove-denied", http.MethodDelete, "/v1.45/containers/abc", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Exec and attach: DOZZLE_ENABLE_SHELL is not supported.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1", "", false},
		{"container-attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},

		// Other container reads are outside Dozzle's call surface.
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-archive-denied", http.MethodGet, "/containers/abc/archive?path=/etc", "", false},
		{"container-export-denied", http.MethodGet, "/containers/abc/export", "", false},

		// Images: no pull, inspect or list in the base preset.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-inspect-denied", http.MethodGet, "/images/nginx/json", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},

		// Volumes, networks, disk usage.
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-inspect-denied", http.MethodGet, "/volumes/data", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-inspect-denied", http.MethodGet, "/networks/bridge", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},
		{"network-connect-denied", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, false},
		{"network-remove-denied", http.MethodDelete, "/networks/abc", "", false},

		// Swarm: mode is untested, so its reads and writes stay denied.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"service-update-denied", http.MethodPost, "/services/abc/update?version=1", `{}`, false},
		{"service-logs-denied", http.MethodGet, "/services/abc/logs", "", false},
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

	// Logs are the sole read-exfiltration route Dozzle needs. Reuse the #379
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
