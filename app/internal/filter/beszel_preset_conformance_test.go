package filter_test

import (
	"net/http"
	"testing"
)

// TestBeszelPresetConformance pins the Beszel agent v0.21.2 default Docker
// Engine API surface, read from agent/docker.go (version probe, container
// list, stats, inspect, info) and agent/docker_registry.go (image inspect for
// update checks) at tag v0.21.2 of henrygd/beszel. The agent sends no API
// version prefix. Calls and the HTTP routes they map to:
//
//	checkDockerVersion       GET /version
//	getDockerStats           GET /containers/json
//	updateContainerStats     GET /containers/{id}/stats?stream=0&one-shot=1
//	getPodmanContainerHealth GET /containers/{id}/json
//	getContainerInfo         GET /containers/{id}/json (hub details view)
//	GetHostInfo              GET /info
//	inspectImageDigests      GET /images/{escaped-ref}/json
//
// The hub's container log view (getLogs, GET /containers/{id}/logs) is a
// read-exfiltration route and stays denied in the base preset.
func TestBeszelPresetConformance(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "beszel.yaml")
	cases := []presetCase{
		// The agent's default surface, bare.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc123def456/stats?stream=0&one-shot=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc123def456/json", "", true},
		{"image-inspect", http.MethodGet, "/images/nginx:latest/json", "", true},
		{"image-inspect-escaped-slashes", http.MethodGet, "/images/ghcr.io%2Fowner%2Fapp:1.0/json", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-version", http.MethodGet, "/v1.45/version", "", true},
		{"v-prefixed-info", http.MethodGet, "/v1.45/info", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats?stream=0&one-shot=1", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-image-inspect", http.MethodGet, "/v1.45/images/nginx:latest/json", "", true},

		// Logs: the hub log view is unsupported by the base preset.
		{"container-logs-denied", http.MethodGet, "/containers/abc/logs?timestamps=1&stdout=1&stderr=1&tail=1000", "", false},
		{"v-prefixed-container-logs-denied", http.MethodGet, "/v1.45/containers/abc/logs?stdout=1", "", false},

		// Container writes and other container reads.
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-archive-denied", http.MethodGet, "/containers/abc/archive?path=/etc", "", false},
		{"container-export-denied", http.MethodGet, "/containers/abc/export", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"v-prefixed-container-start-denied", http.MethodPost, "/v1.45/containers/abc/start", "", false},

		// Images: inspect only.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-get-denied", http.MethodGet, "/images/nginx/get", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},

		// Volumes, networks, disk usage, swarm.
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
	}

	// Beszel needs no read-exfiltration route, so every catalog entry
	// including logs stays denied.
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
