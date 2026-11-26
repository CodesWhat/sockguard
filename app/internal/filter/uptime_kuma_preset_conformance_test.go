package filter_test

import (
	"net/http"
	"testing"
)

// TestUptimeKumaPresetConformance pins Uptime Kuma 2.5.12's Docker Engine API
// surface (latest stable release tag at the time of writing). The call sites
// are server/model/monitor.js (the "docker" monitor type, one request per
// check) and server/docker.js (DockerHost.testDockerHost, run by the Docker
// Host "Test" button). Both use plain axios requests, with no ping, version
// negotiation or other call. Calls and the HTTP routes they map to:
//
//	Monitor check            GET /containers/{name}/json
//	Docker Host test         GET /containers/json?all=true
//
// Uptime Kuma has no container actions, logs, events or stats features, so
// the base preset denies everything else.
func TestUptimeKumaPresetConformance(t *testing.T) {
	assertPresetDoesNotAckReadExfiltration(t, "uptime-kuma.yaml")
	handler := buildDrydockPresetHandler(t, "uptime-kuma.yaml")

	cases := []presetCase{
		// Uptime Kuma's complete Docker surface.
		{"containers-list-all", http.MethodGet, "/containers/json?all=true", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-inspect-name", http.MethodGet, "/containers/my-app_1/json", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=true", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},

		// Reads outside Uptime Kuma's call surface.
		{"ping-denied", http.MethodGet, "/_ping", "", false},
		{"ping-head-denied", http.MethodHead, "/_ping", "", false},
		{"version-denied", http.MethodGet, "/version", "", false},
		{"info-denied", http.MethodGet, "/info", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"container-stats-denied", http.MethodGet, "/containers/abc/stats", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"v-prefixed-container-stats-denied", http.MethodGet, "/v1.45/containers/abc/stats", "", false},

		// Container writes.
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-stop-denied", http.MethodPost, "/containers/abc/stop", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},
		{"v-prefixed-container-start-denied", http.MethodPost, "/v1.45/containers/abc/start", "", false},

		// Inspect is read-only: other methods on the same path stay denied.
		{"container-inspect-post-denied", http.MethodPost, "/containers/abc/json", "", false},

		// Exec and attach.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},

		// Images, volumes, networks, disk usage.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-inspect-denied", http.MethodGet, "/images/nginx/json", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},

		// Swarm.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
		{"nodes-list-denied", http.MethodGet, "/nodes", "", false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},

		// Remaining engine surface.
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// Uptime Kuma never reads logs, so the whole #379 exfiltration catalog
	// must stay denied.
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
