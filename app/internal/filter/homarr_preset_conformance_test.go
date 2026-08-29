package filter_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestHomarrPresetConformance pins Homarr v1.76.2's Docker Engine API surface.
// The call sites are packages/request-handler/src/docker.ts (container list,
// inspect, stats and logs) and packages/api/src/router/docker/docker-router.ts
// (start, stop, restart and remove). Homarr does not call an image endpoint or
// Docker metadata endpoint.
//
// It reuses the preset handler and request-case helpers introduced with the
// #379 preset narrowing so the shipped YAML is exercised through the same rule
// and request-body middleware as the earlier conformance suites.
func TestHomarrPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "homarr.yaml"))
	if err != nil {
		t.Fatalf("load preset homarr.yaml: %v", err)
	}
	if !cfg.InsecureAllowReadExfiltration {
		t.Fatal("homarr.yaml must acknowledge read exfiltration because Homarr reads container logs")
	}

	handler := buildDrydockPresetHandler(t, "homarr.yaml")
	cases := []presetCase{
		// Homarr's complete read surface.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs", "", true},

		// Dashboard container controls.
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},
		{"container-remove-force-denied", http.MethodDelete, "/containers/abc?force=true", "", false},
		{"container-remove-volumes-denied", http.MethodDelete, "/containers/abc?v=true", "", false},
		{"container-remove-link-denied", http.MethodDelete, "/containers/abc?link=true", "", false},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-container-stats", http.MethodGet, "/v1.45/containers/abc/stats", "", true},
		{"v-prefixed-container-logs", http.MethodGet, "/v1.45/containers/abc/logs", "", true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/abc", "", true},
		{"v-prefixed-container-remove-force-denied", http.MethodDelete, "/v1.45/containers/abc?force=1", "", false},

		// Homarr does not call Docker metadata endpoints.
		{"ping-get-denied", http.MethodGet, "/_ping", "", false},
		{"ping-head-denied", http.MethodHead, "/_ping", "", false},
		{"version-denied", http.MethodGet, "/version", "", false},
		{"info-denied", http.MethodGet, "/info", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},

		// Other container reads and writes are outside Homarr's call surface.
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-create-denied", http.MethodPost, "/containers/create", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["true"]}`, false},

		// Homarr makes no image API call.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-inspect-denied", http.MethodGet, "/images/nginx/json", "", false},
		{"image-history-denied", http.MethodGet, "/images/nginx/history", "", false},
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=nginx", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},

		// Other resource families stay default-deny.
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
	}

	// Logs are the sole read-exfiltration route Homarr needs. Reuse the #379
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
