package filter_test

import (
	"net/http"
	"testing"
)

// TestDozzleActionsPresetConformance pins what dozzle-with-actions.yaml adds
// for DOZZLE_ENABLE_ACTIONS in Dozzle v11.5.0. The container buttons go
// through POST /api/hosts/{host}/containers/{id}/actions/{action}
// (internal/web/routes.go, internal/web/actions.go), which calls
// Client.ContainerActions in internal/container/docker/client.go:
//
//	start    ContainerStart    POST /containers/{id}/start
//	stop     ContainerStop     POST /containers/{id}/stop
//	restart  ContainerRestart  POST /containers/{id}/restart
//	remove   ContainerRemove   DELETE /containers/{id}
//
// The server route accepts "remove", but the UI types the action as
// "start" | "stop" | "restart" only (assets/composable/containers/containerActions.ts)
// and the bulk actions are the same three, so the preset leaves remove denied.
// The same flag also turns on the image-update flow (ImagePull, ContainerCreate,
// ContainerRemove), prune and self-update; all of those stay denied.
func TestDozzleActionsPresetConformance(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "dozzle-with-actions.yaml")
	cases := []presetCase{
		// Everything in the base preset still works.
		{"ping", http.MethodGet, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},
		{"containers-list", http.MethodGet, "/containers/json?all=1", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats?stream=1", "", true},
		{"container-logs", http.MethodGet, "/containers/abc/logs?follow=1&stdout=1&stderr=1", "", true},

		// The three actions Dozzle's UI offers.
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-restart", http.MethodPost, "/containers/abc/restart", "", true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-container-stop", http.MethodPost, "/v1.45/containers/abc/stop", "", true},
		{"v-prefixed-container-restart", http.MethodPost, "/v1.45/containers/abc/restart", "", true},

		// Wrong methods on the action paths.
		{"container-start-get-denied", http.MethodGet, "/containers/abc/start", "", false},
		{"container-stop-delete-denied", http.MethodDelete, "/containers/abc/stop", "", false},

		// Remove exists in Dozzle's route but not its UI: denied.
		{"container-remove-denied", http.MethodDelete, "/containers/abc", "", false},
		{"container-remove-force-denied", http.MethodDelete, "/containers/abc?force=1&v=1", "", false},
		{"v-prefixed-container-remove-denied", http.MethodDelete, "/v1.45/containers/abc", "", false},

		// Other container writes stay denied.
		{"container-create-denied", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Exec and attach stay denied: the shell is a separate variant.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["sh"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{}`, false},
		{"exec-resize-denied", http.MethodPost, "/exec/abc/resize?h=40&w=100", "", false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1&stdin=1", "", false},

		// The image-update flow and prune buttons.
		{"image-pull-denied", http.MethodPost, "/images/create?fromImage=amir20/dozzle&tag=latest", "", false},
		{"image-inspect-denied", http.MethodGet, "/images/nginx/json", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"images-prune-denied", http.MethodPost, "/images/prune", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"build-prune-denied", http.MethodPost, "/build/prune", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"service-update-denied", http.MethodPost, "/services/abc/update?version=1", `{}`, false},
	}

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
