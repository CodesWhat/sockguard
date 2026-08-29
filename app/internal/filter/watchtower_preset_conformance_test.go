package filter_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// TestWatchtowerPresetConformance pins the Docker Engine API surface used by
// nicholas-fedor/watchtower v1.21.2. Watchtower's pkg/container package calls
// the Moby client for ping, info, container list/inspect/lifecycle/create,
// lifecycle-hook exec, image inspect/pull/remove and network connect. It does
// not list images or read the broad container, network, volume or distribution
// families the old preset globs admitted.
//
// The handler reuses the #379 preset helpers. Exec start is the one route whose
// production inspector needs a daemon lookup, so the shared policy hook supplies
// the immutable command metadata that Watchtower's preceding ExecCreate stored.
func TestWatchtowerPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "watchtower.yaml"))
	if err != nil {
		t.Fatalf("load preset watchtower.yaml: %v", err)
	}
	if !cfg.InsecureAllowBodyBlindWrites {
		t.Error("watchtower.yaml must acknowledge arbitrary lifecycle-hook exec commands")
	}
	if cfg.InsecureAllowReadExfiltration {
		t.Error("watchtower.yaml must not acknowledge read exfiltration; Watchtower uses no exfiltration route")
	}

	handler := drydockPresetHandlerFromConfig(t, cfg, func(policy *filter.PolicyConfig) {
		policy.Exec.InspectStart = func(context.Context, string) (filter.ExecInspectResult, bool, error) {
			return filter.ExecInspectResult{
				Command: []string{"sh", "-c", "lifecycle hook"},
				User:    "",
			}, true, nil
		}
	})

	cases := []presetCase{
		// Moby client connection setup and mirror discovery.
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"ping-get-fallback", http.MethodGet, "/_ping", "", true},
		{"info", http.MethodGet, "/info", "", true},

		// Container discovery and lifecycle.
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop", "", true},
		{"container-rename", http.MethodPost, "/containers/abc/rename", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc", "", true},

		// Watchtower recreates inspected containers with the stock runtime. A
		// different explicit runtime must not pass the same create rule.
		{"container-create-runc", http.MethodPost, "/containers/create", `{"Image":"nginx","HostConfig":{"Runtime":"runc"}}`, true},
		{"container-create-other-runtime-denied", http.MethodPost, "/containers/create", `{"Image":"nginx","HostConfig":{"Runtime":"kata"}}`, false},

		// Watchtower only changes RestartPolicy to "no". Resource updates stay
		// behind the body inspector even though the route itself is allowed.
		{"container-update-no-restart", http.MethodPost, "/containers/abc/update", `{"RestartPolicy":{"Name":"no"}}`, true},
		{"container-update-memory-denied", http.MethodPost, "/containers/abc/update", `{"Memory":0}`, false},
		{"container-update-cpu-denied", http.MethodPost, "/containers/abc/update", `{"NanoCpus":2000000000}`, false},

		// Lifecycle-hook exec. Watchtower leaves User empty to use the
		// container's configured user, which Sockguard conservatively treats as
		// root, and sends arbitrary sh -c commands plus WT_CONTAINER metadata.
		{"exec-create", http.MethodPost, "/containers/abc/exec", `{"Tty":true,"Cmd":["sh","-c","lifecycle hook"],"Env":["WT_CONTAINER={}"]}`, true},
		{"exec-start", http.MethodPost, "/exec/def/start", `{"Detach":true,"Tty":true}`, true},
		{"exec-inspect", http.MethodGet, "/exec/def/json", "", true},

		// Image inspect accepts registry-qualified names, but image list must be
		// denied explicitly because Watchtower never calls ImageList.
		{"image-inspect-id", http.MethodGet, "/images/sha256:abc/json", "", true},
		{"image-inspect-qualified", http.MethodGet, "/images/ghcr.io/example/app:latest/json", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=ghcr.io/example/app&tag=latest", "", true},
		{"image-remove", http.MethodDelete, "/images/sha256:abc", "", true},
		{"images-list-explicitly-denied", http.MethodGet, "/images/json", "", false},

		// Recreate attaches secondary networks but does not read or mutate the
		// network collection otherwise.
		{"network-connect", http.MethodPost, "/networks/net1/connect", `{"Container":"abc"}`, true},

		// Version prefixes normalize before matching.
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-update", http.MethodPost, "/v1.45/containers/abc/update", `{"RestartPolicy":{"Name":"no"}}`, true},
		{"v-prefixed-image-inspect", http.MethodGet, "/v1.45/images/ghcr.io/example/app:latest/json", "", true},
		{"v-prefixed-network-connect", http.MethodPost, "/v1.45/networks/net1/connect", `{"Container":"abc"}`, true},

		// Metadata Watchtower does not call.
		{"version-denied", http.MethodGet, "/version", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},

		// Unused container reads and lifecycle operations.
		{"container-stats-denied", http.MethodGet, "/containers/abc/stats", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},
		{"container-changes-denied", http.MethodGet, "/containers/abc/changes", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"container-pause-denied", http.MethodPost, "/containers/abc/pause", "", false},
		{"container-unpause-denied", http.MethodPost, "/containers/abc/unpause", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Unused image operations.
		{"image-history-denied", http.MethodGet, "/images/nginx/history", "", false},
		{"image-attestations-denied", http.MethodGet, "/images/nginx/attestations", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag", "", false},
		{"image-load-denied", http.MethodPost, "/images/load", "", false},
		{"images-prune-denied", http.MethodPost, "/images/prune", "", false},

		// Unused network, volume and distribution operations.
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-inspect-denied", http.MethodGet, "/networks/net1", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", "", false},
		{"network-disconnect-denied", http.MethodPost, "/networks/net1/disconnect", `{"Container":"abc"}`, false},
		{"network-remove-denied", http.MethodDelete, "/networks/net1", "", false},
		{"networks-prune-denied", http.MethodPost, "/networks/prune", "", false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-inspect-denied", http.MethodGet, "/volumes/data", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"data"}`, false},
		{"volume-remove-denied", http.MethodDelete, "/volumes/data", "", false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},
		{"distribution-denied", http.MethodGet, "/distribution/nginx/json", "", false},

		// Other Docker resource families remain default-deny.
		{"build-denied", http.MethodPost, "/build", "", false},
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"tasks-list-denied", http.MethodGet, "/tasks", "", false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"configs-list-denied", http.MethodGet, "/configs", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
	}
	cases = append(cases, exfilDenialCases...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
