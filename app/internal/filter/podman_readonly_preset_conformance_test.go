package filter_test

import (
	"net/http"
	"testing"
)

// TestPodmanReadonlyPresetConformance fires representative requests at a
// filter chain built from the shipped podman-readonly.yaml preset (#148 PR7),
// asserting the read-only monitoring posture actually holds on both of
// Podman's API surfaces: the Docker-compat `/vN.NN/...` paths and the native
// `/libpod/...` paths. It reuses the presetCase/buildDrydockPresetHandler/
// fireDrydockCase helpers from drydock_preset_conformance_test.go (same
// package, same conventions) rather than duplicating them.
//
// Three things this test exists to pin:
//
//   - Both surfaces admit the same shape of narrow list/inspect/metadata
//     reads (container/pod/image/network/volume/secret list + inspect,
//     health + version + info + events), so operators get one preset for a
//     Podman host regardless of which API family their monitoring tool uses.
//   - Every path in the exfiltration-gated catalogs
//     (sensitiveExfilEndpoints in internal/cmd/rules.go — archive, export,
//     logs, attach, images/get, images/push, generate/kube, manifest
//     registry pushes, on both surfaces) stays denied, proving the preset
//     never needed insecure_allow_read_exfiltration: true.
//   - No write reaches upstream on either surface — including libpod-only
//     writes with no Docker-compat analog, like pod create and play/kube.
func TestPodmanReadonlyPresetConformance(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "podman-readonly.yaml")

	cases := []presetCase{
		// --- Docker-compat: health + metadata ---
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"info", http.MethodGet, "/info", "", true},
		{"events", http.MethodGet, "/events", "", true},

		// --- Docker-compat: container reads ---
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"container-stats", http.MethodGet, "/containers/abc/stats", "", true},
		{"container-top", http.MethodGet, "/containers/abc/top", "", true},
		{"container-changes", http.MethodGet, "/containers/abc/changes", "", true},

		// --- Docker-compat: image reads ---
		{"images-list", http.MethodGet, "/images/json", "", true},
		{"image-inspect", http.MethodGet, "/images/abc/json", "", true},
		{"image-history", http.MethodGet, "/images/abc/history", "", true},

		// --- Docker-compat: network + volume reads ---
		{"networks-list", http.MethodGet, "/networks", "", true},
		{"network-inspect", http.MethodGet, "/networks/abc", "", true},
		{"volumes-list", http.MethodGet, "/volumes", "", true},
		{"volume-inspect", http.MethodGet, "/volumes/abc", "", true},

		// --- Docker-compat: denied exfiltration surface ---
		{"archive-denied", http.MethodGet, "/containers/abc/archive", "", false},
		{"export-denied", http.MethodGet, "/containers/abc/export", "", false},
		{"logs-denied", http.MethodGet, "/containers/abc/logs", "", false},
		{"attach-ws-denied", http.MethodGet, "/containers/abc/attach/ws", "", false},
		{"attach-denied", http.MethodPost, "/containers/abc/attach", "", false},
		{"images-get-denied", http.MethodGet, "/images/get", "", false},
		{"image-get-denied", http.MethodGet, "/images/abc/get", "", false},
		{"image-push-denied", http.MethodPost, "/images/abc/push", "", false},

		// --- Docker-compat: denied writes ---
		{"container-create-denied", http.MethodPost, "/containers/create", "", false},
		{"container-start-denied", http.MethodPost, "/containers/abc/start", "", false},
		{"container-delete-denied", http.MethodDelete, "/containers/abc", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},

		// --- libpod: health + metadata ---
		{"libpod-ping-get", http.MethodGet, "/libpod/_ping", "", true},
		{"libpod-ping-head", http.MethodHead, "/libpod/_ping", "", true},
		{"libpod-version", http.MethodGet, "/libpod/version", "", true},
		{"libpod-info", http.MethodGet, "/libpod/info", "", true},
		{"libpod-events", http.MethodGet, "/libpod/events", "", true},

		// --- libpod: container reads ---
		{"libpod-containers-list", http.MethodGet, "/libpod/containers/json", "", true},
		{"libpod-container-inspect", http.MethodGet, "/libpod/containers/abc/json", "", true},
		{"libpod-container-stats", http.MethodGet, "/libpod/containers/abc/stats", "", true},
		{"libpod-container-top", http.MethodGet, "/libpod/containers/abc/top", "", true},
		{"libpod-container-changes", http.MethodGet, "/libpod/containers/abc/changes", "", true},

		// --- libpod: pod reads (no Docker-compat equivalent) ---
		{"libpod-pods-list", http.MethodGet, "/libpod/pods/json", "", true},
		{"libpod-pod-inspect", http.MethodGet, "/libpod/pods/abc/json", "", true},
		{"libpod-pods-stats", http.MethodGet, "/libpod/pods/stats", "", true},

		// --- libpod: image reads ---
		{"libpod-images-list", http.MethodGet, "/libpod/images/json", "", true},
		{"libpod-image-inspect", http.MethodGet, "/libpod/images/abc/json", "", true},

		// --- libpod: network, volume, secret reads ---
		{"libpod-networks-list", http.MethodGet, "/libpod/networks/json", "", true},
		{"libpod-network-inspect", http.MethodGet, "/libpod/networks/abc/json", "", true},
		{"libpod-volumes-list", http.MethodGet, "/libpod/volumes/json", "", true},
		{"libpod-volume-inspect", http.MethodGet, "/libpod/volumes/abc/json", "", true},
		{"libpod-secrets-list", http.MethodGet, "/libpod/secrets/json", "", true},
		{"libpod-secret-inspect", http.MethodGet, "/libpod/secrets/abc/json", "", true},

		// --- libpod: denied exfiltration surface ---
		{"libpod-archive-denied", http.MethodGet, "/libpod/containers/abc/archive", "", false},
		{"libpod-export-denied", http.MethodGet, "/libpod/containers/abc/export", "", false},
		{"libpod-logs-denied", http.MethodGet, "/libpod/containers/abc/logs", "", false},
		{"libpod-attach-denied", http.MethodPost, "/libpod/containers/abc/attach", "", false},
		{"libpod-images-export-denied", http.MethodGet, "/libpod/images/export", "", false},
		{"libpod-image-get-denied", http.MethodGet, "/libpod/images/abc/get", "", false},
		{"libpod-image-push-denied", http.MethodPost, "/libpod/images/abc/push", "", false},
		{"libpod-generate-kube-denied", http.MethodGet, "/libpod/generate/kube", "", false},
		{"libpod-manifest-registry-push-denied", http.MethodPost, "/libpod/manifests/abc/registry/abc", "", false},
		{"libpod-manifest-push-denied", http.MethodPost, "/libpod/manifests/abc/push", "", false},

		// --- libpod: denied writes, including the libpod-only surface ---
		{"libpod-container-create-denied", http.MethodPost, "/libpod/containers/create", "", false},
		{"libpod-pod-create-denied", http.MethodPost, "/libpod/pods/create", "", false},
		{"libpod-exec-create-denied", http.MethodPost, "/libpod/containers/abc/exec", "", false},
		{"libpod-exec-start-denied", http.MethodPost, "/libpod/exec/abc/start", "", false},
		{"libpod-volume-create-denied", http.MethodPost, "/libpod/volumes/create", "", false},
		{"libpod-network-create-denied", http.MethodPost, "/libpod/networks/create", "", false},
		{"libpod-secret-create-denied", http.MethodPost, "/libpod/secrets/create", "", false},
		{"libpod-play-kube-denied", http.MethodPost, "/libpod/play/kube", "", false},
		{"libpod-kube-apply-denied", http.MethodPost, "/libpod/kube/apply", "", false},

		// --- version-prefixed variants: the same verdicts must hold after
		// stripVersionPrefix normalization, for Docker's two-part prefixes
		// and Podman's three-part semver prefixes alike ---
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json", "", true},
		{"v-prefixed-container-create-denied", http.MethodPost, "/v1.45/containers/create", "", false},
		{"v-prefixed-logs-denied", http.MethodGet, "/v1.45/containers/abc/logs", "", false},
		{"v-prefixed-libpod-containers-list", http.MethodGet, "/v5.0.0/libpod/containers/json", "", true},
		{"v-prefixed-libpod-pods-list", http.MethodGet, "/v1.45/libpod/pods/json", "", true},
		{"v-prefixed-libpod-pod-create-denied", http.MethodPost, "/v5.0.0/libpod/pods/create", "", false},
		{"v-prefixed-libpod-play-kube-denied", http.MethodPost, "/v5.0.0/libpod/play/kube", "", false},
		{"v-prefixed-libpod-generate-kube-denied", http.MethodGet, "/v5.0.0/libpod/generate/kube", "", false},
	}

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
