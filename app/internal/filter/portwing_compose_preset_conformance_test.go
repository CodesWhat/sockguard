package filter_test

import (
	"net/http"
	"testing"
)

// TestPortwingComposePresetConformance fires a full compose round trip at
// portwing-with-compose.yaml's filter chain, asserting the network and volume
// lifecycle a `docker compose up` / `down -v` deploy needs is admitted while
// /build stays denied. It guards the integration contract this preset exists
// to satisfy: portwing.yaml already covers plain container orchestration, but
// compose stacks additionally create/remove their own networks and named
// volumes, which portwing.yaml denies.
//
// TestDrydockComposePresetConformance is the sibling case for
// drydock-with-compose.yaml, added for symmetry since drydock's own compose
// deploys hit the identical gap.
func TestPortwingComposePresetConformance(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "portwing-with-compose.yaml")

	cases := []presetCase{
		// Everything portwing.yaml already allows must keep working.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"create-runc", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"runc"}}`, true},
		{"logs-allowed", http.MethodGet, "/containers/abc/logs", "", true},

		// Compose round trip: create the stack network, attach a container to
		// a second network, create a named volume, then tear both down.
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"stack_default","Driver":"bridge"}`, true},
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		{"network-disconnect", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc"}`, true},
		{"network-delete", http.MethodDelete, "/networks/abc", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"stack_data","Driver":"local"}`, true},
		{"volume-delete", http.MethodDelete, "/volumes/stack_data", "", true},

		// A custom network/volume driver is still denied — the compose
		// additions don't loosen the existing driver allowlist defaults.
		{"network-create-custom-driver-denied", http.MethodPost, "/networks/create", `{"Name":"stack_default","Driver":"weave"}`, false},
		{"volume-create-custom-driver-denied", http.MethodPost, "/volumes/create", `{"Name":"stack_data","Driver":"nfs"}`, false},

		// Build stays denied — see the preset's header comment on BuildKit's
		// /session + /grpc fallback needs.
		{"build-denied", http.MethodPost, "/build", "", false},

		// Exec and the bulk-exfil surface stay denied, same as portwing.yaml.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
		{"archive-denied", http.MethodGet, "/containers/abc/archive", "", false},
	}

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}

// TestDrydockComposePresetConformance mirrors TestPortwingComposePresetConformance
// against drydock-with-compose.yaml, added for symmetry: drydock's own compose
// deploys hit the identical network/volume-create gap that drydock.yaml has.
func TestDrydockComposePresetConformance(t *testing.T) {
	handler := buildDrydockPresetHandler(t, "drydock-with-compose.yaml")

	cases := []presetCase{
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"create-runc", http.MethodPost, "/containers/create", `{"Image":"x","HostConfig":{"Runtime":"runc"}}`, true},

		// The pre-existing connect rule must survive untouched alongside the
		// new create/delete/disconnect rules.
		{"network-connect", http.MethodPost, "/networks/abc/connect", `{"Container":"abc"}`, true},
		{"network-create", http.MethodPost, "/networks/create", `{"Name":"stack_default","Driver":"bridge"}`, true},
		{"network-disconnect", http.MethodPost, "/networks/abc/disconnect", `{"Container":"abc"}`, true},
		{"network-delete", http.MethodDelete, "/networks/abc", "", true},
		{"volume-create", http.MethodPost, "/volumes/create", `{"Name":"stack_data","Driver":"local"}`, true},
		{"volume-delete", http.MethodDelete, "/volumes/stack_data", "", true},

		{"build-denied", http.MethodPost, "/build", "", false},
		{"logs-denied", http.MethodGet, "/containers/abc/logs", "", false},
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", "", false},
	}

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
