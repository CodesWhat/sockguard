package filter_test

import (
	"net/http"
	"testing"
)

// TestContainerRemovePresetConformance pins the destructive query controls
// each shipped client actually uses. Drydock's recovery path and Portwing's
// force option require force removal; Compose teardown, Watchtower cleanup,
// and GitLab Runner additionally remove anonymous volumes. actions/runner's
// `docker rm --force` needs only force. None of these clients removes legacy
// links through the container-remove endpoint.
func TestContainerRemovePresetConformance(t *testing.T) {
	tests := []struct {
		preset             string
		allowRemoveVolumes bool
	}{
		{preset: "drydock.yaml"},
		{preset: "drydock-with-build.yaml", allowRemoveVolumes: true},
		{preset: "drydock-with-compose.yaml", allowRemoveVolumes: true},
		{preset: "drydock-with-mediated-build.yaml", allowRemoveVolumes: true},
		{preset: "drydock-with-selfupdate.yaml"},
		{preset: "portwing.yaml"},
		{preset: "portwing-with-build.yaml", allowRemoveVolumes: true},
		{preset: "portwing-with-compose.yaml", allowRemoveVolumes: true},
		{preset: "portwing-with-exec.yaml"},
		{preset: "portwing-with-mediated-build.yaml", allowRemoveVolumes: true},
		{preset: "watchtower.yaml", allowRemoveVolumes: true},
		{preset: "github-actions-runner.yaml"},
		{preset: "gitlab-runner.yaml", allowRemoveVolumes: true},
	}

	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			handler := buildDrydockPresetHandler(t, tt.preset)
			cases := []presetCase{
				{"bare-remove", http.MethodDelete, "/containers/abc", "", true},
				{"force-remove", http.MethodDelete, "/containers/abc?force=1", "", true},
				{"link-remove-denied", http.MethodDelete, "/containers/abc?link=1", "", false},
			}
			if tt.allowRemoveVolumes {
				cases = append(cases, presetCase{"anonymous-volume-remove", http.MethodDelete, "/containers/abc?v=1", "", true})
			} else {
				cases = append(cases, presetCase{"anonymous-volume-remove-denied", http.MethodDelete, "/containers/abc?v=1", "", false})
			}

			for _, c := range cases {
				fireDrydockCase(t, handler, c)
			}
		})
	}
}
