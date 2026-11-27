package filter_test

import (
	"net/http"
	"testing"
)

// topPsArgsCases covers the ps_args guard on GET /containers/*/top. ps_args
// reaches the daemon host's ps and its `e` flag prints each process's
// environment, so a consumer that sends none must not be able to pass one.
func topPsArgsCases(prefix string) []presetCase {
	top := prefix + "/containers/abc/top"
	return []presetCase{
		{"top-bare-allowed", http.MethodGet, top, "", true},
		{"top-ps-args-e-denied", http.MethodGet, top + "?ps_args=e", "", false},
		{"top-ps-args-aux-denied", http.MethodGet, top + "?ps_args=aux", "", false},
		{"top-ps-args-empty-denied", http.MethodGet, top + "?ps_args=", "", false},
		{"top-ps-args-cased-key-denied", http.MethodGet, top + "?Ps_Args=e", "", false},
		{"top-ps-args-encoded-key-denied", http.MethodGet, top + "?ps%5Fargs=e", "", false},
		{"top-ps-args-duplicate-denied", http.MethodGet, top + "?ps_args=-ef&ps_args=e", "", false},
		{"top-ps-args-with-other-query-denied", http.MethodGet, top + "?stream=0&ps_args=e", "", false},
		{"v-prefixed-top-ps-args-denied", http.MethodGet, "/v1.45" + top + "?ps_args=e", "", false},
	}
}

func TestTopPsArgsDeniedAcrossPresets(t *testing.T) {
	presets := []struct {
		file   string
		prefix []string
	}{
		{"portwing.yaml", []string{""}},
		{"portwing-with-exec.yaml", []string{""}},
		{"portwing-with-compose.yaml", []string{""}},
		{"portwing-with-build.yaml", []string{""}},
		{"portwing-with-mediated-build.yaml", []string{""}},
		{"gitlab-runner.yaml", []string{""}},
		{"podman-readonly.yaml", []string{"", "/libpod"}},
	}
	for _, p := range presets {
		t.Run(p.file, func(t *testing.T) {
			handler := buildDrydockPresetHandler(t, p.file)
			for _, prefix := range p.prefix {
				for _, c := range topPsArgsCases(prefix) {
					if prefix == "/libpod" && c.name == "v-prefixed-top-ps-args-denied" {
						continue
					}
					c.name = prefix + c.name
					fireDrydockCase(t, handler, c)
				}
			}
		})
	}
}

func TestRunnerAndCISPresetsDenyUnmaskedSystemPaths(t *testing.T) {
	for _, file := range []string{"gitlab-runner.yaml", "github-actions-runner.yaml", "cis-docker-benchmark.yaml"} {
		t.Run(file, func(t *testing.T) {
			handler := buildDrydockPresetHandler(t, file)
			// Only the denial rows: the allowed control row depends on each
			// preset's other create gates (limits, user, image allowlist).
			for _, c := range systemPathsDeniedCases(`{"Image":"alpine:3"`, true) {
				if c.allowed {
					continue
				}
				fireDrydockCase(t, handler, c)
			}
		})
	}
}
