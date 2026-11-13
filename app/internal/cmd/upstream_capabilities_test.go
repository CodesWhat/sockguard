package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfiguredDockerRejectsPositivePodmanIdentity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, header, body string
		status             int
	}{
		{"component", "", `{"Components":[{"Name":"Podman Engine","Version":"6.0.0"}]}`, 200},
		{"component with unknown version type", "", `{"Components":[{"Name":"Podman Engine","Version":6}]}`, 200},
		{"header", "Libpod/6.0.0", `{}`, 200},
		{"header contradicts body", "Libpod/6.0.0", flavorTestDockerVersionBody, 200},
		{"header with malformed body", "Libpod/6.0.0", `{`, 200},
		{"header with failed version route", "Libpod/6.0.0", `unavailable`, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Server", test.header)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			res := multiEndpointResolver(t, server.Listener.Addr().String())
			logger, _ := flavorTestLogger()
			_, err := resolveUpstreamFlavor(t.Context(), newServeDeps(), flavorTestConfig("docker"), res, logger)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "podman") {
				t.Fatalf("configured Docker accepted positive Podman identity: %v", err)
			}
		})
	}
}

func TestVolumeCapabilityRequiresEveryFailoverEndpoint(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, configured, first, second string
		want                            bool
		wantErr                         bool
	}{
		{"all modern auto", "auto", "6.0.0", "6.1.0", true, false},
		{"all modern explicit", "podman", "6.0.0", "6.1.0", true, false},
		{"old secondary", "auto", "6.0.0", "5.8.1", false, false},
		{"old primary", "auto", "5.8.1", "6.0.0", false, false},
		{"unknown secondary version", "auto", "6.0.0", "", false, false},
		{"candidate secondary", "podman", "6.0.0", "6.1.0-rc.1", false, false},
		{"docker override secondary Podman", "docker", "6.0.0", "6.1.0", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first := newVersionServer(t, 200, `{"Components":[{"Name":"Podman Engine","Version":"`+test.first+`"}]}`)
			second := newVersionServer(t, 200, `{"Components":[{"Name":"Podman Engine","Version":"`+test.second+`"}]}`)
			logger, collector := flavorTestLogger()
			got, err := resolveUpstreamCapabilities(t.Context(), newServeDeps(), flavorTestConfig(test.configured), multiEndpointResolver(t, first.addr(), second.addr()), logger)
			if (err != nil) != test.wantErr || got.PodmanConjunctiveVolumeFilters != test.want {
				t.Fatalf("capabilities=%+v err=%v, want volume=%v error=%v", got, err, test.want, test.wantErr)
			}
			if !test.wantErr && (first.calls.Load() != 1 || second.calls.Load() != 1) {
				t.Fatal("not every endpoint was probed")
			}
			if !test.wantErr {
				logged := false
				for _, record := range collector.Records() {
					if record.Message == "upstream flavor resolved" {
						logged = true
						if got, ok := record.Attrs["podman_conjunctive_volume_filters"].(bool); !ok || got != test.want {
							t.Errorf("logged volume capability = %v, want %v", record.Attrs, test.want)
						}
					}
				}
				if !logged {
					t.Fatal("resolved capability log missing")
				}
			}
		})
	}
}

func TestExplicitFlavorFallbackKeepsUnknownVolumeSemanticsRestricted(t *testing.T) {
	t.Parallel()
	for _, configured := range []string{"docker", "podman"} {
		t.Run(configured, func(t *testing.T) {
			t.Parallel()
			unknown := newVersionServer(t, 503, `unavailable`)
			logger, _ := flavorTestLogger()
			got, err := resolveUpstreamCapabilities(t.Context(), newServeDeps(), flavorTestConfig(configured), multiEndpointResolver(t, unknown.addr()), logger)
			if err != nil || string(got.Flavor) != configured || got.PodmanConjunctiveVolumeFilters {
				t.Fatalf("fallback=%+v error=%v", got, err)
			}
		})
	}
}

func TestConfiguredDockerCannotHidePodmanFailover(t *testing.T) {
	t.Parallel()
	first := newVersionServer(t, http.StatusOK, flavorTestDockerVersionBody)
	second := newVersionServer(t, http.StatusOK, flavorTestPodmanVersionBody)
	logger, _ := flavorTestLogger()
	_, err := resolveUpstreamCapabilities(t.Context(), newServeDeps(), flavorTestConfig("docker"), multiEndpointResolver(t, first.addr(), second.addr()), logger)
	if err == nil || first.calls.Load() != 1 || second.calls.Load() != 1 {
		t.Fatalf("Docker primary hid Podman failover: error=%v calls=(%d,%d)", err, first.calls.Load(), second.calls.Load())
	}
}

// TestProbedDockerNeedsEveryEndpointToProbeAsDocker pins the evidence the
// gates that loosen for dockerd rely on: every endpoint positively probed as
// Docker. An explicit upstream.flavor: docker is a setting, not a probe, so a
// failed or unrecognized probe, or one endpoint that couldn't be probed in a
// failover set, leaves the flag off.
func TestProbedDockerNeedsEveryEndpointToProbeAsDocker(t *testing.T) {
	t.Parallel()
	type server struct {
		status int
		body   string
	}
	docker := server{http.StatusOK, flavorTestDockerVersionBody}
	for _, test := range []struct {
		name, configured string
		servers          []server
		want             bool
	}{
		{"auto, one docker endpoint", "auto", []server{docker}, true},
		{"explicit docker, one docker endpoint", "docker", []server{docker}, true},
		{"explicit docker, two docker endpoints", "docker", []server{docker, docker}, true},
		{"explicit docker, failed probe", "docker", []server{{503, `unavailable`}}, false},
		{"explicit docker, unrecognized engine", "docker", []server{{http.StatusOK, `{"Components":[{"Name":"Mystery Engine"}]}`}}, false},
		{"explicit docker, malformed body", "docker", []server{{http.StatusOK, `{`}}, false},
		{"explicit docker, docker then failed probe", "docker", []server{docker, {503, `unavailable`}}, false},
		{"explicit docker, failed probe then docker", "docker", []server{{503, `unavailable`}, docker}, false},
		{"explicit podman, podman endpoint", "podman", []server{{http.StatusOK, flavorTestPodmanVersionBody}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			addrs := make([]string, len(test.servers))
			for i, s := range test.servers {
				addrs[i] = newVersionServer(t, s.status, s.body).addr()
			}
			logger, _ := flavorTestLogger()
			got, err := resolveUpstreamCapabilities(t.Context(), newServeDeps(), flavorTestConfig(test.configured), multiEndpointResolver(t, addrs...), logger)
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if got.ProbedDocker != test.want {
				t.Fatalf("ProbedDocker = %v, want %v (capabilities %+v)", got.ProbedDocker, test.want, got)
			}
		})
	}
}
