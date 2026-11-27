package filter_test

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
	"github.com/codeswhat/sockguard/v3/app/internal/filter"
)

// TestJenkinsPresetConformance pins the Docker Engine API surface of the
// Jenkins Docker plugin (jenkinsci/docker-plugin, tag 1337.v3ca_fd1b_b_25ef)
// provisioning agents with the Inbound (JNLP) connector. Call sites, all
// docker-java-api client commands:
//
//	DockerAPI.java, DockerCloud.java           versionCmd, listContainersCmd (label filter)
//	DockerTemplate.java                        pullImageCmd, inspectImageCmd, createContainerCmd,
//	                                           startContainerCmd, removeContainerCmd (force on failure)
//	DockerImagePullStrategy.java               inspectImageCmd
//	DockerDelegatingComputerLauncher.java      inspectContainerCmd
//	DockerTransientNode.java                   stopContainerCmd, removeContainerCmd
//	DockerContainerWatchdog.java               listContainersCmd (all), removeContainerCmd (force)
//
// Routes: GET /version, GET /containers/json, GET /containers/{id}/json,
// GET /images/{name}/json, POST /images/create, POST /containers/create,
// POST /containers/{id}/start, POST /containers/{id}/stop and
// DELETE /containers/{id}.
//
// Outside the base preset: the Attach connector (execCreateCmd, a raw
// POST /exec/{id}/start, copyArchiveToContainerCmd), the SSH connector
// (copyArchiveToContainerCmd, published ports), the disconnect log read
// (logContainerCmd), and jenkinsci/docker-workflow-plugin 653.v2f2c08eff0ec,
// whose docker.image().inside() shells out to `docker run -v ...
// --volumes-from`, `docker exec` and `docker top`.
func TestJenkinsPresetConformance(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "jenkins.yaml"))
	if err != nil {
		t.Fatalf("load preset jenkins.yaml: %v", err)
	}
	if cfg.InsecureAllowReadExfiltration || cfg.InsecureAllowBodyBlindWrites {
		t.Fatal("jenkins.yaml must not set insecure_allow_* acknowledgments")
	}
	if cfg.Ownership.Owner == "" {
		t.Fatal("jenkins.yaml must set an ownership owner")
	}

	const agent = `{"Image":"docker.io/jenkins/inbound-agent:3396.ve02b_5cde31b_2-5-jdk21"`
	// deny_published_ports is enforced by the resource-limit guard, which
	// serve.go runs after ownership and before the rule layer. Mirror that
	// here so the pin covers it.
	policy := cfg.RequestBody.ToFilterOptions()
	guard := filter.ResourceLimitGuardWithOptions(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		filter.ResourceLimitGuardOptions{PolicyConfig: policy},
	)
	handler := guard(drydockPresetHandlerFromConfig(t, cfg))
	cases := []presetCase{
		// Complete supported surface.
		{"ping-get", http.MethodGet, "/_ping", "", true},
		{"ping-head", http.MethodHead, "/_ping", "", true},
		{"version", http.MethodGet, "/version", "", true},
		{"containers-list", http.MethodGet, "/containers/json", "", true},
		{"containers-list-label-filter", http.MethodGet, `/containers/json?all=1&filters={"label":["JenkinsId=abc"]}`, "", true},
		{"container-inspect", http.MethodGet, "/containers/abc/json", "", true},
		{"image-inspect-qualified", http.MethodGet, "/images/docker.io/jenkins/inbound-agent:3396.ve02b_5cde31b_2-5-jdk21/json", "", true},
		{"image-pull", http.MethodPost, "/images/create?fromImage=docker.io/jenkins/inbound-agent&tag=3396.ve02b_5cde31b_2-5-jdk21", "", true},
		{"container-create", http.MethodPost, "/containers/create?name=agent-1", agent + `,"Cmd":["-url","http://jenkins:8080","secret","agent-1"],"HostConfig":{"Privileged":false}}`, true},
		{"container-start", http.MethodPost, "/containers/abc/start", "", true},
		{"container-stop", http.MethodPost, "/containers/abc/stop?t=10", "", true},
		{"container-remove", http.MethodDelete, "/containers/abc?v=1", "", true},
		{"container-remove-force", http.MethodDelete, "/containers/abc?force=1", "", true},

		// Docker API version prefixes normalize before matching.
		{"v-prefixed-version", http.MethodGet, "/v1.45/version", "", true},
		{"v-prefixed-containers-list", http.MethodGet, "/v1.45/containers/json?all=1", "", true},
		{"v-prefixed-container-inspect", http.MethodGet, "/v1.45/containers/abc/json", "", true},
		{"v-prefixed-image-inspect", http.MethodGet, "/v1.45/images/docker.io/jenkins/inbound-agent:3396.ve02b_5cde31b_2-5-jdk21/json", "", true},
		{"v-prefixed-image-pull", http.MethodPost, "/v1.45/images/create?fromImage=docker.io/jenkins/inbound-agent&tag=3396.ve02b_5cde31b_2-5-jdk21", "", true},
		{"v-prefixed-container-create", http.MethodPost, "/v1.45/containers/create", agent + `}`, true},
		{"v-prefixed-container-start", http.MethodPost, "/v1.45/containers/abc/start", "", true},
		{"v-prefixed-container-stop", http.MethodPost, "/v1.45/containers/abc/stop", "", true},
		{"v-prefixed-container-remove", http.MethodDelete, "/v1.45/containers/abc", "", true},

		// Create policy: the body is inspected.
		{"create-other-image-denied", http.MethodPost, "/containers/create", `{"Image":"docker.io/library/alpine:3.22"}`, false},
		{"create-short-image-denied", http.MethodPost, "/containers/create", `{"Image":"jenkins/inbound-agent"}`, false},
		{"create-empty-image-denied", http.MethodPost, "/containers/create", `{}`, false},
		{"create-privileged-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Privileged":true}}`, false},
		{"create-bind-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Binds":["/:/host"]}}`, false},
		{"create-docker-sock-bind-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`, false},
		{"create-host-network-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"NetworkMode":"host"}}`, false},
		{"create-host-pid-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"PidMode":"host"}}`, false},
		{"create-cap-add-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, false},
		{"create-device-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}}`, false},
		{"create-unconfined-seccomp-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, false},
		{"create-sysctl-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`, false},
		{"create-published-port-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"PortBindings":{"22/tcp":[{"HostPort":"2222"}]}}}`, false},
		{"create-publish-all-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"PublishAllPorts":true}}`, false},
		{"create-volumes-from-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"VolumesFrom":["other"]}}`, false},
		{"create-mounts-bind-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}`, false},
		{"create-container-netns-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"NetworkMode":"container:victim"}}`, false},
		{"create-container-pidns-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"PidMode":"container:victim"}}`, false},
		{"create-host-ipc-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"IpcMode":"host"}}`, false},
		{"create-userns-host-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"UsernsMode":"host"}}`, false},
		{"create-unconfined-apparmor-denied", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, false},
		{"create-tmpfs-allowed", http.MethodPost, "/containers/create", agent + `,"HostConfig":{"Tmpfs":{"/tmp":"rw"}}}`, true},
		{"create-image-digest-bypass-denied", http.MethodPost, "/containers/create", `{"Image":"docker.io/jenkins/inbound-agent:3396.ve02b_5cde31b_2-5-jdk21@sha256:00"}`, false},
		{"libpod-create-denied", http.MethodPost, "/libpod/containers/create", agent + `}`, false},
		{"libpod-containers-list-denied", http.MethodGet, "/libpod/containers/json", "", false},
		{"dot-segment-exec-denied", http.MethodPost, "/containers/abc/../abc/exec", `{}`, false},
		{"encoded-slash-archive-denied", http.MethodPut, "/containers/abc%2Farchive?path=/", "", false},
		{"v-prefixed-create-privileged-denied", http.MethodPost, "/v1.45/containers/create", agent + `,"HostConfig":{"Privileged":true}}`, false},

		// Pull policy: docker.io only.
		{"pull-other-registry-denied", http.MethodPost, "/images/create?fromImage=evil.example.com/jenkins/inbound-agent&tag=1", "", false},
		{"pull-import-denied", http.MethodPost, "/images/create?fromSrc=http://evil.example.com/x.tar", "", false},

		// Attach connector and docker-workflow: exec and attach are refused.
		{"exec-create-denied", http.MethodPost, "/containers/abc/exec", `{"Cmd":["java","-jar","agent.jar"]}`, false},
		{"exec-start-denied", http.MethodPost, "/exec/abc/start", `{"Detach":false,"Tty":false}`, false},
		{"exec-inspect-denied", http.MethodGet, "/exec/abc/json", "", false},
		{"v-prefixed-exec-start-denied", http.MethodPost, "/v1.45/exec/abc/start", `{}`, false},
		{"container-attach-denied", http.MethodPost, "/containers/abc/attach?stream=1", "", false},
		{"container-top-denied", http.MethodGet, "/containers/abc/top", "", false},

		// Archive copy (SSH and Attach connectors) is refused.
		{"archive-put-denied", http.MethodPut, "/containers/abc/archive?path=/home/jenkins", "", false},

		// Other container operations.
		{"container-kill-denied", http.MethodPost, "/containers/abc/kill", "", false},
		{"container-restart-denied", http.MethodPost, "/containers/abc/restart", "", false},
		{"container-rename-denied", http.MethodPost, "/containers/abc/rename?name=x", "", false},
		{"container-update-denied", http.MethodPost, "/containers/abc/update", `{}`, false},
		{"container-wait-denied", http.MethodPost, "/containers/abc/wait", "", false},
		{"containers-prune-denied", http.MethodPost, "/containers/prune", "", false},

		// Images, build, push, tag.
		{"images-list-denied", http.MethodGet, "/images/json", "", false},
		{"image-history-denied", http.MethodGet, "/images/nginx/history", "", false},
		{"image-remove-denied", http.MethodDelete, "/images/nginx", "", false},
		{"image-tag-denied", http.MethodPost, "/images/nginx/tag?repo=x", "", false},
		{"image-push-denied", http.MethodPost, "/images/nginx/push", "", false},
		{"commit-denied", http.MethodPost, "/commit?container=abc", `{}`, false},
		{"build-denied", http.MethodPost, "/build", "", false},
		{"image-prune-denied", http.MethodPost, "/images/prune", "", false},

		// Networks, volumes, system.
		{"info-denied", http.MethodGet, "/info", "", false},
		{"events-denied", http.MethodGet, "/events", "", false},
		{"system-df-denied", http.MethodGet, "/system/df", "", false},
		{"networks-list-denied", http.MethodGet, "/networks", "", false},
		{"network-create-denied", http.MethodPost, "/networks/create", `{"Name":"x"}`, false},
		{"volumes-list-denied", http.MethodGet, "/volumes", "", false},
		{"volume-create-denied", http.MethodPost, "/volumes/create", `{"Name":"x"}`, false},
		{"volumes-prune-denied", http.MethodPost, "/volumes/prune", "", false},

		// Swarm and the remaining surface.
		{"services-list-denied", http.MethodGet, "/services", "", false},
		{"service-create-denied", http.MethodPost, "/services/create", `{}`, false},
		{"swarm-init-denied", http.MethodPost, "/swarm/init", `{}`, false},
		{"secrets-list-denied", http.MethodGet, "/secrets", "", false},
		{"plugins-list-denied", http.MethodGet, "/plugins", "", false},
		{"session-denied", http.MethodPost, "/session", "", false},
		{"auth-denied", http.MethodPost, "/auth", `{}`, false},
	}

	// The preset does not acknowledge read exfiltration, so logs, archive,
	// export and attach must stay denied.
	cases = append(cases, exfilDenialCases...)

	cases = append(cases, systemPathsDeniedCases(agent, true)...)

	for _, c := range cases {
		fireDrydockCase(t, handler, c)
	}
}
